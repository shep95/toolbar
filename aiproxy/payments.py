"""Balance top-ups through Stripe Checkout.

* ``POST /v1/billing/checkout`` (user key auth) creates a Checkout Session and
  returns its URL.
* ``POST /stripe/webhook`` receives Stripe's signed event and credits the
  balance. Credits are keyed on the Checkout Session ID, so a replayed or
  duplicated webhook never credits twice.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
import uuid
from decimal import Decimal, InvalidOperation

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError

from .db import DB_UNAVAILABLE_ERRORS
from .errors import GatewayError
from .gateway import run_request, authenticate, enforce_rate_limit, read_json_body
from .models import BalanceAdjustment, User
from .services import Services, get_services

log = logging.getLogger("aiproxy.payments")

router = APIRouter()

TOPUP_PURPOSE = "aiproxy_topup"
SIGNATURE_TOLERANCE_SECONDS = 300
MAX_WEBHOOK_BYTES = 1_000_000


def verify_stripe_signature(payload: bytes, header: str, secret: str, now: float | None = None) -> bool:
    timestamp = None
    signatures: list[str] = []
    for item in header.split(","):
        key, _, value = item.strip().partition("=")
        if key == "t":
            timestamp = value
        elif key == "v1":
            signatures.append(value)
    if not timestamp or not timestamp.isdigit() or not signatures:
        return False
    if abs((now or time.time()) - int(timestamp)) > SIGNATURE_TOLERANCE_SECONDS:
        return False
    expected = hmac.new(secret.encode(), timestamp.encode() + b"." + payload, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, sig) for sig in signatures)


def sign_stripe_payload(payload: bytes, secret: str, timestamp: int | None = None) -> str:
    """Build a Stripe-Signature header. Used by tests and local tooling."""
    ts = str(timestamp or int(time.time()))
    sig = hmac.new(secret.encode(), ts.encode() + b"." + payload, hashlib.sha256).hexdigest()
    return f"t={ts},v1={sig}"


class StripeUnavailable(Exception):
    """Stripe could not be reached or refused the request; ``message`` is Stripe's reason."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


async def start_checkout(
    services: Services,
    *,
    cents: int,
    client_reference_id: str | None,
    metadata: dict[str, str],
    product_name: str,
    request_id: str,
) -> dict:
    """Create a Stripe Checkout Session and return it. Shared by top-ups and the admin test."""
    settings = services.settings
    form = {
        "mode": "payment",
        "success_url": settings.stripe_success_url,
        "cancel_url": settings.stripe_cancel_url,
        "line_items[0][quantity]": "1",
        "line_items[0][price_data][currency]": "usd",
        "line_items[0][price_data][unit_amount]": str(cents),
        "line_items[0][price_data][product_data][name]": product_name,
        **{f"metadata[{k}]": v for k, v in metadata.items()},
    }
    if client_reference_id:
        form["client_reference_id"] = client_reference_id
    try:
        resp = await services.http.post(
            f"{settings.stripe_api_base}/checkout/sessions",
            data=form,
            headers={
                "Authorization": f"Bearer {settings.stripe_secret_key.get_secret_value()}",
                "Idempotency-Key": request_id,
            },
        )
    except httpx.HTTPError:
        log.exception("stripe unreachable", extra={"request_id": request_id})
        raise StripeUnavailable("Stripe could not be reached") from None
    if resp.status_code >= 400:
        log.error("stripe rejected checkout (HTTP %s): %s", resp.status_code, resp.text[:500])
        try:
            reason = resp.json().get("error", {}).get("message") or f"HTTP {resp.status_code}"
        except ValueError:
            reason = f"HTTP {resp.status_code}"
        raise StripeUnavailable(reason)
    return resp.json()


@router.post("/v1/billing/checkout")
async def create_checkout(request: Request) -> Response:
    async def work(services: Services, request_id: str) -> Response:
        caller = await authenticate(services, request)
        enforce_rate_limit(services, caller)
        settings = services.settings
        if not settings.stripe_enabled:
            raise GatewayError(503, "payments_disabled", "online top-ups are not enabled")
        body = await read_json_body(services, request)
        try:
            amount = Decimal(str(body.get("amount_usd")))
        except (InvalidOperation, ValueError):
            raise GatewayError(400, "invalid_request", "'amount_usd' must be a number") from None
        if (
            not amount.is_finite()
            or amount != amount.quantize(Decimal("0.01"))
            or not settings.stripe_min_topup_usd <= amount <= settings.stripe_max_topup_usd
        ):
            raise GatewayError(
                400,
                "invalid_request",
                f"'amount_usd' must be between {settings.stripe_min_topup_usd} and {settings.stripe_max_topup_usd} with at most 2 decimals",
            )
        try:
            session = await start_checkout(
                services,
                cents=int(amount * 100),
                client_reference_id=str(caller.user_id),
                metadata={"purpose": TOPUP_PURPOSE, "user_id": str(caller.user_id), "credit_usd": str(amount)},
                product_name="API credit",
                request_id=request_id,
            )
        except StripeUnavailable:
            raise GatewayError(502, "payments_unavailable", "could not start checkout") from None
        return JSONResponse(
            {"checkout_url": session.get("url"), "session_id": session.get("id"), "amount_usd": str(amount)},
            headers={"X-Request-Id": request_id},
        )

    return await run_request(request, work)


def _note(event: dict, obj: dict) -> str:
    """Ledger note; records the local currency the customer paid in, if any.

    With Stripe Adaptive Pricing a customer abroad pays in their own currency
    while the session amount stays in USD; Stripe reports what they actually
    paid in ``presentment_details``.
    """
    note = f"stripe event {event.get('id')}"
    presented = obj.get("presentment_details") or {}
    amount, currency = presented.get("presentment_amount"), presented.get("presentment_currency")
    if isinstance(amount, int) and isinstance(currency, str) and currency.lower() != "usd":
        note += f"; customer paid {amount / 100:.2f} {currency.upper()}"
    return note[:500]


@router.post("/stripe/webhook", include_in_schema=False)
async def stripe_webhook(request: Request) -> Response:
    services = get_services(request)
    settings = services.settings
    # Crediting only needs the signing secret; the API key is only used to
    # create checkout sessions.
    if not settings.stripe_webhook_secret:
        return JSONResponse({"error": "payments disabled"}, status_code=503)
    payload = b""
    async for chunk in request.stream():
        payload += chunk
        if len(payload) > MAX_WEBHOOK_BYTES:
            return JSONResponse({"error": "payload too large"}, status_code=413)
    if not verify_stripe_signature(
        payload, request.headers.get("stripe-signature", ""), settings.stripe_webhook_secret.get_secret_value()
    ):
        log.warning("stripe webhook with bad signature", extra={"event": "stripe_bad_signature"})
        return JSONResponse({"error": "invalid signature"}, status_code=400)

    try:
        event = json.loads(payload)
    except ValueError:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)
    if event.get("type") not in ("checkout.session.completed", "checkout.session.async_payment_succeeded"):
        return JSONResponse({"received": True, "ignored": event.get("type")})
    obj = (event.get("data") or {}).get("object") or {}
    if obj.get("payment_status") != "paid" or (obj.get("metadata") or {}).get("purpose") != TOPUP_PURPOSE:
        return JSONResponse({"received": True, "ignored": "not a paid top-up"})
    if (obj.get("currency") or "").lower() != "usd":
        log.error("top-up in unexpected currency %s for session %s", obj.get("currency"), obj.get("id"))
        return JSONResponse({"received": True, "ignored": "currency"})

    try:
        user_id = uuid.UUID(str(obj.get("client_reference_id")))
        # Credit what was actually paid for the credit itself: the lower of the
        # pre-tax subtotal and the final total, so a discount or coupon can
        # never credit more than the customer paid.
        amounts = [int(obj[k]) for k in ("amount_subtotal", "amount_total") if obj.get(k) is not None]
        cents = min(amounts)
        if cents <= 0:
            raise ValueError("non-positive amount")
    except (ValueError, KeyError, TypeError):
        log.error("malformed top-up session %s", obj.get("id"))
        return JSONResponse({"received": True, "ignored": "malformed"})
    amount = Decimal(cents) / Decimal(100)

    try:
        async with services.db.session() as session, session.begin():
            if await session.get(User, user_id) is None:
                raise LookupError(str(user_id))
            session.add(
                BalanceAdjustment(
                    user_id=user_id, amount=amount, source="stripe", external_id=str(obj.get("id")), note=_note(event, obj)
                )
            )
            await session.flush()  # unique external_id: raises if already credited
            await session.execute(update(User).where(User.id == user_id).values(balance=User.balance + amount))
    except IntegrityError:
        return JSONResponse({"received": True, "duplicate": True})
    except LookupError:
        log.error("top-up for unknown user %s (session %s)", user_id, obj.get("id"))
        return JSONResponse({"received": True, "ignored": "unknown user"})
    except DB_UNAVAILABLE_ERRORS:
        log.exception("database unavailable while crediting top-up")
        # Non-2xx makes Stripe retry the webhook later.
        return JSONResponse({"error": "temporarily unavailable"}, status_code=503)

    log.info("balance topped up", extra={"event": "stripe_topup", "user_id": str(user_id), "amount": str(amount)})
    return JSONResponse({"received": True, "credited": str(amount)})


# --------------------------------------------------------------------- return pages

_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><link rel="icon" href="data:,"><title>{title}</title>
<style>
:root {{ --bg:#f6f7f9; --panel:#fff; --text:#1b1f24; --muted:#5f6b7a; --accent:{accent}; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#111418; --panel:#1a1e24; --text:#e6e9ee; --muted:#9aa5b3; }} }}
body {{ margin:0; min-height:100vh; display:grid; place-items:center; background:var(--bg); color:var(--text);
       font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; padding:16px; box-sizing:border-box; }}
main {{ background:var(--panel); border-radius:12px; padding:32px; max-width:440px; text-align:center;
       box-shadow:0 1px 3px rgba(0,0,0,.12); }}
h1 {{ font-size:22px; margin:0 0 8px; color:var(--accent); }}
p {{ margin:0; color:var(--muted); }}
</style></head>
<body><main><h1>{title}</h1><p>{message}</p></main></body></html>"""

_PAGE_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'none'",
    "Cache-Control": "no-store",
}


@router.get("/billing/success", include_in_schema=False)
async def checkout_success() -> Response:
    # Deliberately static: the balance is credited by the signed webhook, never
    # by a visit to this page, so the page reads nothing from the URL.
    html = _PAGE.format(
        title="Payment received",
        accent="#1f8a4c",
        message="Thank you. Your API credit is added to your balance within a few seconds. You can close this page.",
    )
    return Response(html, media_type="text/html; charset=utf-8", headers=_PAGE_HEADERS)


@router.get("/billing/cancel", include_in_schema=False)
async def checkout_cancel() -> Response:
    html = _PAGE.format(
        title="Payment cancelled",
        accent="#b7791f",
        message="No payment was taken and your balance is unchanged. You can close this page.",
    )
    return Response(html, media_type="text/html; charset=utf-8", headers=_PAGE_HEADERS)
