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
        cents = int(amount * 100)
        form = {
            "mode": "payment",
            "success_url": settings.stripe_success_url,
            "cancel_url": settings.stripe_cancel_url,
            "client_reference_id": str(caller.user_id),
            "line_items[0][quantity]": "1",
            "line_items[0][price_data][currency]": "usd",
            "line_items[0][price_data][unit_amount]": str(cents),
            "line_items[0][price_data][product_data][name]": "API credit",
            "metadata[purpose]": TOPUP_PURPOSE,
            "metadata[user_id]": str(caller.user_id),
            "metadata[credit_usd]": str(amount),
        }
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
            raise GatewayError(502, "payments_unavailable", "payment provider unavailable") from None
        if resp.status_code >= 400:
            log.error("stripe rejected checkout (HTTP %s): %s", resp.status_code, resp.text[:500])
            raise GatewayError(502, "payments_unavailable", "could not start checkout")
        session = resp.json()
        return JSONResponse(
            {"checkout_url": session.get("url"), "session_id": session.get("id"), "amount_usd": str(amount)},
            headers={"X-Request-Id": request_id},
        )

    return await run_request(request, work)


@router.post("/stripe/webhook", include_in_schema=False)
async def stripe_webhook(request: Request) -> Response:
    services = get_services(request)
    settings = services.settings
    if not settings.stripe_enabled:
        return JSONResponse({"error": "payments disabled"}, status_code=503)
    payload = await request.body()
    if not verify_stripe_signature(
        payload, request.headers.get("stripe-signature", ""), settings.stripe_webhook_secret.get_secret_value()
    ):
        log.warning("stripe webhook with bad signature", extra={"event": "stripe_bad_signature"})
        return JSONResponse({"error": "invalid signature"}, status_code=400)

    event = json.loads(payload)
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
        cents = int(obj.get("amount_subtotal") if obj.get("amount_subtotal") is not None else obj["amount_total"])
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
                    user_id=user_id, amount=amount, source="stripe", external_id=str(obj.get("id")), note=f"stripe event {event.get('id')}"
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
