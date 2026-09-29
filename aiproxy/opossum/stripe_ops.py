"""Calls to Stripe beyond Checkout: refunds, Connect readiness, Stripe Identity.

All calls use the platform's STRIPE_SECRET_KEY and never send anything about
the payer beyond what Stripe already holds as the processor.
"""

from __future__ import annotations

import logging

import httpx

from ..services import Services
from .processors import ProcessorError

log = logging.getLogger("aiproxy.opossum")


async def _stripe(services: Services, method: str, path: str, data: dict | None = None, idempotency_key: str | None = None) -> dict:
    settings = services.settings
    if not settings.stripe_secret_key:
        raise ProcessorError("Stripe is not configured (STRIPE_SECRET_KEY)")
    headers = {"Authorization": f"Bearer {settings.stripe_secret_key.get_secret_value()}"}
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
    try:
        resp = await services.http.request(method, f"{settings.stripe_api_base}{path}", data=data, headers=headers)
    except httpx.HTTPError:
        log.exception("stripe unreachable")
        raise ProcessorError("Stripe could not be reached") from None
    try:
        body = resp.json()
    except ValueError:
        body = {}
    if resp.status_code >= 400:
        error = body.get("error") if isinstance(body, dict) else None
        message = (error.get("message") if isinstance(error, dict) else None) or f"HTTP {resp.status_code}"
        log.error("stripe %s %s refused: %s", method, path, message)
        raise ProcessorError(f"Stripe: {message}")
    return body


async def payment_intent_for(services: Services, checkout_session_id: str) -> str | None:
    session = await _stripe(services, "GET", f"/checkout/sessions/{checkout_session_id}")
    return session.get("payment_intent")


async def refund(services: Services, *, payment_intent: str, direct: bool, tx_id: str) -> str:
    """Refund in full. For Connect payments the transfer and Opossum's fee are
    pulled back too, so nobody keeps money for a payment that was undone."""
    data = {"payment_intent": payment_intent, "metadata[opossum_tx]": tx_id, "reason": "requested_by_customer"}
    if not direct:
        data["reverse_transfer"] = "true"
        data["refund_application_fee"] = "true"
    result = await _stripe(services, "POST", "/refunds", data, idempotency_key="opossum-refund-" + tx_id)
    return str(result.get("id"))


async def account_ready(services: Services, account: str) -> tuple[bool, str]:
    """Whether a connected account can take payments and receive payouts."""
    info = await _stripe(services, "GET", f"/accounts/{account}")
    if info.get("charges_enabled") and info.get("payouts_enabled"):
        return True, "ready"
    due = (info.get("requirements") or {}).get("currently_due") or []
    reason = (info.get("requirements") or {}).get("disabled_reason") or ("details due: " + ", ".join(due[:5]) if due else "onboarding not finished")
    return False, reason


async def identity_session(services: Services, *, reference: str, return_url: str) -> dict:
    """A Stripe Identity document check. Stripe collects and verifies the
    document; Opossum sends only an opaque reference and learns the result."""
    data = {
        "type": "document",
        "metadata[opossum_ref]": reference,
        "return_url": return_url,
        "options[document][require_live_capture]": "true",
    }
    if services.settings.opossum_identity_selfie:
        data["options[document][require_matching_selfie]"] = "true"
    session = await _stripe(services, "POST", "/identity/verification_sessions", data, idempotency_key="opossum-kyc-" + reference)
    url = session.get("url") or ""
    if not url.startswith("https://verify.stripe.com/"):
        raise ProcessorError("Stripe Identity returned an unexpected address")
    return {"id": session.get("id"), "url": url}


async def payment_details(services: Services, payment_intent: str) -> dict:
    """How a Stripe payment was made: card, or a stablecoin on which network.

    Best effort: a missing detail never blocks settlement.
    """
    try:
        intent = await _stripe(services, "GET", f"/payment_intents/{payment_intent}?expand[]=latest_charge")
    except ProcessorError:
        return {}
    details = ((intent.get("latest_charge") or {}).get("payment_method_details") or {})
    kind = details.get("type")
    if kind == "crypto":
        crypto = details.get("crypto") or {}
        return {"payment_method": "stablecoin via Stripe", "chain": crypto.get("network"),
                "crypto_asset": (crypto.get("token_currency") or "usdc").upper(), "crypto_txid": crypto.get("transaction_hash")}
    return {"payment_method": kind} if kind else {}
