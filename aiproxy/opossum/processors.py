"""Payment processors underneath the relay.

The relay never holds or moves funds itself; an established processor does.

* ``stripe``: Stripe Connect destination charges through Stripe Checkout.
  The payer pays on Stripe's page. Stripe holds the card details; the
  recipient is a Stripe connected account (onboarded and verified by Stripe)
  that receives the payment minus Opossum's application fee. The recipient
  sees Opossum's transaction ID and the payer's pseudonym, not the payer's
  card or identity.
* ``stripe`` with account ``platform``: the platform itself is the
  recipient (the operator's own business). A plain Stripe Checkout payment,
  no Connect needed; Opossum's fee is simply part of what the platform keeps.
* ``sandbox``: settles instantly with test money so the whole flow can be
  tried. Every sandbox receipt carries ``"test": true``; nothing is paid.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from decimal import Decimal

import httpx

from ..services import Services
from .models import OpRecipient, OpTransaction

log = logging.getLogger("aiproxy.opossum")

PAYMENT_PURPOSE = "opossum_payment"
# processor_account value meaning the platform's own Stripe account.
PLATFORM_ACCOUNT = "platform"


class ProcessorError(Exception):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


@dataclass(frozen=True)
class Started:
    status: str  # settled | pending_payment
    reference: str
    checkout_url: str | None = None


def minor_units(value: Decimal) -> int:
    return int((value * 100).to_integral_value())


async def start_payment(services: Services, tx: OpTransaction, recipient: OpRecipient, base_url: str) -> Started:
    if recipient.processor == "sandbox":
        if not services.settings.opossum_sandbox_enabled:
            raise ProcessorError("sandbox payments are switched off")
        return Started("settled", "sbx_" + tx.id.split("_", 1)[1])
    if recipient.processor == "stripe":
        return await _stripe_checkout(services, tx, recipient, base_url)
    raise ProcessorError("this recipient has no payment processor configured")


async def _stripe_checkout(services: Services, tx: OpTransaction, recipient: OpRecipient, base_url: str) -> Started:
    settings = services.settings
    if not settings.stripe_secret_key:
        raise ProcessorError("Stripe is not configured")
    direct = recipient.processor_account == PLATFORM_ACCOUNT
    if not direct and (not recipient.processor_account or not recipient.processor_account.startswith("acct_")):
        raise ProcessorError("this recipient has not finished Stripe onboarding")
    application_fee = tx.opossum_fee + tx.processor_fee
    form = {
        "mode": "payment",
        "success_url": f"{base_url}/opossum#paid/{tx.id}",
        "cancel_url": f"{base_url}/opossum#cancelled/{tx.id}",
        "line_items[0][quantity]": "1",
        "line_items[0][price_data][currency]": tx.currency.lower(),
        "line_items[0][price_data][unit_amount]": str(minor_units(tx.total_cost)),
        # The recipient's name is shown to the payer; nothing about the payer
        # is sent here.
        "line_items[0][price_data][product_data][name]": f"Payment to {recipient.display_name}",
        "payment_intent_data[description]": f"Opossum {tx.id}",
        "payment_intent_data[metadata][opossum_tx]": tx.id,
        "metadata[purpose]": PAYMENT_PURPOSE,
        "metadata[opossum_tx]": tx.id,
        "client_reference_id": tx.id,
    }
    if not direct:
        form["payment_intent_data[application_fee_amount]"] = str(minor_units(application_fee))
        form["payment_intent_data[transfer_data][destination]"] = recipient.processor_account
    try:
        resp = await services.http.post(
            f"{settings.stripe_api_base}/checkout/sessions",
            data=form,
            headers={"Authorization": f"Bearer {settings.stripe_secret_key.get_secret_value()}", "Idempotency-Key": "opossum-" + tx.id},
        )
    except httpx.HTTPError:
        log.exception("stripe unreachable for opossum payment")
        raise ProcessorError("the payment processor could not be reached") from None
    if resp.status_code >= 400:
        log.error("stripe rejected opossum checkout (HTTP %s): %s", resp.status_code, resp.text[:300])
        raise ProcessorError("the payment processor refused this payment")
    session = resp.json()
    url = session.get("url") or ""
    if not url.startswith("https://checkout.stripe.com/"):
        raise ProcessorError("the payment processor returned an unexpected checkout address")
    return Started("pending_payment", str(session.get("id")), url)
