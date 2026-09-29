"""Recipient-facing API (``/opossum/merchant/api``), authenticated with a merchant key.

This is the recipient's whole view of a payment: amount, what they receive,
the payer's pseudonym, and only the identity fields the payer chose to show.
"""

from __future__ import annotations

import hashlib
from decimal import Decimal

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from ..services import get_services
from .crypto import random_id
from .models import OpInvoice, OpRecipient, OpTransaction, OpWebhookDelivery
from .relay import money, currencies, parse_amount, recipient_public, recipient_view
from . import webhooks
from .web import OpError, aware, keys

router = APIRouter(prefix="/opossum/merchant/api")


def hash_merchant_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


async def current_recipient(request: Request):
    services = get_services(request)
    k = keys(services)
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token.startswith("opm_") or len(token) > 100:
        raise OpError(401, "merchant_key_required", "send your merchant key as Authorization: Bearer opm_...")
    async with services.db.session() as session:
        recipient = await session.scalar(select(OpRecipient).where(OpRecipient.api_key_hash == hash_merchant_key(token.strip())))
    if recipient is None or recipient.status == "disabled":
        raise OpError(401, "merchant_key_invalid", "that merchant key is not valid")
    return services, k, recipient


class InvoiceIn(BaseModel):
    reference: str = Field(min_length=1, max_length=80)
    amount: str
    currency: str = "USD"
    description: str | None = Field(default=None, max_length=200)


def invoice_json(inv: OpInvoice) -> dict:
    return {"id": inv.id, "reference": inv.reference, "description": inv.description, "amount": money(inv.amount),
            "currency": inv.currency, "status": inv.status, "paid_transaction": inv.paid_tx_id,
            "created_at": aware(inv.created_at).isoformat(), "pay_link": f"/opossum#pay/invoice/{inv.id}"}


@router.get("/me")
async def me(ctx=Depends(current_recipient)):
    _, _, recipient = ctx
    return recipient_public(recipient)


@router.get("/payments")
async def payments(ctx=Depends(current_recipient), limit: int = Query(default=100, ge=1, le=500)):
    services, k, recipient = ctx
    async with services.db.session() as session:
        rows = (await session.execute(select(OpTransaction).where(OpTransaction.recipient_id == recipient.id)
                                      .order_by(OpTransaction.created_at.desc()).limit(limit))).scalars().all()
    return [recipient_view(k, tx) for tx in rows]


@router.post("/invoices", status_code=201)
async def create_invoice(body: InvoiceIn, ctx=Depends(current_recipient)):
    services, _, recipient = ctx
    currency = body.currency.upper()
    if currency not in currencies(services):
        raise OpError(400, "unsupported_currency", f"currency must be one of {', '.join(currencies(services))}")
    amount = parse_amount(body.amount)
    if amount != amount.quantize(Decimal("0.01")):
        raise OpError(400, "invalid_amount", "amount can have at most 2 decimals")
    inv = OpInvoice(id=random_id("inv_", 9), recipient_id=recipient.id, reference=body.reference, description=body.description,
                    amount=amount, currency=currency, status="open")
    async with services.db.session() as session, session.begin():
        session.add(inv)
    return invoice_json(inv)


@router.get("/invoices")
async def invoices(ctx=Depends(current_recipient)):
    services, _, recipient = ctx
    async with services.db.session() as session:
        rows = (await session.execute(select(OpInvoice).where(OpInvoice.recipient_id == recipient.id)
                                      .order_by(OpInvoice.created_at.desc()).limit(200))).scalars().all()
    return [invoice_json(i) for i in rows]


class RefundIn(BaseModel):
    # On-chain payments: the transaction that sent the refund from your wallet.
    txid: str | None = Field(default=None, max_length=100)


@router.post("/payments/{tx_id}/refund")
async def refund(tx_id: str, body: RefundIn | None = None, ctx=Depends(current_recipient)):
    """Refund one of your own settled payments in full."""
    from .relay import refund_payment

    services, k, recipient = ctx
    tx = await refund_payment(services, k, tx_id, actor=f"merchant:{recipient.handle}", reason="refunded by merchant",
                              recipient_id=recipient.id, chain_refund_txid=(body.txid if body else None))
    return {"id": tx.id, "status": tx.status}


class ChainSetup(BaseModel):
    btc_xpub: str | None = Field(default=None, max_length=130)
    btc_first_address: str | None = Field(default=None, max_length=100)
    btc_address_type: str | None = Field(default=None, max_length=12)
    usdc_address: str | None = Field(default=None, max_length=42)


async def apply_chain_setup(services, k, recipient_id, body: ChainSetup) -> dict:
    from .chainutil import ChainError
    from .chains import configure, rail_label, rails_for

    try:
        config = configure(body.btc_xpub, body.btc_first_address, body.btc_address_type, body.usdc_address)
    except ChainError as exc:
        raise OpError(400, "invalid_chain_setup", str(exc)) from None
    rails = rails_for(config)
    async with services.db.session() as session, session.begin():
        row = await session.get(OpRecipient, recipient_id)
        row.chain_config_enc = k.seal(config, f"op_recipients:{row.id}:chain")
        row.chain_rails = ",".join(rails)
        from . import audit

        await audit.append(session, "merchant", "chain_setup", row.handle, rails=rails)
    return {"rails": [{"id": r, "label": rail_label(r)} for r in rails],
            "btc_first_address": config.get("btc", {}).get("first_address"), "usdc_address": config.get("evm", {}).get("address")}


@router.put("/chain")
async def chain_setup(body: ChainSetup, ctx=Depends(current_recipient)):
    """Accept crypto straight to your own wallet. Opossum never holds keys or coins:
    give a Bitcoin extended public key (and your wallet's first receiving address,
    to confirm the key type) and/or a USDC receiving address."""
    services, k, recipient = ctx
    return await apply_chain_setup(services, k, recipient.id, body)


@router.get("/fees")
async def fees(ctx=Depends(current_recipient)):
    """Opossum fees on direct on-chain payments, billed to you."""
    _, _, recipient = ctx
    return {"fees_due_usd": money(recipient.fees_due or 0)}


class WebhookIn(BaseModel):
    url: str | None = Field(default=None, max_length=300)


@router.get("/webhook")
async def webhook_status(ctx=Depends(current_recipient)):
    services, _, recipient = ctx
    async with services.db.session() as session:
        recent = (await session.execute(select(OpWebhookDelivery).where(OpWebhookDelivery.recipient_id == recipient.id)
                                        .order_by(OpWebhookDelivery.id.desc()).limit(20))).scalars().all()
    return {"url": recipient.webhook_url, "events": list(webhooks.EVENT_TYPES),
            "signature": "Opossum-Signature: t=<unix>,v1=<hex hmac_sha256(secret, t + '.' + body)>",
            "recent": [{"event_id": d.event_id, "type": d.event_type, "attempts": d.attempts, "last_error": d.last_error,
                        "delivered_at": aware(d.delivered_at).isoformat() if d.delivered_at else None} for d in recent]}


@router.put("/webhook")
async def set_webhook(body: WebhookIn, ctx=Depends(current_recipient)):
    """Set (or clear, with url null) the endpoint for signed events. The secret is shown once."""
    services, k, recipient = ctx
    secret = None
    if body.url:
        try:
            await webhooks.check_url(body.url)
        except webhooks.WebhookUrlError as exc:
            raise OpError(400, "invalid_webhook_url", str(exc)) from None
        secret = webhooks.new_secret()
    async with services.db.session() as session, session.begin():
        row = await session.get(OpRecipient, recipient.id)
        row.webhook_url = body.url or None
        row.webhook_secret_enc = k.seal(secret, f"op_recipients:{row.id}:webhook") if secret else None
        if secret:
            webhooks.enqueue(session, row, "webhook.test", {"message": "your opossum webhook is set up"})
    return {"url": body.url or None, "secret": secret,
            "note": "shown once; verify each event's Opossum-Signature with it" if secret else "webhook removed"}
