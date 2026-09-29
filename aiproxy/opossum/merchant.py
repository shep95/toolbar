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
from .models import OpInvoice, OpRecipient, OpTransaction
from .relay import money, currencies, parse_amount, recipient_public, recipient_view
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
