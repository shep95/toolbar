"""General-purpose transactions: charge the per-transaction fee for anything.

AI requests are one kind of transaction. This API covers every other kind —
payments, orders, transfers, bookings, sign-ups — from any app, in any
country and currency:

    POST /v1/transactions   {"reference": "order_123", "type": "payment",
                             "amount": "49.90", "currency": "EUR", "country": "DE"}

The proxy does not move the transaction's money. It records the transaction
and charges the fee (the $0.03 base, adjusted for the account's country) to the
account's prepaid balance. ``reference`` is the caller's own ID: sending the
same reference again returns the original record and is never charged twice,
so callers can retry safely.
"""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from typing import Any

import orjson
from fastapi import APIRouter, Request
from fastapi.responses import Response
from sqlalchemy import select

from .billing import BillingRejected
from .countries import income_group, normalise_country, plain
from .db import DB_UNAVAILABLE_ERRORS
from .errors import GatewayError
from .gateway import authenticate, enforce_rate_limit, json_response, read_json_body, run_request
from .models import Charge
from .services import Services

router = APIRouter()

REFERENCE_RE = re.compile(r"^[A-Za-z0-9._:/@#-]{1,200}$")
TYPE_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
MAX_AMOUNT = Decimal("100000000000000")


def _money(value) -> str | None:
    return None if value is None else f"{Decimal(value):.6f}"


def charge_json(charge: Charge) -> dict[str, Any]:
    return {
        "id": str(charge.id),
        "object": "transaction",
        "reference": charge.reference,
        "type": charge.type,
        "amount": None if charge.amount is None else plain(charge.amount),
        "currency": charge.currency,
        "country": charge.country,
        "description": charge.description,
        "metadata": orjson.loads(charge.metadata_json) if charge.metadata_json else {},
        "fee": {
            "amount_usd": _money(charge.fee_charged),
            "country": charge.fee_country,
            "multiplier": plain(charge.fee_multiplier),
        },
        "created_at": charge.timestamp.isoformat() if charge.timestamp else None,
    }


def _parse(body: dict[str, Any]) -> dict[str, Any]:
    def bad(message: str):
        raise GatewayError(400, "invalid_request", message)

    reference = body.get("reference")
    if not isinstance(reference, str) or not REFERENCE_RE.match(reference):
        bad("'reference' is required: your own ID for this transaction (up to 200 letters, digits and . _ : / @ # -)")
    tx_type = body.get("type", "transaction")
    if not isinstance(tx_type, str) or not TYPE_RE.match(tx_type):
        bad("'type' must be a short label such as payment, order, transfer (letters, digits and . _ -)")

    amount = body.get("amount")
    if amount is not None:
        if isinstance(amount, bool) or not isinstance(amount, (int, float, str)):
            bad("'amount' must be a number")
        try:
            amount = Decimal(str(amount))
        except InvalidOperation:
            bad("'amount' must be a number")
        if not amount.is_finite() or amount < 0 or amount > MAX_AMOUNT:
            bad("'amount' must be between 0 and 100000000000000")
        amount = amount.quantize(Decimal("0.000001"))

    currency = body.get("currency")
    if currency is not None:
        if not isinstance(currency, str) or not CURRENCY_RE.match(currency.upper()):
            bad("'currency' must be an ISO 4217 code such as USD, EUR, INR")
        currency = currency.upper()

    try:
        country = normalise_country(body.get("country"))
    except ValueError as exc:
        bad(str(exc))

    description = body.get("description")
    if description is not None and (not isinstance(description, str) or len(description) > 500):
        bad("'description' must be text of at most 500 characters")

    metadata = body.get("metadata")
    metadata_json = None
    if metadata is not None:
        if not isinstance(metadata, dict) or len(metadata) > 20:
            bad("'metadata' must be an object with at most 20 keys")
        for key, value in metadata.items():
            if len(key) > 40 or not isinstance(value, (str, int, float, bool)) or len(str(value)) > 500:
                bad("'metadata' keys must be at most 40 characters and values plain text or numbers up to 500 characters")
        metadata_json = orjson.dumps(metadata, option=orjson.OPT_SORT_KEYS).decode()

    return {
        "reference": reference, "type": tx_type, "amount": amount, "currency": currency, "country": country,
        "description": description, "metadata_json": metadata_json,
    }


def _same_transaction(charge: Charge, fields: dict[str, Any]) -> bool:
    stored_amount = None if charge.amount is None else Decimal(charge.amount).quantize(Decimal("0.000001"))
    return charge.type == fields["type"] and stored_amount == fields["amount"] and charge.currency == fields["currency"]


@router.post("/v1/transactions")
async def record_transaction(request: Request) -> Response:
    async def work(services: Services, request_id: str) -> Response:
        caller = await authenticate(services, request)
        enforce_rate_limit(services, caller)
        fields = _parse(await read_json_body(services, request))
        fee_country = caller.country
        if services.settings.price_by_transaction_country and fields["country"]:
            fee_country = fields["country"]
        try:
            result = await services.billing.record_charge(
                user_id=caller.user_id, api_key_id=caller.api_key_id, fee_country=fee_country,
                request_id=request_id, **fields,
            )
        except BillingRejected as exc:
            raise GatewayError(exc.status_code, exc.outcome, exc.message) from None
        except DB_UNAVAILABLE_ERRORS:
            raise GatewayError(503, "database_unavailable", "service temporarily unavailable", write_audit_row=False) from None

        if result.replay and not _same_transaction(result.charge, fields):
            raise GatewayError(
                409, "reference_conflict",
                "this reference was already used for a different transaction; use a new reference",
            )
        services.key_usage.touch(caller.api_key_id)
        payload = charge_json(result.charge)
        payload["replayed"] = result.replay
        headers = {"X-Request-Id": request_id, "X-Fee-Charged": "0.000000" if result.replay else payload["fee"]["amount_usd"]}
        if result.balance_after is not None:
            payload["balance_remaining_usd"] = _money(result.balance_after)
            headers["X-Balance-Remaining"] = payload["balance_remaining_usd"]
        return json_response(payload, status_code=200 if result.replay else 201, headers=headers)

    return await run_request(request, work)


@router.get("/v1/transactions")
async def list_transactions(request: Request) -> Response:
    async def work(services: Services, request_id: str) -> Response:
        caller = await authenticate(services, request)
        enforce_rate_limit(services, caller)
        params = request.query_params
        try:
            limit = min(max(int(params.get("limit", "50")), 1), 200)
        except ValueError:
            raise GatewayError(400, "invalid_request", "'limit' must be a number") from None
        stmt = select(Charge).where(Charge.user_id == caller.user_id).order_by(Charge.timestamp.desc()).limit(limit)
        reference = params.get("reference")
        if reference:
            stmt = stmt.where(Charge.reference == reference)
        try:
            async with services.db.session() as session:
                rows = (await session.execute(stmt)).scalars().all()
        except DB_UNAVAILABLE_ERRORS:
            raise GatewayError(503, "database_unavailable", "service temporarily unavailable", write_audit_row=False) from None
        return json_response({"object": "list", "data": [charge_json(c) for c in rows]}, headers={"X-Request-Id": request_id})

    return await run_request(request, work)


async def fee_quote(services: Services, country: str | None) -> dict[str, Any]:
    """What one transaction costs this account right now."""
    multiplier = await services.billing.country_multiplier(country)
    base = await services.billing.price_for("transactions", None)
    return {
        "country": country,
        "income_group": income_group(country) if country else None,
        "multiplier": plain(multiplier),
        "per_transaction_usd": _money(base.scaled(multiplier).fee_for(None)),
    }
