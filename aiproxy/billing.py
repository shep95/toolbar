"""Billing engine.

Every proxied request goes through three steps:

1. ``reserve`` (before the upstream call): atomically deduct the per-request
   fee from the balance (only if the user is active, the key is active and
   the balance covers it) and insert a ``pending`` transaction. Reserving up
   front means two concurrent requests can never both spend the same last cent.
2. ``complete`` (upstream succeeded): compute the final fee from usage, adjust
   the reservation to that amount and mark the transaction ``success``.
3. ``fail`` (upstream failed): refund the reservation in full and mark the
   transaction ``failed``/``error``. The user is never charged for a failure.

``complete`` and ``fail`` only act on a transaction that is still ``pending``,
so each reservation settles exactly once even if a stale-transaction sweep and
a late-finishing stream race each other.

Speed: on PostgreSQL each step is a single auto-committed SQL statement (one
network round trip, row locks held for microseconds). Other databases (SQLite
in tests and local development) use the equivalent multi-statement version.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal

from sqlalchemy import and_, exists, select, text, update
from sqlalchemy.exc import DBAPIError, IntegrityError

from .connectors import Usage
from .db import Database
from .countries import default_multiplier
from .domains import pricing_key
from .models import (
    ApiKey,
    Charge,
    CountryPricing,
    KeyStatus,
    Pricing,
    Transaction,
    TxStatus,
    User,
    UserStatus,
    utcnow,
)

log = logging.getLogger("aiproxy.billing")

SIX_PLACES = Decimal("0.000001")


class BillingRejected(Exception):
    def __init__(self, status_code: int, outcome: str, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.outcome = outcome
        self.message = message


@dataclass(frozen=True)
class Price:
    fee_per_request: Decimal
    fee_per_1k_tokens: Decimal = Decimal("0")

    def fee_for(self, tokens: int | None) -> Decimal:
        fee = self.fee_per_request
        if tokens and self.fee_per_1k_tokens:
            fee += self.fee_per_1k_tokens * Decimal(tokens) / Decimal(1000)
        return fee.quantize(SIX_PLACES, rounding=ROUND_HALF_UP)

    def scaled(self, multiplier: Decimal) -> Price:
        if multiplier == 1:
            return self
        return Price(self.fee_per_request * multiplier, self.fee_per_1k_tokens * multiplier)


@dataclass(frozen=True)
class Reservation:
    transaction_id: uuid.UUID
    user_id: uuid.UUID
    price: Price
    reserved: Decimal
    balance_after: Decimal
    fee_country: str | None = None
    fee_multiplier: Decimal = Decimal("1")


@dataclass(frozen=True)
class ChargeResult:
    charge: Charge
    balance_after: Decimal | None
    replay: bool


@dataclass(frozen=True)
class Settlement:
    fee: Decimal
    balance: Decimal | None
    applied: bool


# --------------------------------------------------------------------- PostgreSQL fast path

_PG_RESERVE = text(
    """
    WITH u AS (
        UPDATE users SET balance = balance - CAST(:fee AS numeric)
        WHERE id = CAST(:uid AS uuid)
          AND status = 'active'
          AND balance > 0
          AND balance >= CAST(:fee AS numeric)
          AND EXISTS (SELECT 1 FROM api_keys k WHERE k.id = CAST(:kid AS uuid) AND k.status = 'active')
        RETURNING balance
    ), t AS (
        INSERT INTO transactions
            (id, user_id, api_key_id, provider, model_called, endpoint, fee_charged, timestamp, status, request_id,
             fee_country, fee_multiplier)
        SELECT CAST(:txid AS uuid), CAST(:uid AS uuid), CAST(:kid AS uuid), CAST(:provider AS varchar),
               CAST(:model AS varchar), CAST(:endpoint AS varchar), CAST(:fee AS numeric), now(),
               'pending', CAST(:rid AS varchar), CAST(:fcountry AS varchar), CAST(:fmult AS numeric)
        FROM u
        RETURNING id
    )
    SELECT balance FROM u
    """
)

_PG_CHARGE = text(
    """
    WITH u AS (
        UPDATE users SET balance = balance - CAST(:fee AS numeric)
        WHERE id = CAST(:uid AS uuid)
          AND status = 'active'
          AND balance > 0
          AND balance >= CAST(:fee AS numeric)
          AND EXISTS (SELECT 1 FROM api_keys k WHERE k.id = CAST(:kid AS uuid) AND k.status = 'active')
          AND NOT EXISTS (SELECT 1 FROM charges c WHERE c.user_id = CAST(:uid AS uuid) AND c.reference = CAST(:ref AS varchar))
        RETURNING balance
    ), c AS (
        INSERT INTO charges
            (id, user_id, api_key_id, reference, domain, type, amount, currency, country, description, metadata_json,
             attributes_json, fee_charged, fee_country, fee_multiplier, timestamp, request_id)
        SELECT CAST(:cid AS uuid), CAST(:uid AS uuid), CAST(:kid AS uuid), CAST(:ref AS varchar),
               CAST(:domain AS varchar), CAST(:type AS varchar), CAST(:amount AS numeric), CAST(:currency AS varchar),
               CAST(:country AS varchar), CAST(:description AS varchar), CAST(:meta AS text), CAST(:attrs AS text),
               CAST(:fee AS numeric), CAST(:fcountry AS varchar), CAST(:fmult AS numeric), now(),
               CAST(:rid AS varchar)
        FROM u
        RETURNING id
    )
    SELECT balance FROM u
    """
)

_PG_SETTLE_TX = """
    UPDATE transactions SET
        status = 'success', fee_charged = CAST(:fee AS numeric), tokens_used = CAST(:tokens AS integer),
        input_tokens = CAST(:input AS integer), output_tokens = CAST(:output AS integer),
        upstream_status = CAST(:ustatus AS integer), latency_ms = CAST(:latency AS integer), completed_at = now(),
        model_called = COALESCE(CAST(:model AS varchar), model_called)
    WHERE id = CAST(:txid AS uuid) AND status = 'pending'
    RETURNING user_id
"""
_PG_COMPLETE_FLAT = text(_PG_SETTLE_TX)
_PG_COMPLETE_ADJUST = text(
    """
    WITH t AS (
        UPDATE transactions SET
            status = 'success', fee_charged = CAST(:fee AS numeric), tokens_used = CAST(:tokens AS integer),
            input_tokens = CAST(:input AS integer), output_tokens = CAST(:output AS integer),
            upstream_status = CAST(:ustatus AS integer), latency_ms = CAST(:latency AS integer), completed_at = now(),
            model_called = COALESCE(CAST(:model AS varchar), model_called)
        WHERE id = CAST(:txid AS uuid) AND status = 'pending'
        RETURNING user_id
    )
    UPDATE users SET balance = users.balance - CAST(:delta AS numeric)
    FROM t WHERE users.id = t.user_id
    RETURNING users.balance
    """
)
_PG_REFUND = text(
    """
    WITH t AS (
        UPDATE transactions SET
            status = CAST(:status AS varchar), fee_charged = 0, upstream_status = CAST(:ustatus AS integer),
            error = CAST(:error AS text), latency_ms = CAST(:latency AS integer), completed_at = now()
        WHERE id = CAST(:txid AS uuid) AND status = 'pending'
        RETURNING user_id
    )
    UPDATE users SET balance = users.balance + CAST(:amount AS numeric)
    FROM t WHERE users.id = t.user_id
    RETURNING users.id
    """
)


class BillingEngine:
    def __init__(self, db: Database, default_fee_per_request: Decimal, pricing_cache_seconds: float = 30.0):
        self.db = db
        self.default_price = Price(fee_per_request=Decimal(default_fee_per_request))
        self.fast = db.engine.dialect.name == "postgresql"
        self._autocommit = db.engine.execution_options(isolation_level="AUTOCOMMIT") if self.fast else None
        self._price_cache: dict[tuple[str, str], tuple[Price, float]] = {}
        self._pricing_ttl = pricing_cache_seconds
        self._country_overrides: dict[str, Decimal] = {}
        self._country_overrides_expire = 0.0

    async def _pg(self, statement, params: dict):
        """Run one auto-committed statement; retry once if the pooled connection was dead.

        Settling and refunding are idempotent (they only touch pending rows).
        A retried reservation can at worst hold a second fee on a transaction
        that never reaches a provider, which the stale sweep refunds.
        """
        for attempt in (1, 2):
            try:
                async with self._autocommit.connect() as conn:
                    return (await conn.execute(statement, params)).first()
            except DBAPIError as exc:
                if attempt == 1 and exc.connection_invalidated:
                    continue
                raise

    # ------------------------------------------------------------ pricing

    def invalidate_pricing(self) -> None:
        self._price_cache.clear()
        self._country_overrides_expire = 0.0

    async def country_multiplier(self, country: str | None) -> Decimal:
        """Admin override for the country if any, else its income-group default."""
        if not country:
            return Decimal("1")
        now = time.monotonic()
        if self._country_overrides_expire <= now:
            async with self.db.session() as session:
                rows = (await session.execute(select(CountryPricing.country, CountryPricing.multiplier))).all()
            self._country_overrides = {c: Decimal(m) for c, m in rows}
            self._country_overrides_expire = now + self._pricing_ttl
        return self._country_overrides.get(country, default_multiplier(country))

    async def price_for(self, provider: str, model: str | None) -> Price:
        key = (provider, model or "*")
        cached = self._price_cache.get(key)
        now = time.monotonic()
        if cached and cached[1] > now:
            return cached[0]
        async with self.db.session() as session:
            price = await self.lookup_price(session, provider, model)
        if len(self._price_cache) > 10_000:
            self._price_cache.clear()
        self._price_cache[key] = (price, now + self._pricing_ttl)
        return price

    async def lookup_price(self, session, provider: str, model: str | None) -> Price:
        candidates = [(provider, model or "*"), (provider, "*"), ("*", "*")]
        rows = (
            await session.execute(
                select(Pricing).where(
                    Pricing.provider.in_({p for p, _ in candidates}),
                    Pricing.model.in_({m for _, m in candidates}),
                )
            )
        ).scalars().all()
        by_key = {(r.provider, r.model): r for r in rows}
        for key in candidates:
            row = by_key.get(key)
            if row is not None:
                return Price(Decimal(row.fee_per_request), Decimal(row.fee_per_1k_tokens))
        return self.default_price

    # ------------------------------------------------------------ reserve

    async def reserve(
        self,
        *,
        user_id: uuid.UUID,
        api_key_id: uuid.UUID,
        provider: str,
        model: str | None,
        endpoint: str,
        request_id: str,
        country: str | None = None,
    ) -> Reservation:
        multiplier = await self.country_multiplier(country)
        price = (await self.price_for(provider, model)).scaled(multiplier)
        reserved = price.fee_for(None)
        tx_id = uuid.uuid4()
        model = model[:200] if model else None
        if self.fast:
            row = await self._pg(
                _PG_RESERVE,
                {
                    "fee": reserved, "uid": user_id, "kid": api_key_id, "txid": tx_id,
                    "provider": provider, "model": model, "endpoint": endpoint[:100], "rid": request_id,
                    "fcountry": country, "fmult": multiplier,
                },
            )
            balance_after = row[0] if row else None
        else:
            balance_after = await self._reserve_portable(
                user_id, api_key_id, provider, model, endpoint, request_id, reserved, tx_id, country, multiplier
            )
        if balance_after is None:
            raise await self._rejection_reason(user_id, api_key_id)
        return Reservation(
            transaction_id=tx_id, user_id=user_id, price=price, reserved=reserved, balance_after=Decimal(balance_after),
            fee_country=country, fee_multiplier=multiplier,
        )

    async def _reserve_portable(
        self, user_id, api_key_id, provider, model, endpoint, request_id, reserved, tx_id, country, multiplier
    ):
        async with self.db.session() as session, session.begin():
            balance_after = (
                await session.execute(
                    update(User)
                    .where(
                        and_(
                            User.id == user_id,
                            User.status == UserStatus.ACTIVE,
                            User.balance > 0,
                            User.balance >= reserved,
                            exists().where(ApiKey.id == api_key_id, ApiKey.status == KeyStatus.ACTIVE),
                        )
                    )
                    .values(balance=User.balance - reserved)
                    .returning(User.balance)
                )
            ).scalar_one_or_none()
            if balance_after is None:
                return None
            session.add(
                Transaction(
                    id=tx_id, user_id=user_id, api_key_id=api_key_id, provider=provider, model_called=model,
                    endpoint=endpoint[:100], fee_charged=reserved, status=TxStatus.PENDING, request_id=request_id,
                    fee_country=country, fee_multiplier=multiplier,
                )
            )
            return balance_after

    async def _rejection_reason(self, user_id: uuid.UUID, api_key_id: uuid.UUID) -> BillingRejected:
        async with self.db.session() as session:
            user_status = (await session.execute(select(User.status).where(User.id == user_id))).scalar_one_or_none()
            key_status = (await session.execute(select(ApiKey.status).where(ApiKey.id == api_key_id))).scalar_one_or_none()
        if key_status != KeyStatus.ACTIVE:
            return BillingRejected(401, "key_revoked", "this API key has been revoked")
        if user_status != UserStatus.ACTIVE:
            return BillingRejected(403, "user_suspended", "account is suspended")
        return BillingRejected(402, "insufficient_balance", "insufficient balance; top up to continue")

    # ------------------------------------------------------------ general transactions

    async def record_charge(
        self,
        *,
        user_id: uuid.UUID,
        api_key_id: uuid.UUID,
        reference: str,
        domain: str,
        type: str,
        amount: Decimal | None,
        currency: str | None,
        country: str | None,
        description: str | None,
        metadata_json: str | None,
        attributes_json: str | None,
        fee_country: str | None,
        request_id: str,
    ) -> ChargeResult:
        """Charge the fee for one transaction and record it, exactly once per reference.

        Debit and record happen in one atomic step. Repeating a reference
        returns the original record without charging again.
        """
        existing = await self._find_charge(user_id, reference)
        if existing is not None:
            return ChargeResult(existing, None, replay=True)

        multiplier = await self.country_multiplier(fee_country)
        fee = (await self.price_for(pricing_key(domain), type)).scaled(multiplier).fee_for(None)
        charge = Charge(
            id=uuid.uuid4(), user_id=user_id, api_key_id=api_key_id, reference=reference, domain=domain, type=type,
            amount=amount, currency=currency, country=country, description=description,
            metadata_json=metadata_json, attributes_json=attributes_json, fee_charged=fee,
            fee_country=fee_country, fee_multiplier=multiplier, request_id=request_id,
        )
        try:
            if self.fast:
                row = await self._pg(
                    _PG_CHARGE,
                    {
                        "fee": fee, "uid": user_id, "kid": api_key_id, "ref": reference, "cid": charge.id,
                        "domain": domain, "type": type, "amount": amount, "currency": currency, "country": country,
                        "description": description, "meta": metadata_json, "attrs": attributes_json,
                        "fcountry": fee_country,
                        "fmult": multiplier, "rid": request_id,
                    },
                )
                balance_after = row[0] if row else None
            else:
                balance_after = await self._charge_portable(charge)
        except IntegrityError:
            balance_after = None  # a concurrent request with the same reference won the race
        if balance_after is None:
            existing = await self._find_charge(user_id, reference)
            if existing is not None:
                return ChargeResult(existing, None, replay=True)
            raise await self._rejection_reason(user_id, api_key_id)
        charge.timestamp = charge.timestamp or utcnow()
        return ChargeResult(charge, Decimal(balance_after), replay=False)

    async def _charge_portable(self, charge: Charge):
        async with self.db.session() as session, session.begin():
            duplicate = (
                await session.execute(
                    select(Charge.id).where(Charge.user_id == charge.user_id, Charge.reference == charge.reference)
                )
            ).first()
            if duplicate:
                return None
            balance_after = (
                await session.execute(
                    update(User)
                    .where(
                        and_(
                            User.id == charge.user_id,
                            User.status == UserStatus.ACTIVE,
                            User.balance > 0,
                            User.balance >= charge.fee_charged,
                            exists().where(ApiKey.id == charge.api_key_id, ApiKey.status == KeyStatus.ACTIVE),
                        )
                    )
                    .values(balance=User.balance - charge.fee_charged)
                    .returning(User.balance)
                )
            ).scalar_one_or_none()
            if balance_after is None:
                return None
            session.add(charge)
            await session.flush()
            session.expunge(charge)
            return balance_after

    async def _find_charge(self, user_id: uuid.UUID, reference: str) -> Charge | None:
        async with self.db.session() as session:
            return (
                await session.execute(select(Charge).where(Charge.user_id == user_id, Charge.reference == reference))
            ).scalar_one_or_none()

    # ------------------------------------------------------------ settle

    async def complete(
        self,
        reservation: Reservation,
        *,
        usage: Usage,
        model: str | None,
        upstream_status: int,
        latency_ms: int,
    ) -> Settlement:
        fee = reservation.price.fee_for(usage.total)
        delta = fee - reservation.reserved
        model = model[:200] if model else None
        if self.fast:
            params = {
                "fee": fee, "tokens": usage.total, "input": usage.input_tokens, "output": usage.output_tokens,
                "ustatus": upstream_status, "latency": latency_ms, "model": model,
                "txid": reservation.transaction_id, "delta": delta,
            }
            row = await self._pg(_PG_COMPLETE_ADJUST if delta else _PG_COMPLETE_FLAT, params)
            if row is None:
                log.warning("transaction %s was already settled; not charging again", reservation.transaction_id)
                return Settlement(fee=Decimal("0"), balance=None, applied=False)
            balance = Decimal(row[0]) if delta else reservation.balance_after
            return Settlement(fee=fee, balance=balance, applied=True)

        async with self.db.session() as session, session.begin():
            values = dict(
                status=TxStatus.SUCCESS, fee_charged=fee, tokens_used=usage.total, input_tokens=usage.input_tokens,
                output_tokens=usage.output_tokens, upstream_status=upstream_status, latency_ms=latency_ms,
                completed_at=utcnow(),
            )
            if model:
                values["model_called"] = model
            settled = await session.execute(
                update(Transaction)
                .where(Transaction.id == reservation.transaction_id, Transaction.status == TxStatus.PENDING)
                .values(**values)
                .returning(Transaction.id)
            )
            if settled.scalar_one_or_none() is None:
                log.warning("transaction %s was already settled; not charging again", reservation.transaction_id)
                return Settlement(fee=Decimal("0"), balance=None, applied=False)
            balance = reservation.balance_after
            if delta:
                # Token-based pricing can cost more than the reservation. The
                # balance may then dip below zero; the next request is blocked.
                result = await session.execute(
                    update(User)
                    .where(User.id == reservation.user_id)
                    .values(balance=User.balance - delta)
                    .returning(User.balance)
                )
                balance = Decimal(result.scalar_one())
            return Settlement(fee=fee, balance=balance, applied=True)

    async def fail(
        self,
        reservation: Reservation,
        *,
        status: str = TxStatus.FAILED,
        upstream_status: int | None = None,
        error: str | None = None,
        latency_ms: int | None = None,
    ) -> bool:
        return await self._refund(
            transaction_id=reservation.transaction_id,
            user_id=reservation.user_id,
            amount=reservation.reserved,
            status=status,
            upstream_status=upstream_status,
            error=error,
            latency_ms=latency_ms,
        )

    async def _refund(self, *, transaction_id, user_id, amount, status, upstream_status, error, latency_ms) -> bool:
        error = error[:2000] if error else None
        if self.fast:
            row = await self._pg(
                _PG_REFUND,
                {
                    "status": status, "ustatus": upstream_status, "error": error, "latency": latency_ms,
                    "txid": transaction_id, "amount": Decimal(amount),
                },
            )
            return row is not None

        async with self.db.session() as session, session.begin():
            settled = await session.execute(
                update(Transaction)
                .where(Transaction.id == transaction_id, Transaction.status == TxStatus.PENDING)
                .values(
                    status=status, fee_charged=Decimal("0"), upstream_status=upstream_status, error=error,
                    latency_ms=latency_ms, completed_at=utcnow(),
                )
                .returning(Transaction.id)
            )
            if settled.scalar_one_or_none() is None:
                return False
            if amount:
                await session.execute(update(User).where(User.id == user_id).values(balance=User.balance + amount))
            return True

    async def reconcile_stale(self, older_than: timedelta, now: datetime | None = None) -> int:
        """Refund and close transactions left pending (crash, lost settlement...)."""
        cutoff = (now or utcnow()) - older_than
        async with self.db.session() as session:
            stale = (
                await session.execute(
                    select(Transaction.id, Transaction.user_id, Transaction.fee_charged)
                    .where(Transaction.status == TxStatus.PENDING, Transaction.timestamp < cutoff)
                    .limit(500)
                )
            ).all()
        count = 0
        for tx_id, user_id, reserved in stale:
            if await self._refund(
                transaction_id=tx_id,
                user_id=user_id,
                amount=Decimal(reserved),
                status=TxStatus.ERROR,
                upstream_status=None,
                error="abandoned: still pending after timeout; reservation refunded",
                latency_ms=None,
            ):
                count += 1
        if count:
            log.warning("reconciled %d stale pending transactions", count)
        return count
