"""Billing engine.

Every proxied request goes through three steps:

1. ``reserve`` (before the upstream call): in one DB transaction, look up the
   price, atomically deduct the per-request fee from the balance (only if the
   user is active and can afford it) and insert a ``pending`` transaction.
   Reserving up front means two concurrent requests can never both spend the
   same last cent.
2. ``complete`` (upstream succeeded): compute the final fee from usage, adjust
   the reservation to that amount and mark the transaction ``success``.
3. ``fail`` (upstream failed): refund the reservation in full and mark the
   transaction ``failed``/``error``. The user is never charged for a failure.

``complete`` and ``fail`` only act on a transaction that is still ``pending``,
so each reservation settles exactly once even if a stale-transaction sweep and
a late-finishing stream race each other.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal

from sqlalchemy import and_, select, update

from .connectors import Usage
from .db import Database
from .models import ApiKey, Pricing, Transaction, TxStatus, User, UserStatus, utcnow

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


@dataclass(frozen=True)
class Reservation:
    transaction_id: uuid.UUID
    user_id: uuid.UUID
    price: Price
    reserved: Decimal
    balance_after: Decimal


@dataclass(frozen=True)
class Settlement:
    fee: Decimal
    balance: Decimal | None
    applied: bool


class BillingEngine:
    def __init__(self, db: Database, default_fee_per_request: Decimal):
        self.db = db
        self.default_price = Price(fee_per_request=Decimal(default_fee_per_request))

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

    async def reserve(
        self,
        *,
        user_id: uuid.UUID,
        api_key_id: uuid.UUID,
        provider: str,
        model: str | None,
        endpoint: str,
        request_id: str,
    ) -> Reservation:
        async with self.db.session() as session, session.begin():
            price = await self.lookup_price(session, provider, model)
            reserved = price.fee_for(None)
            result = await session.execute(
                update(User)
                .where(
                    and_(
                        User.id == user_id,
                        User.status == UserStatus.ACTIVE,
                        User.balance > 0,
                        User.balance >= reserved,
                    )
                )
                .values(balance=User.balance - reserved)
                .returning(User.balance)
            )
            balance_after = result.scalar_one_or_none()
            if balance_after is None:
                status = (await session.execute(select(User.status).where(User.id == user_id))).scalar_one_or_none()
                if status != UserStatus.ACTIVE:
                    raise BillingRejected(403, "user_suspended", "account is suspended")
                raise BillingRejected(402, "insufficient_balance", "insufficient balance; top up to continue")

            tx = Transaction(
                user_id=user_id,
                api_key_id=api_key_id,
                provider=provider,
                model_called=(model or None) and model[:200],
                endpoint=endpoint[:100],
                fee_charged=reserved,
                status=TxStatus.PENDING,
                request_id=request_id,
            )
            session.add(tx)
            await session.execute(update(ApiKey).where(ApiKey.id == api_key_id).values(last_used_at=utcnow()))
            await session.flush()
            return Reservation(
                transaction_id=tx.id,
                user_id=user_id,
                price=price,
                reserved=reserved,
                balance_after=Decimal(balance_after),
            )

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
        async with self.db.session() as session, session.begin():
            values = dict(
                status=TxStatus.SUCCESS,
                fee_charged=fee,
                tokens_used=usage.total,
                input_tokens=usage.input_tokens,
                output_tokens=usage.output_tokens,
                upstream_status=upstream_status,
                latency_ms=latency_ms,
                completed_at=utcnow(),
            )
            if model:
                values["model_called"] = model[:200]
            settled = await session.execute(
                update(Transaction)
                .where(Transaction.id == reservation.transaction_id, Transaction.status == TxStatus.PENDING)
                .values(**values)
                .returning(Transaction.id)
            )
            if settled.scalar_one_or_none() is None:
                log.warning("transaction %s was already settled; not charging again", reservation.transaction_id)
                return Settlement(fee=Decimal("0"), balance=None, applied=False)
            delta = fee - reservation.reserved
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
        async with self.db.session() as session, session.begin():
            return await self._refund(
                session,
                transaction_id=reservation.transaction_id,
                user_id=reservation.user_id,
                amount=reservation.reserved,
                status=status,
                upstream_status=upstream_status,
                error=error,
                latency_ms=latency_ms,
            )

    async def _refund(self, session, *, transaction_id, user_id, amount, status, upstream_status, error, latency_ms) -> bool:
        settled = await session.execute(
            update(Transaction)
            .where(Transaction.id == transaction_id, Transaction.status == TxStatus.PENDING)
            .values(
                status=status,
                fee_charged=Decimal("0"),
                upstream_status=upstream_status,
                error=(error or None) and error[:2000],
                latency_ms=latency_ms,
                completed_at=utcnow(),
            )
            .returning(Transaction.id)
        )
        if settled.scalar_one_or_none() is None:
            return False
        if amount:
            await session.execute(update(User).where(User.id == user_id).values(balance=User.balance + amount))
        return True

    async def reconcile_stale(self, older_than: timedelta, now: datetime | None = None) -> int:
        """Refund and close transactions left pending (crash, dropped connection...)."""
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
            async with self.db.session() as session, session.begin():
                if await self._refund(
                    session,
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
