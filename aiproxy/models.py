"""Database schema.

Core tables from the spec: ``users``, ``api_keys``, ``transactions``.
Supporting tables: ``pricing`` (admin-set fees), ``balance_adjustments``
(every credit/top-up, idempotent on external payment IDs) and ``audit_log``
(every rejected request, so nothing fails silently).

Money is stored as NUMERIC(18, 6) US dollars, never floats.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

MONEY = Numeric(18, 6)

PROVIDER_ANY = "any"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class UserStatus:
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ALL = (ACTIVE, SUSPENDED)


class KeyStatus:
    ACTIVE = "active"
    REVOKED = "revoked"
    ALL = (ACTIVE, REVOKED)


class TxStatus:
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"  # upstream rejected or was unreachable; never charged
    ERROR = "error"  # abandoned / internal error; never charged
    ALL = (PENDING, SUCCESS, FAILED, ERROR)


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    balance: Mapped[Decimal] = mapped_column(MONEY, default=Decimal("0"), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default=UserStatus.ACTIVE, nullable=False)
    # ISO 3166-1 alpha-2 country used for country-adjusted fees. Set by an
    # admin, never by the user, so nobody can claim a cheaper country.
    # NULL means unknown: the full base fee applies.
    country: Mapped[str | None] = mapped_column(String(2))

    api_keys: Mapped[list[ApiKey]] = relationship(back_populates="user", lazy="raise")

    __table_args__ = (CheckConstraint("status in ('active', 'suspended')", name="ck_users_status"),)


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    # SHA-256 hex digest of the raw key. The raw key is shown once and never stored.
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    # First characters of the key, safe to display so users can tell keys apart.
    key_prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    name: Mapped[str | None] = mapped_column(String(100))
    # Which upstream this key may reach: openai / anthropic / mistral / any.
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    # Optional lock to one transaction domain (see domains.py). NULL = any
    # domain. A key locked to a non-AI domain cannot use the AI gateway.
    domain: Mapped[str | None] = mapped_column(String(32))
    # Per-key override of the global requests-per-minute limit.
    rate_limit_per_minute: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(16), default=KeyStatus.ACTIVE, nullable=False)

    user: Mapped[User] = relationship(back_populates="api_keys", lazy="raise")

    __table_args__ = (CheckConstraint("status in ('active', 'revoked')", name="ck_api_keys_status"),)


class Transaction(Base):
    __tablename__ = "transactions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    api_key_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("api_keys.id", ondelete="CASCADE"), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    model_called: Mapped[str | None] = mapped_column(String(200))
    endpoint: Mapped[str | None] = mapped_column(String(100))
    tokens_used: Mapped[int | None] = mapped_column(Integer)
    input_tokens: Mapped[int | None] = mapped_column(Integer)
    output_tokens: Mapped[int | None] = mapped_column(Integer)
    # While pending this holds the amount reserved from the balance.
    # On success it is the final fee. On failed/error it is always 0.
    fee_charged: Mapped[Decimal] = mapped_column(MONEY, default=Decimal("0"), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(16), default=TxStatus.PENDING, nullable=False)
    upstream_status: Mapped[int | None] = mapped_column(Integer)
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)
    request_id: Mapped[str | None] = mapped_column(String(64))
    # Country whose economy the fee was adjusted for, and the multiplier used.
    fee_country: Mapped[str | None] = mapped_column(String(2))
    fee_multiplier: Mapped[Decimal | None] = mapped_column(Numeric(8, 4))

    __table_args__ = (
        CheckConstraint(
            "status in ('pending', 'success', 'failed', 'error')", name="ck_transactions_status"
        ),
        Index("ix_transactions_user_ts", "user_id", "timestamp"),
        Index("ix_transactions_status_ts", "status", "timestamp"),
        Index("ix_transactions_ts", "timestamp"),
    )


class Pricing(Base):
    """Admin-managed fees. Lookup order: (provider, model) → (provider, '*') → ('*', '*') → env default."""

    __tablename__ = "pricing"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str] = mapped_column(String(200), nullable=False, default="*")
    fee_per_request: Mapped[Decimal] = mapped_column(MONEY, nullable=False)
    # Token-based component. 0 means pure flat fee.
    fee_per_1k_tokens: Mapped[Decimal] = mapped_column(MONEY, nullable=False, default=Decimal("0"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (UniqueConstraint("provider", "model", name="uq_pricing_provider_model"),)


class BalanceAdjustment(Base):
    """Ledger of every balance credit that did not come from a proxied request."""

    __tablename__ = "balance_adjustments"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    amount: Mapped[Decimal] = mapped_column(MONEY, nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False)  # admin / stripe
    # e.g. the Stripe checkout session ID. Unique so a replayed webhook never double-credits.
    external_id: Mapped[str | None] = mapped_column(String(255), unique=True)
    note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class AuditLog(Base):
    """One row per rejected request (401/402/403/429/400/503...)."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    request_id: Mapped[str | None] = mapped_column(String(64))
    user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    api_key_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    key_prefix: Mapped[str | None] = mapped_column(String(16))
    client_ip: Mapped[str | None] = mapped_column(String(64))
    method: Mapped[str | None] = mapped_column(String(10))
    path: Mapped[str | None] = mapped_column(String(300))
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    outcome: Mapped[str] = mapped_column(String(64), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)


class Charge(Base):
    """A fee charged for any kind of transaction recorded through /v1/transactions.

    The proxy does not move the transaction's money; it records that the
    transaction happened and charges the per-transaction fee to the account's
    prepaid balance. ``reference`` is the caller's own ID for the transaction
    and makes recording idempotent: the same reference is never charged twice.
    """

    __tablename__ = "charges"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    api_key_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("api_keys.id", ondelete="CASCADE"), nullable=False)
    reference: Mapped[str] = mapped_column(String(200), nullable=False)
    # Domain of business (general, ai, brokerage, crypto, payments...). NULL on
    # rows recorded before domains existed, which count as general.
    domain: Mapped[str | None] = mapped_column(String(32))
    type: Mapped[str] = mapped_column(String(64), nullable=False)
    # The transaction's own value, for the caller's records (not moved by us).
    amount: Mapped[Decimal | None] = mapped_column(Numeric(20, 6))
    currency: Mapped[str | None] = mapped_column(String(3))
    country: Mapped[str | None] = mapped_column(String(2))
    description: Mapped[str | None] = mapped_column(String(500))
    metadata_json: Mapped[str | None] = mapped_column(Text)
    # Domain-specific fields, validated per domain (symbol, asset, network...).
    attributes_json: Mapped[str | None] = mapped_column(Text)
    fee_charged: Mapped[Decimal] = mapped_column(MONEY, nullable=False)
    fee_country: Mapped[str | None] = mapped_column(String(2))
    fee_multiplier: Mapped[Decimal] = mapped_column(Numeric(8, 4), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(64))

    __table_args__ = (
        UniqueConstraint("user_id", "reference", name="uq_charges_user_reference"),
        Index("ix_charges_ts", "timestamp"),
        Index("ix_charges_user_ts", "user_id", "timestamp"),
    )


class CountryPricing(Base):
    """Admin override of the fee multiplier for one country."""

    __tablename__ = "country_pricing"

    country: Mapped[str] = mapped_column(String(2), primary_key=True)
    multiplier: Mapped[Decimal] = mapped_column(Numeric(8, 4), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class AdminSession(Base):
    """A signed-in dashboard session. Only a hash of the session ID is stored."""

    __tablename__ = "admin_sessions"

    id_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(200))
