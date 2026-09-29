"""Opossum tables.

What is deliberately *not* here: ledger entries, categories, notes, budgets
and receipts' private context. Those live on the user's device and, if the
user wants a backup, only as ciphertext the server cannot read (``op_backups``).

Identity (legal name, address, email...) is only ever stored encrypted, in
``op_identities``. Accounts are found by a keyed hash of the email, so the
accounts table holds no readable contact details.

Relay records (``op_transactions``) hold what is needed to move money,
settle disputes and meet legal duties, and nothing else. The link to the
paying account is kept two ways: a keyed "owner tag" so the owner can list
their own receipts, and an encrypted envelope that is only opened through a
recorded compliance case.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from ..models import MONEY, Base, utcnow


class OpAccount(Base):
    __tablename__ = "op_accounts"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    # HMAC of the lower-cased email: lets sign-in find the account without
    # storing a readable address.
    email_index: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    # Client-side key derivation parameters. The password itself never
    # reaches the server; the browser derives an auth key and a separate
    # ledger key from it.
    kdf_salt: Mapped[str] = mapped_column(String(64), nullable=False)
    kdf_iterations: Mapped[int] = mapped_column(Integer, nullable=False)
    auth_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    recovery_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    jurisdiction: Mapped[str] = mapped_column(String(2), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    mfa_secret_enc: Mapped[str | None] = mapped_column(Text)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    mfa_last_step: Mapped[int | None] = mapped_column(BigInteger)
    # none | self_attested | verified | rejected | review
    kyc_status: Mapped[str] = mapped_column(String(16), nullable=False, default="none")
    kyc_note: Mapped[str | None] = mapped_column(String(200))
    kyc_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # After closing, identity is kept only as long as the law requires.
    identity_retain_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class OpIdentity(Base):
    """Layer 1. One encrypted JSON document per account."""

    __tablename__ = "op_identities"

    account_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("op_accounts.id", ondelete="CASCADE"), primary_key=True)
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class OpDevice(Base):
    __tablename__ = "op_devices"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    account_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("op_accounts.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    # ECDSA P-256 public key (JWK). The private key is created in the browser
    # as non-extractable and never leaves the device.
    public_jwk: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    approved_via: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class OpSession(Base):
    __tablename__ = "op_sessions"

    id_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    account_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("op_accounts.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    user_agent: Mapped[str | None] = mapped_column(String(200))


class OpRecipient(Base):
    """A merchant or payee that can receive payments through the relay."""

    __tablename__ = "op_recipients"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    handle: Mapped[str] = mapped_column(String(40), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(100), nullable=False)
    category: Mapped[str] = mapped_column(String(40), nullable=False, default="general")
    country: Mapped[str] = mapped_column(String(2), nullable=False, default="US")
    # sandbox | stripe
    processor: Mapped[str] = mapped_column(String(16), nullable=False)
    processor_account: Mapped[str | None] = mapped_column(String(64))
    # active | review | disabled
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    api_key_hash: Mapped[str | None] = mapped_column(String(64), unique=True)
    api_key_prefix: Mapped[str | None] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class OpInvoice(Base):
    __tablename__ = "op_invoices"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    recipient_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("op_recipients.id"), nullable=False, index=True)
    reference: Mapped[str] = mapped_column(String(80), nullable=False)
    description: Mapped[str | None] = mapped_column(String(200))
    amount: Mapped[Decimal] = mapped_column(MONEY, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    paid_tx_id: Mapped[str | None] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class OpTransaction(Base):
    """Layer 2 (transaction identity) plus the minimum of layer 3."""

    __tablename__ = "op_transactions"
    __table_args__ = (Index("ix_op_tx_owner_created", "owner_tag", "created_at"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    owner_tag: Mapped[str] = mapped_column(String(64), nullable=False)
    # Encrypted {"account_id", "device_id"}; opened only for a compliance case.
    compliance_envelope: Mapped[str] = mapped_column(Text, nullable=False)
    recipient_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("op_recipients.id"), nullable=False, index=True)
    invoice_id: Mapped[str | None] = mapped_column(String(40))
    tx_type: Mapped[str] = mapped_column(String(24), nullable=False)
    mode: Mapped[str] = mapped_column(String(16), nullable=False)
    payer_pseudonym: Mapped[str] = mapped_column(String(40), nullable=False)
    # What the payer chose to show the recipient, encrypted at rest.
    disclosed_enc: Mapped[str | None] = mapped_column(Text)
    memo_commitment: Mapped[str | None] = mapped_column(String(64))
    amount: Mapped[Decimal] = mapped_column(MONEY, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    fee_bearer: Mapped[str] = mapped_column(String(10), nullable=False)
    opossum_fee: Mapped[Decimal] = mapped_column(MONEY, nullable=False)
    processor_fee: Mapped[Decimal] = mapped_column(MONEY, nullable=False)
    total_cost: Mapped[Decimal] = mapped_column(MONEY, nullable=False)
    recipient_receives: Mapped[Decimal] = mapped_column(MONEY, nullable=False)
    fee_rule: Mapped[str] = mapped_column(String(80), nullable=False)
    # pending_payment | settled | failed | cancelled | refunded
    status: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    processor: Mapped[str] = mapped_column(String(16), nullable=False)
    processor_ref: Mapped[str | None] = mapped_column(String(80), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    settled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retain_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    # The signed receipt (SD-JWT) and the holder's disclosures, encrypted.
    receipt_enc: Mapped[str | None] = mapped_column(Text)


class OpFeeRule(Base):
    __tablename__ = "op_fee_rules"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    recipient_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("op_recipients.id", ondelete="CASCADE"))
    tx_type: Mapped[str | None] = mapped_column(String(24))
    percent: Mapped[Decimal] = mapped_column(MONEY, nullable=False)
    flat: Mapped[Decimal] = mapped_column(MONEY, nullable=False, default=Decimal("0"))
    minimum: Mapped[Decimal | None] = mapped_column(MONEY)
    maximum: Mapped[Decimal | None] = mapped_column(MONEY)
    starts_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class OpJurisdiction(Base):
    """Per-country compliance settings. Countries without a row use the defaults in config."""

    __tablename__ = "op_jurisdictions"

    country: Mapped[str] = mapped_column(String(2), primary_key=True)
    unverified_tx_limit: Mapped[Decimal] = mapped_column(MONEY, nullable=False)
    unverified_daily_limit: Mapped[Decimal] = mapped_column(MONEY, nullable=False)
    verified_tx_limit: Mapped[Decimal] = mapped_column(MONEY, nullable=False)
    retention_days: Mapped[int] = mapped_column(Integer, nullable=False)
    blocked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    note: Mapped[str | None] = mapped_column(String(200))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class OpScreeningEntry(Base):
    """A name on a screening list (e.g. loaded from a sanctions provider)."""

    __tablename__ = "op_screening"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    normalized_name: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    list_name: Mapped[str] = mapped_column(String(80), nullable=False)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class OpBackup(Base):
    """User-controlled encrypted ledger backup. The server cannot decrypt it."""

    __tablename__ = "op_backups"

    account_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("op_accounts.id", ondelete="CASCADE"), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ciphertext: Mapped[str | None] = mapped_column(Text)
    # The ledger key, wrapped by keys derived from the password and from the
    # recovery code. Both derivations happen in the browser.
    wrapped_keys: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class OpAuditEntry(Base):
    """Hash-chained audit trail: each entry commits to the one before it."""

    __tablename__ = "op_audit"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    actor: Mapped[str] = mapped_column(String(80), nullable=False)
    action: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    subject: Mapped[str | None] = mapped_column(String(80))
    details: Mapped[str] = mapped_column(Text, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)


class OpAuditHead(Base):
    """Single row holding the chain head, locked while appending."""

    __tablename__ = "op_audit_head"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hash: Mapped[str] = mapped_column(String(64), nullable=False)
    count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)


class OpCase(Base):
    """A legal or compliance request that justifies opening protected data."""

    __tablename__ = "op_cases"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    legal_basis: Mapped[str] = mapped_column(String(40), nullable=False)
    reference: Mapped[str] = mapped_column(String(120), nullable=False)
    authority: Mapped[str] = mapped_column(String(120), nullable=False)
    scope: Mapped[str] = mapped_column(Text, nullable=False)
    # now | delayed | prohibited (e.g. a court order forbids telling the user)
    notify: Mapped[str] = mapped_column(String(12), nullable=False)
    notify_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(12), nullable=False, default="open")
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class OpDisclosure(Base):
    """One act of disclosure under a case: which transaction, which fields."""

    __tablename__ = "op_disclosures"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(String(40), ForeignKey("op_cases.id"), nullable=False, index=True)
    tx_id: Mapped[str | None] = mapped_column(String(40))
    owner_tag: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    fields: Mapped[str] = mapped_column(Text, nullable=False)
    disclosed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class OpNonce(Base):
    """Seen request nonces, so a signed request cannot be replayed."""

    __tablename__ = "op_nonces"

    nonce: Mapped[str] = mapped_column(String(64), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)


class OpIdempotency(Base):
    __tablename__ = "op_idempotency"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    tx_id: Mapped[str] = mapped_column(String(40), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
