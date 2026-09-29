"""Compliance controls: limits by jurisdiction, identity checks, screening.

Opossum keeps routine payments private from recipients; it does not avoid
KYC, AML, sanctions, tax or court obligations. This module is where those
obligations are enforced, per jurisdiction and per payment method:

* blocked countries (sanctions programmes) for payers and recipients;
* per-payment and 24-hour limits for accounts whose identity is not
  verified, and a higher per-payment limit once verified;
* real-money payments need at least a self-attested identity in the vault;
* name screening against lists an operator loads (e.g. from a sanctions data
  provider). The built-in list is empty: load a real list before going live.

Limits and retention are rows in ``op_jurisdictions`` so an operator can
set them per country without a deploy.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from datetime import timedelta
from decimal import Decimal

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import Settings
from ..models import utcnow
from .models import OpJurisdiction, OpScreeningEntry, OpTransaction


class ComplianceBlock(Exception):
    def __init__(self, code: str, message: str, status: int = 403):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


@dataclass(frozen=True)
class Limits:
    country: str
    unverified_tx_limit: Decimal
    unverified_daily_limit: Decimal
    verified_tx_limit: Decimal
    retention_days: int
    blocked: bool

    def as_dict(self) -> dict:
        return {
            "country": self.country,
            "unverified_tx_limit": str(self.unverified_tx_limit),
            "unverified_daily_limit": str(self.unverified_daily_limit),
            "verified_tx_limit": str(self.verified_tx_limit),
            "retention_days": self.retention_days,
            "blocked": self.blocked,
        }


def blocked_countries(settings: Settings) -> set[str]:
    return {c.strip().upper() for c in settings.opossum_blocked_countries.split(",") if c.strip()}


async def limits_for(session: AsyncSession, settings: Settings, country: str) -> Limits:
    row = await session.get(OpJurisdiction, country)
    if row is not None:
        return Limits(country, row.unverified_tx_limit, row.unverified_daily_limit, row.verified_tx_limit,
                      row.retention_days, row.blocked or country in blocked_countries(settings))
    return Limits(
        country,
        settings.opossum_unverified_tx_limit,
        settings.opossum_unverified_daily_limit,
        settings.opossum_verified_tx_limit,
        settings.opossum_retention_days,
        country in blocked_countries(settings),
    )


def normalise_name(name: str) -> str:
    text = unicodedata.normalize("NFKD", name or "").encode("ascii", "ignore").decode().lower()
    return re.sub(r"[^a-z0-9]+", " ", text).strip()


async def screen_name(session: AsyncSession, name: str) -> str | None:
    """Return the list name on an exact normalised match, else None."""
    normal = normalise_name(name)
    if not normal:
        return None
    hit = await session.scalar(select(OpScreeningEntry.list_name).where(OpScreeningEntry.normalized_name == normal).limit(1))
    return hit


async def check_payment(
    session: AsyncSession,
    settings: Settings,
    *,
    account_country: str,
    kyc_status: str,
    owner_tag: str,
    recipient_country: str,
    amount_usd_equivalent: Decimal,
    real_money: bool,
) -> Limits:
    limits = await limits_for(session, settings, account_country)
    if limits.blocked:
        raise ComplianceBlock("jurisdiction_blocked", "payments are not available in your country")
    if recipient_country in blocked_countries(settings):
        raise ComplianceBlock("recipient_jurisdiction_blocked", "payments to this recipient's country are not available")
    if kyc_status in ("review", "rejected"):
        raise ComplianceBlock("account_under_review", "this account is under compliance review; payments are paused")
    if real_money and kyc_status == "none":
        raise ComplianceBlock("identity_required", "add your legal name and address (kept encrypted, never shown to recipients) before real payments")
    verified = kyc_status == "verified"
    per_payment = limits.verified_tx_limit if verified else limits.unverified_tx_limit
    if amount_usd_equivalent > per_payment:
        hint = "" if verified else " until your identity is verified"
        raise ComplianceBlock("over_limit", f"payments above {per_payment} are not available{hint}")
    if not verified:
        since = utcnow() - timedelta(hours=24)
        spent = await session.scalar(
            select(func.coalesce(func.sum(OpTransaction.total_cost), 0)).where(
                OpTransaction.owner_tag == owner_tag,
                OpTransaction.created_at >= since,
                OpTransaction.status.in_(("pending_payment", "settled")),
            )
        )
        if Decimal(spent or 0) + amount_usd_equivalent > limits.unverified_daily_limit:
            raise ComplianceBlock("over_daily_limit", f"this would pass the 24-hour limit of {limits.unverified_daily_limit} for unverified accounts")
    return limits
