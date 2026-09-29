"""Administrative compliance layer (``/admin/api/opossum``), behind the admin sign-in.

Routine views never show who paid: they list relay records by transaction ID
and pseudonym. Opening protected data (who is behind a payment, their
identity, their other payments) needs an open compliance case with a stated
legal basis, discloses only the fields asked for, and is written to the
hash-chained audit trail and to the user's disclosure log (unless the order
forbids telling them).
"""

from __future__ import annotations

import json
import re
import secrets
import uuid
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Literal

import httpx
from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import case, delete, func, select

from ..admin import require_admin
from ..countries import normalise_country
from ..models import utcnow
from ..services import Services
from . import audit
from .compliance import limits_for
from .sanctions import key_for, screen
from .crypto import random_id
from .merchant import hash_merchant_key
from .models import (
    OpAccount,
    OpAuditEntry,
    OpAuditHead,
    OpCase,
    OpDisclosure,
    OpFeeRule,
    OpIdentity,
    OpJurisdiction,
    OpRecipient,
    OpScreeningEntry,
    OpTransaction,
)
from .relay import HANDLE_RE, TX_TYPES, money, recipient_view
from .web import OpError, aware, base_url, keys

router = APIRouter(prefix="/admin/api/opossum", dependencies=[Depends(require_admin)])

LEGAL_BASES = ("court_order", "subpoena", "regulator_request", "law_enforcement_request", "tax_authority_request",
               "sanctions_screening", "fraud_investigation", "user_request")
CASE_FIELDS = ("account_id", "device_id", "email", "legal_name", "address", "date_of_birth", "phone",
               "identity_status", "account_payments")


def _actor(request: Request) -> str:
    row = getattr(request.state, "admin_session", None)
    return f"admin:{row.id_hash[:10]}" if row is not None else "admin:token"


# ---------------------------------------------------------------- overview and routine views


@router.get("/overview")
async def overview(services: Services = Depends(require_admin)):
    keys(services)
    since = utcnow() - timedelta(days=30)
    async with services.db.session() as session:
        accounts = dict((await session.execute(select(OpAccount.kyc_status, func.count()).where(OpAccount.status == "active")
                                               .group_by(OpAccount.kyc_status))).all())
        by_status = dict((await session.execute(select(OpTransaction.status, func.count()).group_by(OpTransaction.status))).all())
        volume = (await session.execute(
            select(OpTransaction.currency, func.count(), func.coalesce(func.sum(OpTransaction.amount), 0),
                   func.coalesce(func.sum(OpTransaction.opossum_fee), 0),
                   func.sum(case((OpTransaction.processor == "sandbox", 1), else_=0)))
            .where(OpTransaction.status == "settled", OpTransaction.created_at >= since).group_by(OpTransaction.currency)
        )).all()
        recipients = await session.scalar(select(func.count()).select_from(OpRecipient).where(OpRecipient.status == "active"))
        open_cases = await session.scalar(select(func.count()).select_from(OpCase).where(OpCase.status == "open"))
        head = await session.get(OpAuditHead, 1)
    return {
        "accounts_by_identity_status": accounts,
        "payments_by_status": by_status,
        "settled_30d": [{"currency": c, "payments": n, "volume": money(v), "opossum_fees": money(f), "sandbox_payments": int(s or 0)}
                        for c, n, v, f, s in volume],
        "active_recipients": recipients,
        "open_cases": open_cases,
        "audit_entries": head.count if head else 0,
        "fee_percent_default": str(services.settings.opossum_fee_percent),
    }


@router.get("/transactions")
async def transactions(services: Services = Depends(require_admin), limit: int = Query(default=100, ge=1, le=500),
                       status: str | None = Query(default=None, max_length=20)):
    """Relay records as a recipient would see them. No account, no identity."""
    k = keys(services)
    stmt = select(OpTransaction, OpRecipient.handle).join(OpRecipient, OpRecipient.id == OpTransaction.recipient_id) \
        .order_by(OpTransaction.created_at.desc()).limit(limit)
    if status:
        stmt = stmt.where(OpTransaction.status == status)
    async with services.db.session() as session:
        rows = (await session.execute(stmt)).all()
    out = []
    for tx, handle in rows:
        view = recipient_view(k, tx)
        view["payer"] = {"pseudonym": tx.payer_pseudonym}  # what the payer showed the recipient stays with the recipient
        out.append({**view, "recipient": handle, "mode": tx.mode, "processor": tx.processor, "fee_rule": tx.fee_rule})
    return out


# ---------------------------------------------------------------- recipients


class RecipientIn(BaseModel):
    handle: str
    display_name: str = Field(min_length=1, max_length=100)
    category: str = Field(default="general", max_length=40)
    country: str = "US"
    processor: Literal["sandbox", "stripe"] = "sandbox"
    # A Stripe connected account (acct_...), or "platform" when the recipient is
    # the operator's own business on the platform's Stripe account.
    processor_account: str | None = Field(default=None, max_length=64)

    @field_validator("processor_account")
    @classmethod
    def _account(cls, v):
        if v is not None and v != "platform" and not re.fullmatch(r"acct_[A-Za-z0-9]{6,60}", v):
            raise ValueError("processor_account must be acct_... or platform")
        return v

    @field_validator("handle")
    @classmethod
    def _handle(cls, v: str) -> str:
        if not HANDLE_RE.match(v):
            raise ValueError("handle: 3-40 lowercase letters, digits and dashes")
        return v

    @field_validator("country")
    @classmethod
    def _country(cls, v: str) -> str:
        return normalise_country(v) or "US"


class RecipientPatch(BaseModel):
    display_name: str | None = Field(default=None, max_length=100)
    category: str | None = Field(default=None, max_length=40)
    status: Literal["active", "review", "disabled", "onboarding"] | None = None
    processor_account: str | None = Field(default=None, max_length=64)


def _recipient_json(r: OpRecipient) -> dict:
    return {"id": str(r.id), "handle": r.handle, "display_name": r.display_name, "category": r.category, "country": r.country,
            "processor": r.processor, "processor_account": r.processor_account, "status": r.status,
            "merchant_key_prefix": r.api_key_prefix, "created_at": aware(r.created_at).isoformat(),
            "rails": [x for x in (r.chain_rails or "").split(",") if x], "fees_due": money(r.fees_due or 0)}


@router.get("/recipients")
async def list_recipients(services: Services = Depends(require_admin)):
    async with services.db.session() as session:
        rows = (await session.execute(select(OpRecipient).order_by(OpRecipient.created_at))).scalars().all()
    return [_recipient_json(r) for r in rows]


@router.post("/recipients", status_code=201)
async def create_recipient(body: RecipientIn, request: Request, services: Services = Depends(require_admin)):
    keys(services)
    if body.processor == "sandbox" and not services.settings.opossum_sandbox_enabled:
        raise OpError(400, "sandbox_off", "sandbox recipients are switched off")
    async with services.db.session() as session, session.begin():
        if await session.scalar(select(OpRecipient.id).where(OpRecipient.handle == body.handle)):
            raise OpError(409, "handle_taken", "that handle is taken")
        hit = await screen(session, body.display_name)
        r = OpRecipient(handle=body.handle, display_name=body.display_name, category=body.category, country=body.country,
                        processor=body.processor, processor_account=body.processor_account, status="review" if hit else "active")
        session.add(r)
        await session.flush()
        await audit.append(session, _actor(request), "recipient_created", r.handle, processor=r.processor, screening_hit=bool(hit))
    return _recipient_json(r)


@router.patch("/recipients/{recipient_id}")
async def update_recipient(recipient_id: uuid.UUID, body: RecipientPatch, request: Request, services: Services = Depends(require_admin)):
    async with services.db.session() as session, session.begin():
        r = await session.get(OpRecipient, recipient_id)
        if r is None:
            raise OpError(404, "unknown_recipient", "no such recipient")
        changes = body.model_dump(exclude_none=True)
        for key, value in changes.items():
            setattr(r, key, value)
        await audit.append(session, _actor(request), "recipient_updated", r.handle, fields=sorted(changes))
    return _recipient_json(r)


@router.post("/recipients/{recipient_id}/merchant-key")
async def merchant_key(recipient_id: uuid.UUID, request: Request, services: Services = Depends(require_admin)):
    """Issue (or replace) the recipient's API key. Shown once."""
    raw = "opm_" + secrets.token_urlsafe(32)
    async with services.db.session() as session, session.begin():
        r = await session.get(OpRecipient, recipient_id)
        if r is None:
            raise OpError(404, "unknown_recipient", "no such recipient")
        r.api_key_hash, r.api_key_prefix = hash_merchant_key(raw), raw[:12]
        await audit.append(session, _actor(request), "merchant_key_issued", r.handle)
    return {"merchant_key": raw, "note": "shown once; store it in the merchant's secret store"}


@router.post("/recipients/{recipient_id}/stripe-onboarding")
async def stripe_onboarding(recipient_id: uuid.UUID, request: Request, services: Services = Depends(require_admin)):
    """Create a Stripe Express connected account (Stripe verifies the business) and return its onboarding link."""
    settings = services.settings
    if not settings.stripe_secret_key:
        raise OpError(400, "stripe_off", "set STRIPE_SECRET_KEY first")
    auth = {"Authorization": f"Bearer {settings.stripe_secret_key.get_secret_value()}"}
    async with services.db.session() as session:
        r = await session.get(OpRecipient, recipient_id)
    if r is None:
        raise OpError(404, "unknown_recipient", "no such recipient")
    try:
        account = r.processor_account
        if not account:
            resp = await services.http.post(f"{settings.stripe_api_base}/accounts", headers=auth, data={
                "type": "express", "country": r.country, "business_profile[name]": r.display_name,
                "capabilities[card_payments][requested]": "true", "capabilities[transfers][requested]": "true",
                "metadata[opossum_handle]": r.handle,
            })
            if resp.status_code >= 400:
                raise OpError(502, "stripe_error", resp.json().get("error", {}).get("message", "Stripe refused"))
            account = resp.json()["id"]
        here = base_url(request)
        link = await services.http.post(f"{settings.stripe_api_base}/account_links", headers=auth, data={
            "account": account, "type": "account_onboarding",
            "refresh_url": f"{here}/admin#opossum", "return_url": f"{here}/admin#opossum",
        })
        if link.status_code >= 400:
            raise OpError(502, "stripe_error", link.json().get("error", {}).get("message", "Stripe refused"))
    except httpx.HTTPError:
        raise OpError(502, "stripe_unreachable", "Stripe could not be reached") from None
    async with services.db.session() as session, session.begin():
        row = await session.get(OpRecipient, recipient_id)
        row.processor, row.processor_account = "stripe", account
        if row.status == "active":
            row.status = "onboarding"  # takes payments once Stripe says charges and payouts are enabled
        await audit.append(session, _actor(request), "recipient_stripe_onboarding", row.handle)
    return {"account": account, "onboarding_url": link.json().get("url")}


@router.put("/recipients/{recipient_id}/chain")
async def recipient_chain(recipient_id: uuid.UUID, request: Request, services: Services = Depends(require_admin)):
    """Set up direct crypto payments to the recipient's own wallet (same rules as the merchant API)."""
    from .merchant import ChainSetup, apply_chain_setup

    body = ChainSetup(**(await request.json()))
    async with services.db.session() as session:
        if await session.get(OpRecipient, recipient_id) is None:
            raise OpError(404, "unknown_recipient", "no such recipient")
    return await apply_chain_setup(services, keys(services), recipient_id, body)


@router.post("/recipients/{recipient_id}/fees-paid")
async def fees_paid(recipient_id: uuid.UUID, body: dict, request: Request, services: Services = Depends(require_admin)):
    """Record that a recipient paid its billed on-chain fees."""
    try:
        amount = Decimal(str(body.get("amount")))
    except Exception:  # noqa: BLE001
        raise OpError(400, "invalid_amount", "amount must be a number") from None
    async with services.db.session() as session, session.begin():
        r = await session.get(OpRecipient, recipient_id)
        if r is None:
            raise OpError(404, "unknown_recipient", "no such recipient")
        if not amount.is_finite() or amount <= 0 or amount > (r.fees_due or 0):
            raise OpError(400, "invalid_amount", f"amount must be between 0 and {money(r.fees_due or 0)}")
        r.fees_due = (r.fees_due or Decimal("0")) - amount
        await audit.append(session, _actor(request), "fees_paid", r.handle, amount=str(amount))
    return {"fees_due": money(r.fees_due)}


@router.post("/recipients/{recipient_id}/check-onboarding")
async def check_onboarding(recipient_id: uuid.UUID, request: Request, services: Services = Depends(require_admin)):
    """Ask Stripe whether the connected account can take payments yet."""
    from .processors import PLATFORM_ACCOUNT, ProcessorError
    from .stripe_ops import account_ready

    async with services.db.session() as session:
        r = await session.get(OpRecipient, recipient_id)
    if r is None or r.processor != "stripe" or not r.processor_account or r.processor_account == PLATFORM_ACCOUNT:
        raise OpError(400, "not_connect", "this recipient is not a Stripe Connect account")
    try:
        ready, detail = await account_ready(services, r.processor_account)
    except ProcessorError as exc:
        raise OpError(502, "stripe_error", exc.message) from None
    async with services.db.session() as session, session.begin():
        row = await session.get(OpRecipient, recipient_id)
        if ready and row.status == "onboarding":
            row.status = "active"
            await audit.append(session, _actor(request), "recipient_ready", row.handle)
    return {"ready": ready, "detail": detail, "status": row.status}


@router.post("/transactions/{tx_id}/refund")
async def refund_transaction(tx_id: str, request: Request, body: dict | None = None, services: Services = Depends(require_admin)):
    """Refund a settled payment in full through its processor."""
    from .relay import refund_payment

    reason = str((body or {}).get("reason") or "refunded by operator")[:120]
    tx = await refund_payment(services, keys(services), tx_id, actor=_actor(request), reason=reason)
    return {"id": tx.id, "status": tx.status, "refund": tx.refund_ref}


@router.get("/sanctions")
async def sanctions_status(services: Services = Depends(require_admin)):
    from .models import OpListMeta

    async with services.db.session() as session:
        rows = (await session.execute(select(OpListMeta))).scalars().all()
    return {"auto_refresh": services.settings.opossum_ofac_enabled, "refresh_hours": services.settings.opossum_ofac_refresh_hours,
            "lists": [{"list": m.list_name, "source": m.source, "entries": m.entries,
                       "loaded_at": aware(m.loaded_at).isoformat() if m.loaded_at else None,
                       "checked_at": aware(m.checked_at).isoformat() if m.checked_at else None, "last_error": m.last_error} for m in rows]}


@router.post("/sanctions/refresh")
async def sanctions_refresh(request: Request, services: Services = Depends(require_admin)):
    """Download the OFAC SDN list now and re-screen everyone."""
    from .sanctions import refresh_ofac

    result = await refresh_ofac(services)
    if not result["ok"]:
        raise OpError(502, "list_unavailable", "could not load the OFAC list: " + result["error"][:200])
    return result


# ---------------------------------------------------------------- fees


class FeeRuleIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    percent: Decimal = Field(ge=0, le=50)
    flat: Decimal = Field(default=Decimal("0"), ge=0, le=1000)
    minimum: Decimal | None = Field(default=None, ge=0, le=1000)
    maximum: Decimal | None = Field(default=None, ge=0, le=100000)
    recipient_handle: str | None = None
    tx_type: str | None = None
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    priority: int = Field(default=0, ge=-100, le=100)

    @field_validator("tx_type")
    @classmethod
    def _type(cls, v):
        if v is not None and v not in TX_TYPES:
            raise ValueError(f"tx_type must be one of {', '.join(TX_TYPES)}")
        return v


def _rule_json(r: OpFeeRule, handles: dict) -> dict:
    return {"id": str(r.id), "name": r.name, "percent": str(r.percent), "flat": str(r.flat),
            "minimum": str(r.minimum) if r.minimum is not None else None, "maximum": str(r.maximum) if r.maximum is not None else None,
            "recipient": handles.get(r.recipient_id), "tx_type": r.tx_type, "priority": r.priority, "active": r.active,
            "starts_at": aware(r.starts_at).isoformat() if r.starts_at else None, "ends_at": aware(r.ends_at).isoformat() if r.ends_at else None}


@router.get("/fee-rules")
async def fee_rules(services: Services = Depends(require_admin)):
    async with services.db.session() as session:
        rows = (await session.execute(select(OpFeeRule).where(OpFeeRule.active.is_(True)).order_by(OpFeeRule.created_at))).scalars().all()
        handles = dict((await session.execute(select(OpRecipient.id, OpRecipient.handle))).all())
    return {"default": {"percent": str(services.settings.opossum_fee_percent)}, "rules": [_rule_json(r, handles) for r in rows]}


@router.post("/fee-rules", status_code=201)
async def add_fee_rule(body: FeeRuleIn, request: Request, services: Services = Depends(require_admin)):
    if body.minimum is not None and body.maximum is not None and body.minimum > body.maximum:
        raise OpError(400, "invalid_rule", "minimum is above maximum")
    if body.starts_at and body.ends_at and body.starts_at >= body.ends_at:
        raise OpError(400, "invalid_rule", "the promotion ends before it starts")
    async with services.db.session() as session, session.begin():
        recipient_id = None
        if body.recipient_handle:
            recipient_id = await session.scalar(select(OpRecipient.id).where(OpRecipient.handle == body.recipient_handle))
            if recipient_id is None:
                raise OpError(404, "unknown_recipient", "no recipient with that handle")
        rule = OpFeeRule(name=body.name, percent=body.percent, flat=body.flat, minimum=body.minimum, maximum=body.maximum,
                         recipient_id=recipient_id, tx_type=body.tx_type, starts_at=body.starts_at, ends_at=body.ends_at,
                         priority=body.priority)
        session.add(rule)
        await session.flush()
        await audit.append(session, _actor(request), "fee_rule_added", str(rule.id), percent=str(rule.percent), name=rule.name)
        handles = {recipient_id: body.recipient_handle} if recipient_id else {}
    return _rule_json(rule, handles)


@router.delete("/fee-rules/{rule_id}")
async def remove_fee_rule(rule_id: uuid.UUID, request: Request, services: Services = Depends(require_admin)):
    async with services.db.session() as session, session.begin():
        rule = await session.get(OpFeeRule, rule_id)
        if rule is None:
            raise OpError(404, "unknown_rule", "no such rule")
        rule.active = False
        await audit.append(session, _actor(request), "fee_rule_removed", str(rule.id))
    return {"removed": str(rule_id)}


# ---------------------------------------------------------------- jurisdictions and screening


class JurisdictionIn(BaseModel):
    unverified_tx_limit: Decimal = Field(ge=0)
    unverified_daily_limit: Decimal = Field(ge=0)
    verified_tx_limit: Decimal = Field(ge=0)
    retention_days: int = Field(ge=30, le=36500)
    blocked: bool = False
    note: str | None = Field(default=None, max_length=200)


@router.get("/jurisdictions")
async def jurisdictions(services: Services = Depends(require_admin)):
    s = services.settings
    async with services.db.session() as session:
        rows = (await session.execute(select(OpJurisdiction).order_by(OpJurisdiction.country))).scalars().all()
    return {
        "defaults": {"unverified_tx_limit": str(s.opossum_unverified_tx_limit), "unverified_daily_limit": str(s.opossum_unverified_daily_limit),
                     "verified_tx_limit": str(s.opossum_verified_tx_limit), "retention_days": s.opossum_retention_days,
                     "blocked_countries": s.opossum_blocked_countries},
        "countries": [{"country": r.country, "unverified_tx_limit": str(r.unverified_tx_limit),
                       "unverified_daily_limit": str(r.unverified_daily_limit), "verified_tx_limit": str(r.verified_tx_limit),
                       "retention_days": r.retention_days, "blocked": r.blocked, "note": r.note} for r in rows],
    }


@router.put("/jurisdictions/{country}")
async def set_jurisdiction(country: str, body: JurisdictionIn, request: Request, services: Services = Depends(require_admin)):
    try:
        code = normalise_country(country)
    except ValueError as exc:
        raise OpError(400, "invalid_country", str(exc)) from None
    async with services.db.session() as session, session.begin():
        row = await session.get(OpJurisdiction, code)
        if row is None:
            row = OpJurisdiction(country=code, **body.model_dump())
            session.add(row)
        else:
            for key, value in body.model_dump().items():
                setattr(row, key, value)
            row.updated_at = utcnow()
        await audit.append(session, _actor(request), "jurisdiction_set", code, **{k: str(v) for k, v in body.model_dump().items()})
    return (await jurisdictions(services))


@router.delete("/jurisdictions/{country}")
async def reset_jurisdiction(country: str, request: Request, services: Services = Depends(require_admin)):
    async with services.db.session() as session, session.begin():
        await session.execute(delete(OpJurisdiction).where(OpJurisdiction.country == country.upper()[:2]))
        await audit.append(session, _actor(request), "jurisdiction_reset", country.upper()[:2])
    return {"reset": country.upper()[:2]}


class ScreeningIn(BaseModel):
    names: list[str] = Field(min_length=1, max_length=5000)
    list_name: str = Field(min_length=1, max_length=80)


@router.get("/screening")
async def screening(services: Services = Depends(require_admin)):
    async with services.db.session() as session:
        rows = (await session.execute(select(OpScreeningEntry.list_name, func.count()).group_by(OpScreeningEntry.list_name))).all()
    return {"lists": [{"list": name, "entries": n} for name, n in rows],
            "note": "load names from a sanctions data provider; the built-in list is empty"}


@router.post("/screening", status_code=201)
async def add_screening(body: ScreeningIn, request: Request, services: Services = Depends(require_admin)):
    names = {key_for(n) for n in body.names if " " in key_for(n)}
    async with services.db.session() as session, session.begin():
        for name in names:
            session.add(OpScreeningEntry(normalized_name=name[:200], list_name=body.list_name))
        await audit.append(session, _actor(request), "screening_list_loaded", body.list_name, entries=len(names))
    return {"added": len(names), "list": body.list_name}


@router.delete("/screening/{list_name}")
async def remove_screening(list_name: str, request: Request, services: Services = Depends(require_admin)):
    async with services.db.session() as session, session.begin():
        await session.execute(delete(OpScreeningEntry).where(OpScreeningEntry.list_name == list_name))
        await audit.append(session, _actor(request), "screening_list_removed", list_name[:80])
    return {"removed": list_name}


# ---------------------------------------------------------------- identity checks (KYC)


@router.get("/kyc")
async def kyc_queue(services: Services = Depends(require_admin)):
    """Accounts waiting on an identity decision. Shows no identity data."""
    async with services.db.session() as session:
        rows = (await session.execute(select(OpAccount).where(OpAccount.status == "active", OpAccount.kyc_status.in_(("self_attested", "review")))
                                      .order_by(OpAccount.kyc_updated_at))).scalars().all()
    return [{"account_id": str(a.id), "jurisdiction": a.jurisdiction, "kyc_status": a.kyc_status, "note": a.kyc_note,
             "since": aware(a.kyc_updated_at).isoformat() if a.kyc_updated_at else None} for a in rows]


class KycDecision(BaseModel):
    status: Literal["verified", "rejected", "review", "self_attested"]
    note: str = Field(min_length=3, max_length=200)


@router.get("/kyc/{account_id}")
async def kyc_open(account_id: uuid.UUID, request: Request, services: Services = Depends(require_admin)):
    """Open one account's identity for an identity check. Recorded in the audit trail."""
    k = keys(services)
    async with services.db.session() as session, session.begin():
        account = await session.get(OpAccount, account_id)
        row = await session.get(OpIdentity, account_id)
        if account is None or row is None:
            raise OpError(404, "unknown_account", "no identity on file")
        await audit.append(session, _actor(request), "identity_opened_for_kyc", str(account_id))
    return {"account_id": str(account_id), "identity": k.open(row.ciphertext, f"op_identities:{account_id}:doc"),
            "kyc_status": account.kyc_status}


@router.post("/kyc/{account_id}")
async def kyc_decide(account_id: uuid.UUID, body: KycDecision, request: Request, services: Services = Depends(require_admin)):
    async with services.db.session() as session, session.begin():
        account = await session.get(OpAccount, account_id)
        if account is None:
            raise OpError(404, "unknown_account", "no such account")
        account.kyc_status, account.kyc_note, account.kyc_updated_at = body.status, body.note, utcnow()
        await audit.append(session, _actor(request), "kyc_decision", str(account_id), status=body.status)
    return {"account_id": str(account_id), "kyc_status": body.status}


# ---------------------------------------------------------------- compliance cases


class CaseIn(BaseModel):
    legal_basis: Literal[LEGAL_BASES]  # type: ignore[valid-type]
    reference: str = Field(min_length=3, max_length=120)
    authority: str = Field(min_length=2, max_length=120)
    scope: str = Field(min_length=10, max_length=4000)
    notify: Literal["now", "delayed", "prohibited"] = "now"
    notify_after: datetime | None = None


class DiscloseIn(BaseModel):
    transaction_id: str = Field(min_length=4, max_length=40)
    fields: list[Literal[CASE_FIELDS]] = Field(min_length=1)  # type: ignore[valid-type]
    since: datetime | None = None
    until: datetime | None = None


def _case_json(c: OpCase) -> dict:
    return {"id": c.id, "legal_basis": c.legal_basis, "reference": c.reference, "authority": c.authority, "scope": c.scope,
            "notify": c.notify, "notify_after": aware(c.notify_after).isoformat() if c.notify_after else None, "status": c.status,
            "opened_at": aware(c.opened_at).isoformat(), "closed_at": aware(c.closed_at).isoformat() if c.closed_at else None}


@router.get("/cases")
async def cases(services: Services = Depends(require_admin)):
    async with services.db.session() as session:
        rows = (await session.execute(select(OpCase).order_by(OpCase.opened_at.desc()).limit(200))).scalars().all()
        counts = dict((await session.execute(select(OpDisclosure.case_id, func.count()).group_by(OpDisclosure.case_id))).all())
    return [{**_case_json(c), "disclosures": counts.get(c.id, 0)} for c in rows]


@router.post("/cases", status_code=201)
async def open_case(body: CaseIn, request: Request, services: Services = Depends(require_admin)):
    if body.notify == "delayed" and body.notify_after is None:
        raise OpError(400, "invalid_case", "a delayed notice needs notify_after")
    c = OpCase(id=random_id("case_", 9), legal_basis=body.legal_basis, reference=body.reference, authority=body.authority,
               scope=body.scope, notify=body.notify, notify_after=body.notify_after, status="open")
    async with services.db.session() as session, session.begin():
        session.add(c)
        await audit.append(session, _actor(request), "case_opened", c.id, legal_basis=c.legal_basis, notify=c.notify)
    return _case_json(c)


@router.post("/cases/{case_id}/close")
async def close_case(case_id: str, request: Request, services: Services = Depends(require_admin)):
    async with services.db.session() as session, session.begin():
        c = await session.get(OpCase, case_id[:40])
        if c is None:
            raise OpError(404, "unknown_case", "no such case")
        c.status, c.closed_at = "closed", utcnow()
        await audit.append(session, _actor(request), "case_closed", c.id)
    return _case_json(c)


@router.post("/cases/{case_id}/disclose")
async def disclose(case_id: str, body: DiscloseIn, request: Request, services: Services = Depends(require_admin)):
    """Disclose the listed fields about the payer of one transaction, and nothing else."""
    k = keys(services)
    async with services.db.session() as session, session.begin():
        c = await session.get(OpCase, case_id[:40])
        if c is None or c.status != "open":
            raise OpError(409, "case_not_open", "disclosure needs an open case")
        tx = await session.get(OpTransaction, body.transaction_id)
        if tx is None:
            raise OpError(404, "unknown_payment", "no such transaction (it may be past its retention period)")
        envelope = k.open(tx.compliance_envelope, f"op_transactions:{tx.id}:envelope")
        account_id = uuid.UUID(envelope["account_id"])
        account = await session.get(OpAccount, account_id)
        identity = {}
        identity_row = await session.get(OpIdentity, account_id)
        if identity_row is not None:
            identity = k.open(identity_row.ciphertext, f"op_identities:{account_id}:doc")
        out: dict = {"transaction": recipient_view(k, tx)}
        out["transaction"]["payer"] = {"pseudonym": tx.payer_pseudonym}
        for field in body.fields:
            if field == "account_id":
                out["account_id"] = str(account_id)
            elif field == "device_id":
                out["device_id"] = envelope.get("device_id")
            elif field == "identity_status":
                out["identity_status"] = account.kyc_status if account else None
            elif field == "address":
                out["address"] = {key: identity.get(key) for key in ("address_line1", "address_line2", "city", "postal_code", "country")}
            elif field == "account_payments":
                since = body.since or (utcnow() - timedelta(days=365))
                until = body.until or utcnow()
                rows = (await session.execute(select(OpTransaction).where(
                    OpTransaction.owner_tag == tx.owner_tag, OpTransaction.created_at >= since, OpTransaction.created_at <= until,
                ).order_by(OpTransaction.created_at))).scalars().all()
                out["account_payments"] = {"since": since.isoformat(), "until": until.isoformat(),
                                           "payments": [{"id": r.id, "amount": money(r.amount), "currency": r.currency, "status": r.status,
                                                         "created_at": aware(r.created_at).isoformat()} for r in rows]}
            else:
                out[field] = identity.get(field)
        session.add(OpDisclosure(case_id=c.id, tx_id=tx.id, owner_tag=tx.owner_tag, fields=json.dumps(sorted(body.fields))))
        await audit.append(session, _actor(request), "case_disclosure", c.id, transaction=tx.id, fields=sorted(body.fields))
    return {"case": c.id, "disclosed": out}


# ---------------------------------------------------------------- audit trail


@router.get("/audit")
async def audit_entries(services: Services = Depends(require_admin), limit: int = Query(default=100, ge=1, le=1000),
                        action: str | None = Query(default=None, max_length=60)):
    stmt = select(OpAuditEntry).order_by(OpAuditEntry.id.desc()).limit(limit)
    if action:
        stmt = stmt.where(OpAuditEntry.action == action)
    async with services.db.session() as session:
        rows = (await session.execute(stmt)).scalars().all()
    return [{"id": e.id, "at": aware(e.at).isoformat(), "actor": e.actor, "action": e.action, "subject": e.subject,
             "details": json.loads(e.details), "hash": e.hash} for e in rows]


@router.get("/audit/verify")
async def audit_verify(services: Services = Depends(require_admin)):
    async with services.db.session() as session:
        return await audit.verify_chain(session)


@router.get("/limits/{country}")
async def limits(country: str, services: Services = Depends(require_admin)):
    async with services.db.session() as session:
        return (await limits_for(session, services.settings, country.upper()[:2])).as_dict()
