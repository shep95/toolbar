"""Admin layer: accounts, keys, pricing, usage and audit views.

Authenticated with ``ADMIN_API_TOKEN`` (``Authorization: Bearer <token>``),
completely separate from user API keys: a user key can never reach these
routes and the admin token can never be used to proxy traffic.
Upstream provider credentials live in environment variables only, so the admin
layer can report which providers are configured but cannot read or change them.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import logging
import re
import uuid
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import case, func, select, update
from sqlalchemy.exc import IntegrityError

from .countries import (
    DEFAULT_MULTIPLIERS,
    INCOME_GROUP,
    MAX_MULTIPLIER,
    MIN_MULTIPLIER,
    default_multiplier,
    income_group,
    normalise_country,
    plain,
)
from .models import (
    PROVIDER_ANY,
    ApiKey,
    Charge,
    CountryPricing,
    AuditLog,
    BalanceAdjustment,
    KeyStatus,
    Pricing,
    Transaction,
    TxStatus,
    User,
    utcnow,
)
from .security import constant_time_equals, display_prefix, generate_api_key, hash_api_key
from .services import Services, get_services
from .transactions_api import charge_json

log = logging.getLogger("aiproxy.admin")

MAX_AMOUNT = Decimal("1000000")


def _ip_allowed(ip: str, allowlist: str) -> bool:
    if not allowlist.strip():
        return True
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in allowlist.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            if address in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            log.error("invalid ADMIN_ALLOWED_IPS entry %r", entry)
    return False


def _check_admin_ip(request: Request, services: Services) -> str:
    ip = request.client.host if request.client else "unknown"
    if not _ip_allowed(ip, services.settings.admin_allowed_ips):
        log.warning("admin access from disallowed address", extra={"event": "admin_ip_denied", "client_ip": ip})
        raise HTTPException(404, "not found")  # do not reveal that an admin area exists
    return ip


def require_admin(request: Request) -> Services:
    services = get_services(request)
    settings = services.settings
    ip = _check_admin_ip(request, services)
    if not settings.admin_enabled:
        raise HTTPException(503, "admin API disabled: set ADMIN_API_TOKEN (at least 32 characters)")
    limited, retry_after = services.admin_failure_limiter.is_limited(ip, settings.admin_auth_failures_per_minute_per_ip)
    if limited:
        raise HTTPException(429, "too many failed admin logins", headers={"Retry-After": str(retry_after)})
    auth = request.headers.get("authorization", "")
    scheme, _, token = auth.partition(" ")
    if scheme.lower() != "bearer" or not constant_time_equals(
        token.strip(), settings.admin_api_token.get_secret_value()
    ):
        services.admin_failure_limiter.check(ip, 1_000_000)
        log.warning("admin auth failed", extra={"event": "admin_auth_failed", "client_ip": ip})
        raise HTTPException(401, "invalid admin token", headers={"WWW-Authenticate": "Bearer"})
    return services


api = APIRouter(prefix="/admin/api", dependencies=[Depends(require_admin)])
pages = APIRouter()


def _money(value) -> str:
    return f"{Decimal(value or 0):.6f}"


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


# ---------------------------------------------------------------- schemas


def _country_field(value):
    try:
        return normalise_country(value)
    except ValueError as exc:
        raise ValueError(str(exc)) from None


class UserCreate(BaseModel):
    email: EmailStr
    initial_balance: Decimal = Field(default=Decimal("0"), ge=0, le=MAX_AMOUNT)
    # ISO country for country-adjusted fees; omit for the full base fee.
    country: str | None = None

    _check_country = field_validator("country")(classmethod(lambda cls, v: _country_field(v)))


class UserUpdate(BaseModel):
    status: Literal["active", "suspended"] | None = None
    # Send null to clear (full base fee).
    country: str | None = None

    _check_country = field_validator("country")(classmethod(lambda cls, v: _country_field(v)))


class CountryPricingUpsert(BaseModel):
    multiplier: Decimal = Field(ge=MIN_MULTIPLIER, le=MAX_MULTIPLIER)


class CreditRequest(BaseModel):
    amount: Decimal = Field(ge=-MAX_AMOUNT, le=MAX_AMOUNT)
    note: str | None = Field(default=None, max_length=500)

    @field_validator("amount")
    @classmethod
    def _non_zero(cls, value: Decimal) -> Decimal:
        if value == 0:
            raise ValueError("amount must not be zero")
        return value


class KeyCreate(BaseModel):
    provider: str
    name: str | None = Field(default=None, max_length=100)
    rate_limit_per_minute: int | None = Field(default=None, ge=1, le=100_000)


class PricingUpsert(BaseModel):
    provider: str
    model: str = Field(default="*", min_length=1, max_length=200)
    fee_per_request: Decimal = Field(ge=0, le=Decimal("1000"))
    fee_per_1k_tokens: Decimal = Field(default=Decimal("0"), ge=0, le=Decimal("1000"))


def _valid_provider(services: Services, provider: str, allow_any: bool) -> str:
    allowed = set(services.connectors) | ({PROVIDER_ANY} if allow_any else set())
    if provider not in allowed:
        raise HTTPException(422, f"provider must be one of: {', '.join(sorted(allowed))}")
    return provider


def _user_json(user: User) -> dict:
    return {
        "id": str(user.id),
        "email": user.email,
        "balance": _money(user.balance),
        "status": user.status,
        "country": user.country,
        "created_at": _iso(user.created_at),
    }


def _key_json(key: ApiKey) -> dict:
    return {
        "id": str(key.id),
        "user_id": str(key.user_id),
        "prefix": key.key_prefix,
        "name": key.name,
        "provider": key.provider,
        "rate_limit_per_minute": key.rate_limit_per_minute,
        "status": key.status,
        "created_at": _iso(key.created_at),
        "last_used_at": _iso(key.last_used_at),
    }


def _tx_json(tx: Transaction) -> dict:
    return {
        "id": str(tx.id),
        "user_id": str(tx.user_id),
        "api_key_id": str(tx.api_key_id),
        "provider": tx.provider,
        "model_called": tx.model_called,
        "endpoint": tx.endpoint,
        "tokens_used": tx.tokens_used,
        "input_tokens": tx.input_tokens,
        "output_tokens": tx.output_tokens,
        "fee_charged": _money(tx.fee_charged),
        "timestamp": _iso(tx.timestamp),
        "completed_at": _iso(tx.completed_at),
        "status": tx.status,
        "upstream_status": tx.upstream_status,
        "latency_ms": tx.latency_ms,
        "error": tx.error,
        "request_id": tx.request_id,
    }


async def _get_user(session, user_id: uuid.UUID) -> User:
    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(404, "user not found")
    return user


# ---------------------------------------------------------------- overview


@api.get("/overview")
async def overview(services: Services = Depends(require_admin)):
    now = utcnow()
    async with services.db.session() as session:
        users = (await session.execute(select(func.count(User.id)))).scalar_one()
        active_keys = (
            await session.execute(select(func.count(ApiKey.id)).where(ApiKey.status == KeyStatus.ACTIVE))
        ).scalar_one()
        windows = {}
        for label, delta in (("last_24h", timedelta(days=1)), ("last_30d", timedelta(days=30))):
            row = (
                await session.execute(
                    select(
                        func.count(Transaction.id),
                        func.coalesce(func.sum(case((Transaction.status == TxStatus.SUCCESS, 1), else_=0)), 0),
                        func.coalesce(
                            func.sum(case((Transaction.status == TxStatus.SUCCESS, Transaction.fee_charged), else_=0)), 0
                        ),
                        func.coalesce(func.sum(Transaction.tokens_used), 0),
                    ).where(Transaction.timestamp >= now - delta)
                )
            ).one()
            windows[label] = {
                "requests": row[0],
                "successful": int(row[1]),
                "revenue": _money(row[2]),
                "tokens": int(row[3]),
            }
            charges = (
                await session.execute(
                    select(func.count(Charge.id), func.coalesce(func.sum(Charge.fee_charged), 0)).where(
                        Charge.timestamp >= now - delta
                    )
                )
            ).one()
            windows[label]["transactions"] = charges[0]
            windows[label]["transaction_revenue"] = _money(charges[1])
            windows[label]["total_revenue"] = _money(Decimal(row[2] or 0) + Decimal(charges[1] or 0))
        pending = (
            await session.execute(select(func.count(Transaction.id)).where(Transaction.status == TxStatus.PENDING))
        ).scalar_one()
    return {
        "users": users,
        "active_keys": active_keys,
        "pending_transactions": pending,
        **windows,
        "providers": {name: {"configured": c.configured, "country": c.country} for name, c in services.connectors.items()},
        "default_fee_per_request": _money(services.settings.default_fee_per_request),
        "stripe_enabled": services.settings.stripe_enabled,
    }


@api.get("/providers")
async def providers(services: Services = Depends(require_admin)):
    return [c.describe() for c in services.connectors.values()]


# ---------------------------------------------------------------- countries


@api.get("/countries")
async def country_pricing(services: Services = Depends(require_admin)):
    """Default multipliers per income group, every classified country, and admin overrides."""
    base = await services.billing.price_for("transactions", None)
    async with services.db.session() as session:
        overrides = (await session.execute(select(CountryPricing).order_by(CountryPricing.country))).scalars().all()
    return {
        "base_fee_usd": _money(base.fee_for(None)),
        "groups": {
            group: {"multiplier": str(m), "fee_usd": _money(base.scaled(m).fee_for(None))}
            for group, m in DEFAULT_MULTIPLIERS.items()
        },
        "countries": {code: group for code, group in sorted(INCOME_GROUP.items())},
        "unlisted_countries": "high",
        "overrides": [
            {
                "country": o.country,
                "multiplier": plain(o.multiplier),
                "fee_usd": _money(base.scaled(Decimal(o.multiplier)).fee_for(None)),
                "default_group": income_group(o.country),
                "updated_at": _iso(o.updated_at),
            }
            for o in overrides
        ],
    }


@api.put("/countries/{country}")
async def set_country_pricing(country: str, payload: CountryPricingUpsert, services: Services = Depends(require_admin)):
    try:
        code = normalise_country(country)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    async with services.db.session() as session, session.begin():
        row = await session.get(CountryPricing, code)
        if row is None:
            row = CountryPricing(country=code, multiplier=payload.multiplier)
            session.add(row)
        row.multiplier = payload.multiplier
        row.updated_at = utcnow()
    services.billing.invalidate_pricing()
    log.info("country pricing set", extra={"event": "admin_country_pricing", "country": code, "multiplier": str(payload.multiplier)})
    return {"country": code, "multiplier": str(payload.multiplier)}


@api.delete("/countries/{country}")
async def delete_country_pricing(country: str, services: Services = Depends(require_admin)):
    try:
        code = normalise_country(country)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    async with services.db.session() as session, session.begin():
        row = await session.get(CountryPricing, code)
        if row is None:
            raise HTTPException(404, "no override for that country")
        await session.delete(row)
    services.billing.invalidate_pricing()
    return {"country": code, "multiplier": str(default_multiplier(code)), "reset_to_default": True}


@api.get("/charges")
async def list_charges(
    services: Services = Depends(require_admin),
    user_id: uuid.UUID | None = None,
    type: str | None = Query(default=None, max_length=64),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    """General transactions recorded through /v1/transactions."""
    stmt = select(Charge).order_by(Charge.timestamp.desc()).limit(limit).offset(offset)
    if user_id:
        stmt = stmt.where(Charge.user_id == user_id)
    if type:
        stmt = stmt.where(Charge.type == type)
    async with services.db.session() as session:
        rows = (await session.execute(stmt)).scalars().all()
    return [{**charge_json(c), "user_id": str(c.user_id), "api_key_id": str(c.api_key_id)} for c in rows]


# ---------------------------------------------------------------- users


@api.post("/users", status_code=201)
async def create_user(payload: UserCreate, services: Services = Depends(require_admin)):
    try:
        async with services.db.session() as session, session.begin():
            user = User(email=payload.email.lower(), balance=payload.initial_balance, country=payload.country)
            session.add(user)
            await session.flush()
            if payload.initial_balance:
                session.add(
                    BalanceAdjustment(user_id=user.id, amount=payload.initial_balance, source="admin", note="initial balance")
                )
    except IntegrityError:
        raise HTTPException(409, "a user with that email already exists") from None
    return _user_json(user)


@api.get("/users")
async def list_users(
    services: Services = Depends(require_admin),
    q: str | None = Query(default=None, max_length=320),
    status: Literal["active", "suspended"] | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    stmt = select(User).order_by(User.created_at.desc()).limit(limit).offset(offset)
    if q:
        stmt = stmt.where(User.email.ilike(f"%{q.lower()}%"))
    if status:
        stmt = stmt.where(User.status == status)
    async with services.db.session() as session:
        users = (await session.execute(stmt)).scalars().all()
    return [_user_json(u) for u in users]


@api.get("/users/{user_id}")
async def get_user(user_id: uuid.UUID, services: Services = Depends(require_admin)):
    async with services.db.session() as session:
        user = await _get_user(session, user_id)
        keys = (
            await session.execute(select(ApiKey).where(ApiKey.user_id == user_id).order_by(ApiKey.created_at.desc()))
        ).scalars().all()
        adjustments = (
            await session.execute(
                select(BalanceAdjustment)
                .where(BalanceAdjustment.user_id == user_id)
                .order_by(BalanceAdjustment.created_at.desc())
                .limit(50)
            )
        ).scalars().all()
    return {
        **_user_json(user),
        "keys": [_key_json(k) for k in keys],
        "balance_adjustments": [
            {
                "id": str(a.id),
                "amount": _money(a.amount),
                "source": a.source,
                "external_id": a.external_id,
                "note": a.note,
                "created_at": _iso(a.created_at),
            }
            for a in adjustments
        ],
    }


@api.patch("/users/{user_id}")
async def update_user(user_id: uuid.UUID, payload: UserUpdate, services: Services = Depends(require_admin)):
    async with services.db.session() as session, session.begin():
        user = await _get_user(session, user_id)
        if "status" in payload.model_fields_set:
            if payload.status is None:
                raise HTTPException(422, "status must be active or suspended")
            user.status = payload.status
        if "country" in payload.model_fields_set:
            user.country = payload.country
    services.auth_cache.clear()
    log.info(
        "user updated",
        extra={"event": "admin_user_update", "user_id": str(user_id), "fields": sorted(payload.model_fields_set)},
    )
    return _user_json(user)


@api.post("/users/{user_id}/credits")
async def credit_user(user_id: uuid.UUID, payload: CreditRequest, services: Services = Depends(require_admin)):
    async with services.db.session() as session, session.begin():
        await _get_user(session, user_id)
        balance = (
            await session.execute(
                update(User).where(User.id == user_id).values(balance=User.balance + payload.amount).returning(User.balance)
            )
        ).scalar_one()
        session.add(BalanceAdjustment(user_id=user_id, amount=payload.amount, source="admin", note=payload.note))
    log.info("balance adjusted", extra={"event": "admin_credit", "user_id": str(user_id), "amount": str(payload.amount)})
    return {"user_id": str(user_id), "balance": _money(balance)}


# ---------------------------------------------------------------- keys


@api.post("/users/{user_id}/keys", status_code=201)
async def issue_key(user_id: uuid.UUID, payload: KeyCreate, services: Services = Depends(require_admin)):
    provider = _valid_provider(services, payload.provider, allow_any=True)
    raw_key = generate_api_key()
    async with services.db.session() as session, session.begin():
        await _get_user(session, user_id)
        key = ApiKey(
            user_id=user_id,
            key_hash=hash_api_key(raw_key),
            key_prefix=display_prefix(raw_key),
            name=payload.name,
            provider=provider,
            rate_limit_per_minute=payload.rate_limit_per_minute,
        )
        session.add(key)
        await session.flush()
    log.info("key issued", extra={"event": "admin_key_issued", "user_id": str(user_id), "api_key_id": str(key.id)})
    # The only time the raw key ever leaves the server.
    return {**_key_json(key), "api_key": raw_key, "warning": "store this key now; it cannot be shown again"}


@api.get("/users/{user_id}/keys")
async def list_keys(user_id: uuid.UUID, services: Services = Depends(require_admin)):
    async with services.db.session() as session:
        keys = (
            await session.execute(select(ApiKey).where(ApiKey.user_id == user_id).order_by(ApiKey.created_at.desc()))
        ).scalars().all()
    return [_key_json(k) for k in keys]


@api.delete("/keys/{key_id}")
async def revoke_key(key_id: uuid.UUID, services: Services = Depends(require_admin)):
    async with services.db.session() as session, session.begin():
        key = await session.get(ApiKey, key_id)
        if key is None:
            raise HTTPException(404, "key not found")
        key.status = KeyStatus.REVOKED
    services.auth_cache.clear()
    log.info("key revoked", extra={"event": "admin_key_revoked", "api_key_id": str(key_id)})
    return _key_json(key)


# ---------------------------------------------------------------- pricing


@api.get("/pricing")
async def list_pricing(services: Services = Depends(require_admin)):
    async with services.db.session() as session:
        rows = (await session.execute(select(Pricing).order_by(Pricing.provider, Pricing.model))).scalars().all()
    return {
        "default_fee_per_request": _money(services.settings.default_fee_per_request),
        "rules": [
            {
                "id": r.id,
                "provider": r.provider,
                "model": r.model,
                "fee_per_request": _money(r.fee_per_request),
                "fee_per_1k_tokens": _money(r.fee_per_1k_tokens),
                "updated_at": _iso(r.updated_at),
            }
            for r in rows
        ],
    }


@api.put("/pricing")
async def upsert_pricing(payload: PricingUpsert, services: Services = Depends(require_admin)):
    provider = payload.provider
    # "transactions" prices general transactions; its model is the transaction type.
    if provider not in ("*", "transactions"):
        _valid_provider(services, provider, allow_any=False)
    async with services.db.session() as session, session.begin():
        row = (
            await session.execute(select(Pricing).where(Pricing.provider == provider, Pricing.model == payload.model))
        ).scalar_one_or_none()
        if row is None:
            row = Pricing(provider=provider, model=payload.model)
            session.add(row)
        row.fee_per_request = payload.fee_per_request
        row.fee_per_1k_tokens = payload.fee_per_1k_tokens
        row.updated_at = utcnow()
        await session.flush()
    services.billing.invalidate_pricing()
    log.info("pricing updated", extra={"event": "admin_pricing", "provider": provider, "model": payload.model})
    return {
        "id": row.id,
        "provider": row.provider,
        "model": row.model,
        "fee_per_request": _money(row.fee_per_request),
        "fee_per_1k_tokens": _money(row.fee_per_1k_tokens),
    }


@api.delete("/pricing/{pricing_id}")
async def delete_pricing(pricing_id: int, services: Services = Depends(require_admin)):
    async with services.db.session() as session, session.begin():
        row = await session.get(Pricing, pricing_id)
        if row is None:
            raise HTTPException(404, "pricing rule not found")
        await session.delete(row)
    services.billing.invalidate_pricing()
    return {"deleted": pricing_id}


# ---------------------------------------------------------------- usage


@api.get("/transactions")
async def list_transactions(
    services: Services = Depends(require_admin),
    user_id: uuid.UUID | None = None,
    api_key_id: uuid.UUID | None = None,
    provider: str | None = None,
    status: Literal["pending", "success", "failed", "error"] | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    stmt = select(Transaction).order_by(Transaction.timestamp.desc()).limit(limit).offset(offset)
    if user_id:
        stmt = stmt.where(Transaction.user_id == user_id)
    if api_key_id:
        stmt = stmt.where(Transaction.api_key_id == api_key_id)
    if provider:
        stmt = stmt.where(Transaction.provider == provider)
    if status:
        stmt = stmt.where(Transaction.status == status)
    async with services.db.session() as session:
        rows = (await session.execute(stmt)).scalars().all()
    return [_tx_json(t) for t in rows]


@api.get("/usage")
async def usage(
    services: Services = Depends(require_admin),
    days: int = Query(default=30, ge=1, le=366),
    user_id: uuid.UUID | None = None,
):
    """Daily totals per provider, plus top users, for the dashboard."""
    since = utcnow() - timedelta(days=days)
    day = func.date(Transaction.timestamp)
    success = Transaction.status == TxStatus.SUCCESS
    filters = [Transaction.timestamp >= since]
    if user_id:
        filters.append(Transaction.user_id == user_id)
    async with services.db.session() as session:
        daily = (
            await session.execute(
                select(
                    day.label("day"),
                    Transaction.provider,
                    func.count(Transaction.id),
                    func.coalesce(func.sum(case((success, 1), else_=0)), 0),
                    func.coalesce(func.sum(case((success, Transaction.fee_charged), else_=0)), 0),
                    func.coalesce(func.sum(Transaction.tokens_used), 0),
                )
                .where(*filters)
                .group_by(day, Transaction.provider)
                .order_by(day)
            )
        ).all()
        top_users = (
            await session.execute(
                select(
                    User.id,
                    User.email,
                    func.count(Transaction.id),
                    func.coalesce(func.sum(case((success, Transaction.fee_charged), else_=0)), 0),
                )
                .join(User, User.id == Transaction.user_id)
                .where(*filters)
                .group_by(User.id, User.email)
                .order_by(func.coalesce(func.sum(case((success, Transaction.fee_charged), else_=0)), 0).desc())
                .limit(20)
            )
        ).all()
        charge_day = func.date(Charge.timestamp)
        charge_filters = [Charge.timestamp >= since] + ([Charge.user_id == user_id] if user_id else [])
        charge_daily = (
            await session.execute(
                select(charge_day, func.count(Charge.id), func.coalesce(func.sum(Charge.fee_charged), 0))
                .where(*charge_filters)
                .group_by(charge_day)
                .order_by(charge_day)
            )
        ).all()
    rows = [
        {
            "day": str(r[0]),
            "provider": r[1],
            "requests": r[2],
            "successful": int(r[3]),
            "revenue": _money(r[4]),
            "tokens": int(r[5]),
        }
        for r in daily
    ] + [
        # General transactions appear as their own line.
        {"day": str(r[0]), "provider": "transactions", "requests": r[1], "successful": r[1], "revenue": _money(r[2]), "tokens": 0}
        for r in charge_daily
    ]
    rows.sort(key=lambda r: (r["day"], r["provider"]))
    return {
        "days": days,
        "daily": rows,
        "top_users": [
            {"user_id": str(r[0]), "email": r[1], "requests": r[2], "revenue": _money(r[3])} for r in top_users
        ],
    }


@api.get("/audit")
async def audit_log(
    services: Services = Depends(require_admin),
    limit: int = Query(default=100, ge=1, le=1000),
    outcome: str | None = Query(default=None, max_length=64),
    user_id: uuid.UUID | None = None,
):
    stmt = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)
    if outcome:
        stmt = stmt.where(AuditLog.outcome == outcome)
    if user_id:
        stmt = stmt.where(AuditLog.user_id == user_id)
    async with services.db.session() as session:
        rows = (await session.execute(stmt)).scalars().all()
    return [
        {
            "id": r.id,
            "timestamp": _iso(r.timestamp),
            "request_id": r.request_id,
            "user_id": str(r.user_id) if r.user_id else None,
            "api_key_id": str(r.api_key_id) if r.api_key_id else None,
            "key_prefix": r.key_prefix,
            "client_ip": r.client_ip,
            "method": r.method,
            "path": r.path,
            "status_code": r.status_code,
            "outcome": r.outcome,
            "detail": r.detail,
        }
        for r in rows
    ]


@api.post("/maintenance/reconcile")
async def reconcile(services: Services = Depends(require_admin)):
    count = await services.billing.reconcile_stale(timedelta(minutes=services.settings.pending_timeout_minutes))
    return {"reconciled": count}


# ---------------------------------------------------------------- dashboard page

_DASHBOARD_HTML = (Path(__file__).parent / "static" / "admin.html").read_text(encoding="utf-8")
_SCRIPTS = re.findall(r"<script>(.*?)</script>", _DASHBOARD_HTML, flags=re.S)
# Only the page's own inline script may run (pinned by hash), so injected
# markup can never execute script even if it got into the page.
_SCRIPT_HASHES = " ".join(
    "'sha256-" + base64.b64encode(hashlib.sha256(code.encode("utf-8")).digest()).decode() + "'" for code in _SCRIPTS
)
_DASHBOARD_CSP = (
    f"default-src 'none'; script-src {_SCRIPT_HASHES}; style-src 'unsafe-inline'; connect-src 'self'; "
    "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)


@pages.get("/admin", response_class=HTMLResponse, include_in_schema=False)
async def dashboard(request: Request) -> HTMLResponse:
    # The page itself holds no data; it calls /admin/api with the token the
    # operator types in, so it is safe to serve without auth.
    _check_admin_ip(request, get_services(request))
    return HTMLResponse(
        _DASHBOARD_HTML,
        headers={"Content-Security-Policy": _DASHBOARD_CSP, "Cache-Control": "no-store"},
    )
