"""Request plumbing shared by the Opossum routers: keys, errors, sessions."""

from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import delete, or_

from ..admin_session import check_same_origin
from ..models import utcnow
from ..services import Services, get_services
from .crypto import KeysMissing, RelayKeys
from .models import OpAccount, OpSession

log = logging.getLogger("aiproxy.opossum")

COOKIE = "__Host-opossum_session"
CSRF_HEADER = "x-opossum-request"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
TOUCH_SECONDS = 60


class OpError(Exception):
    """An error with a stable machine-readable code and a plain-language message."""

    def __init__(self, status: int, code: str, message: str, **extra):
        super().__init__(message)
        self.status, self.code, self.message, self.extra = status, code, message, extra


async def op_error_handler(request: Request, exc: OpError) -> JSONResponse:
    return JSONResponse(status_code=exc.status, content={"error": {"code": exc.code, "message": exc.message, **exc.extra}})


def aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def keys(services: Services) -> RelayKeys:
    if services.opossum_keys is None:
        master = services.settings.opossum_master_key
        if master is None:
            raise OpError(503, "opossum_not_configured", "Opossum is not switched on yet: the operator must set OPOSSUM_MASTER_KEY")
        try:
            services.opossum_keys = RelayKeys.from_master(master.get_secret_value())
        except KeysMissing as exc:
            raise OpError(503, "opossum_not_configured", str(exc)) from None
    return services.opossum_keys  # type: ignore[return-value]


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def base_url(request: Request) -> str:
    proto = (request.headers.get("x-forwarded-proto") or request.url.scheme).split(",")[0].strip()
    return f"{'https' if proto == 'https' else request.url.scheme}://{request.headers.get('host', request.url.netloc)}"


def same_origin(request: Request) -> None:
    try:
        check_same_origin(request, CSRF_HEADER)
    except Exception:
        raise OpError(403, "cross_site", "this request must come from the Opossum app on this site") from None


# ---------------------------------------------------------------- sessions


def _hash(session_id: str) -> str:
    return hashlib.sha256(session_id.encode()).hexdigest()


def _limits(services: Services) -> tuple[timedelta, timedelta]:
    s = services.settings
    return timedelta(minutes=max(1, s.opossum_session_idle_minutes)), timedelta(hours=max(1, s.opossum_session_max_hours))


async def open_session(services: Services, request: Request, response: Response, account: OpAccount) -> None:
    idle, lifetime = _limits(services)
    now = utcnow()
    session_id = secrets.token_urlsafe(32)
    async with services.db.session() as session, session.begin():
        await session.execute(delete(OpSession).where(
            OpSession.account_id == account.id, or_(OpSession.expires_at < now, OpSession.last_seen_at < now - idle)
        ))
        session.add(OpSession(
            id_hash=_hash(session_id), account_id=account.id, created_at=now, last_seen_at=now,
            expires_at=now + lifetime, user_agent=(request.headers.get("user-agent") or "")[:200],
        ))
    response.set_cookie(COOKIE, session_id, path="/", secure=True, httponly=True, samesite="strict")


async def close_session(services: Services, request: Request, response: Response) -> None:
    session_id = request.cookies.get(COOKIE)
    if session_id and len(session_id) <= 128:
        async with services.db.session() as session, session.begin():
            await session.execute(delete(OpSession).where(OpSession.id_hash == _hash(session_id)))
    response.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="strict")


async def end_all_sessions(session, account_id) -> None:
    await session.execute(delete(OpSession).where(OpSession.account_id == account_id))


async def current_account(request: Request) -> tuple[Services, OpAccount]:
    """Dependency: the signed-in account. Unsafe methods must also be same-origin."""
    services = get_services(request)
    keys(services)
    session_id = request.cookies.get(COOKIE)
    if not session_id or len(session_id) > 128:
        raise OpError(401, "signed_out", "sign in to continue")
    idle, _ = _limits(services)
    now = utcnow()
    async with services.db.session() as session, session.begin():
        row = await session.get(OpSession, _hash(session_id))
        if row is None:
            raise OpError(401, "signed_out", "sign in to continue")
        agent = (request.headers.get("user-agent") or "")[:200]
        if now >= aware(row.expires_at) or now - aware(row.last_seen_at) >= idle or row.user_agent != agent:
            await session.delete(row)
            raise OpError(401, "session_ended", "your session ended; sign in again")
        if (now - aware(row.last_seen_at)).total_seconds() >= TOUCH_SECONDS:
            row.last_seen_at = now
        account = await session.get(OpAccount, row.account_id)
        if account is None or account.status != "active":
            await session.delete(row)
            raise OpError(401, "account_closed", "this account is not active")
        session.expunge(account)
    if request.method not in SAFE_METHODS:
        same_origin(request)
    request.state.op_account = account
    return services, account


async def purge(services: Services) -> None:
    """Expired sessions, nonces and idempotency keys."""
    from .models import OpIdempotency, OpNonce

    idle, _ = _limits(services)
    now = utcnow()
    async with services.db.session() as session, session.begin():
        await session.execute(delete(OpSession).where(or_(OpSession.expires_at < now, OpSession.last_seen_at < now - idle)))
        await session.execute(delete(OpNonce).where(OpNonce.expires_at < now))
        await session.execute(delete(OpIdempotency).where(OpIdempotency.expires_at < now))
