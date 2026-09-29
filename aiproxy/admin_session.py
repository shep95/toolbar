"""Dashboard sign-in: server-side sessions behind an HttpOnly cookie.

The admin token is typed once and exchanged for a random session ID. The ID
lives only in a ``__Host-`` cookie that is Secure, HttpOnly and
SameSite=Strict, so the page's JavaScript (and anything pasted into the
browser console) never sees a credential. Only a SHA-256 of the ID is stored,
so a database dump cannot be replayed as a session.

Sessions end after ``ADMIN_SESSION_IDLE_MINUTES`` of inactivity, at the
latest ``ADMIN_SESSION_MAX_HOURS`` after sign-in, when the browser's
User-Agent changes, or when an operator ends them all from the dashboard.

Requests that change anything with a session cookie must come from the
dashboard's own origin and carry ``X-Admin-Request: 1``; a cross-site page
can send neither.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import orjson
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import delete, func, or_, select

from .audit import record_rejection
from .models import AdminSession, utcnow
from .security import constant_time_equals
from .services import Services, get_services

log = logging.getLogger("aiproxy.admin")

COOKIE = "__Host-admin_session"
CSRF_HEADER = "x-admin-request"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# last_seen_at is written at most this often per session.
TOUCH_SECONDS = 60
MAX_LOGIN_BYTES = 4096


def _hash(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


def _aware(value: datetime) -> datetime:
    # SQLite returns naive datetimes; everything is stored in UTC.
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _agent(request: Request) -> str:
    return (request.headers.get("user-agent") or "")[:200]


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------- where the admin area answers


def allowed_hosts(services: Services) -> set[str]:
    raw = services.settings.admin_allowed_hosts or services.settings.env_value("RAILWAY_PUBLIC_DOMAIN") or ""
    return {h.strip().lower().rstrip(".") for h in raw.split(",") if h.strip()}


def _request_host(request: Request) -> str:
    host = (request.headers.get("host") or "").strip().lower()
    if host.startswith("["):  # IPv6 literal
        return host.split("]")[0] + "]"
    return host.rsplit(":", 1)[0].rstrip(".")


def check_host(request: Request, services: Services) -> None:
    """404 unless the request names the admin hostname.

    Stops the dashboard answering on the raw IP, on a stray domain someone
    points at the service, or through DNS rebinding.
    """
    hosts = allowed_hosts(services)
    if hosts and _request_host(request) not in hosts:
        log.warning("admin access on unexpected host", extra={"event": "admin_host_denied", "client_ip": client_ip(request)})
        raise HTTPException(404, "not found")


def check_same_origin(request: Request, header: str = CSRF_HEADER) -> None:
    """403 unless a state-changing cookie request comes from the page itself."""
    if request.headers.get(header) != "1":
        raise HTTPException(403, "missing dashboard request header")
    site = request.headers.get("sec-fetch-site")
    if site is not None and site != "same-origin":
        raise HTTPException(403, "cross-site request refused")
    origin = request.headers.get("origin")
    if origin is None:
        # Browsers send Origin on every non-GET fetch; without it only a
        # same-origin Sec-Fetch-Site can vouch for the request.
        if site != "same-origin":
            raise HTTPException(403, "cross-site request refused")
        return
    parts = urlsplit(origin)
    if parts.scheme not in ("https", "http") or parts.netloc.lower() != (request.headers.get("host") or "").lower():
        raise HTTPException(403, "cross-site request refused")


# ---------------------------------------------------------------- session store


def _limits(services: Services) -> tuple[timedelta, timedelta]:
    s = services.settings
    return timedelta(minutes=max(1, s.admin_session_idle_minutes)), timedelta(hours=max(1, s.admin_session_max_hours))


async def create_session(services: Services, request: Request) -> tuple[str, AdminSession]:
    idle, lifetime = _limits(services)
    now = utcnow()
    session_id = secrets.token_urlsafe(32)
    row = AdminSession(
        id_hash=_hash(session_id),
        created_at=now,
        last_seen_at=now,
        expires_at=now + lifetime,
        ip=client_ip(request)[:64],
        user_agent=_agent(request),
    )
    async with services.db.session() as session, session.begin():
        await session.execute(
            delete(AdminSession).where(or_(AdminSession.expires_at < now, AdminSession.last_seen_at < now - idle))
        )
        count = await session.scalar(select(func.count()).select_from(AdminSession))
        excess = (count or 0) - max(1, services.settings.admin_max_sessions) + 1
        if excess > 0:
            # Too many open sessions: the least recently used ones are signed out.
            oldest = select(AdminSession.id_hash).order_by(AdminSession.last_seen_at).limit(excess)
            await session.execute(delete(AdminSession).where(AdminSession.id_hash.in_(oldest.scalar_subquery())))
        session.add(row)
    return session_id, row


async def load_session(services: Services, request: Request) -> AdminSession | None:
    session_id = request.cookies.get(COOKIE)
    if not session_id or len(session_id) > 128:
        return None
    idle, _ = _limits(services)
    now = utcnow()
    key = _hash(session_id)
    async with services.db.session() as session, session.begin():
        row = await session.get(AdminSession, key)
        if row is None:
            return None
        if (
            now >= _aware(row.expires_at)
            or now - _aware(row.last_seen_at) >= idle
            or not constant_time_equals(row.user_agent or "", _agent(request))
        ):
            await session.delete(row)
            return None
        if (now - _aware(row.last_seen_at)).total_seconds() >= TOUCH_SECONDS:
            row.last_seen_at = now
    return row


async def end_session(services: Services, request: Request) -> None:
    session_id = request.cookies.get(COOKIE)
    if session_id and len(session_id) <= 128:
        async with services.db.session() as session, session.begin():
            await session.execute(delete(AdminSession).where(AdminSession.id_hash == _hash(session_id)))


async def end_all_sessions(services: Services) -> int:
    async with services.db.session() as session, session.begin():
        result = await session.execute(delete(AdminSession))
    return result.rowcount or 0


async def purge_expired(services: Services) -> int:
    idle, _ = _limits(services)
    now = utcnow()
    async with services.db.session() as session, session.begin():
        result = await session.execute(
            delete(AdminSession).where(or_(AdminSession.expires_at < now, AdminSession.last_seen_at < now - idle))
        )
    return result.rowcount or 0


async def list_sessions(services: Services, current: AdminSession | None) -> list[dict]:
    idle, _ = _limits(services)
    async with services.db.session() as session:
        rows = (await session.execute(select(AdminSession).order_by(AdminSession.last_seen_at.desc()))).scalars().all()
    return [
        {
            "created_at": _aware(r.created_at).isoformat(),
            "last_seen_at": _aware(r.last_seen_at).isoformat(),
            "expires_at": min(_aware(r.expires_at), _aware(r.last_seen_at) + idle).isoformat(),
            "ip": r.ip,
            "user_agent": r.user_agent,
            "current": current is not None and r.id_hash == current.id_hash,
        }
        for r in rows
    ]


def set_cookie(response: Response, session_id: str) -> None:
    # No Max-Age: the cookie also dies with the browser. The server enforces
    # the real lifetime.
    response.set_cookie(COOKIE, session_id, path="/", secure=True, httponly=True, samesite="strict")


def clear_cookie(response: Response) -> None:
    response.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="strict")


# ---------------------------------------------------------------- sign-in endpoints

router = APIRouter()


def _gate(request: Request) -> Services:
    """Checks every dashboard route shares: address allowlist, hostname, enabled."""
    from .admin import _check_admin_ip  # late import: admin imports this module

    services = get_services(request)
    _check_admin_ip(request, services)
    check_host(request, services)
    if not services.settings.admin_enabled:
        raise HTTPException(503, "admin API disabled: set ADMIN_API_TOKEN (at least 32 characters)")
    return services


def _status(services: Services, row: AdminSession | None) -> dict:
    idle, _ = _limits(services)
    if row is None:
        return {"signed_in": False}
    return {
        "signed_in": True,
        "idle_minutes": int(idle.total_seconds() // 60),
        "expires_at": _aware(row.expires_at).isoformat(),
    }


@router.get("/admin/session", include_in_schema=False)
async def session_status(request: Request) -> Response:
    services = _gate(request)
    row = await load_session(services, request)
    response = JSONResponse(_status(services, row))
    if row is None and COOKIE in request.cookies:
        clear_cookie(response)
    return response


@router.post("/admin/session", include_in_schema=False)
async def sign_in(request: Request) -> Response:
    services = _gate(request)
    settings = services.settings
    ip = client_ip(request)
    check_same_origin(request)
    limited, retry_after = services.admin_failure_limiter.is_limited(ip, settings.admin_auth_failures_per_minute_per_ip)
    if limited:
        raise HTTPException(429, "too many failed sign-ins, wait a minute", headers={"Retry-After": str(retry_after)})
    if not (request.headers.get("content-type") or "").startswith("application/json"):
        raise HTTPException(415, "expected JSON")
    body = await request.body()
    if len(body) > MAX_LOGIN_BYTES:
        raise HTTPException(413, "request too large")
    try:
        token = orjson.loads(body).get("token")
    except (ValueError, AttributeError):
        token = None
    if not isinstance(token, str) or not constant_time_equals(token.strip(), settings.admin_api_token.get_secret_value()):
        services.admin_failure_limiter.check(ip, 1_000_000)
        await record_rejection(
            services.db, status_code=401, outcome="admin_signin_failed", request_id=secrets.token_hex(8),
            method="POST", path="/admin/session", client_ip=ip,
        )
        raise HTTPException(401, "that token is not right")
    session_id, row = await create_session(services, request)
    log.info("admin signed in", extra={"event": "admin_signin", "client_ip": ip})
    response = JSONResponse(_status(services, row))
    set_cookie(response, session_id)
    return response


@router.delete("/admin/session", include_in_schema=False)
async def sign_out(request: Request) -> Response:
    services = _gate(request)
    check_same_origin(request)
    await end_session(services, request)
    response = JSONResponse({"signed_in": False})
    clear_cookie(response)
    return response

