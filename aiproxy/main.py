"""Application factory.

Run with::

    uvicorn aiproxy.main:app --host 0.0.0.0 --port 8000 --proxy-headers
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import logging
import socket
import ssl
from contextlib import asynccontextmanager
from datetime import timedelta

import httpx
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import admin, admin_session, gateway, payments, transactions_api
from .opossum import admin_api as opossum_admin, api as opossum_api, maintenance as opossum_maintenance
from .opossum import merchant as opossum_merchant, pages as opossum_pages
from .opossum.web import OpError, op_error_handler
from .billing import BillingEngine
from .config import Settings, get_settings
from .connectors import build_connectors
from .db import DB_UNAVAILABLE_ERRORS, Database
from .logging_setup import configure_logging
from .keycache import AuthCache
from .services import Services

log = logging.getLogger("aiproxy")

# Paths allowed over plain HTTP so platform health checks keep working.
_HTTP_ALLOWED = {"/healthz", "/readyz"}


class HttpsOnlyMiddleware:
    """Rejects plain-HTTP requests and adds security headers.

    TLS is terminated by the hosting platform (Railway, Render, a reverse
    proxy); it reports the original scheme in ``X-Forwarded-Proto``.
    """

    def __init__(self, app, enabled: bool):
        self.app = app
        self.enabled = enabled

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        if self.enabled and scope["path"] not in _HTTP_ALLOWED:
            headers = dict(scope.get("headers") or [])
            proto = headers.get(b"x-forwarded-proto", scope.get("scheme", "http").encode()).decode("latin-1")
            if proto.split(",")[0].strip().lower() != "https":
                response = JSONResponse(
                    status_code=400,
                    content={"error": {"message": "HTTPS is required", "type": "invalid_request_error", "code": "https_required"}},
                )
                return await response(scope, receive, send)

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                present = {name.lower() for name, _ in headers}
                extra = [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                ]
                # API responses carry balances and model output: never cache them,
                # never render them as a page.
                if b"cache-control" not in present:
                    extra.append((b"cache-control", b"no-store"))
                if b"content-security-policy" not in present:
                    extra.append((b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"))
                if self.enabled:
                    extra.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
                message["headers"] = headers + extra
            await send(message)

        await self.app(scope, receive, send_with_headers)


async def _maintenance_forever(services: Services) -> None:
    """Flush batched key-usage timestamps, refund abandoned transactions and
    drop expired dashboard sessions."""
    tick = 10
    reconcile_every = max(1, services.settings.reconcile_interval_seconds // tick)
    timeout = timedelta(minutes=services.settings.pending_timeout_minutes)
    ticks = 0
    while True:
        await asyncio.sleep(tick)
        ticks += 1
        try:
            await services.key_usage.flush(services.db)
            if ticks % reconcile_every == 0:
                await services.billing.reconcile_stale(timeout)
                await admin_session.purge_expired(services)
                await opossum_maintenance.run(services)
        except DB_UNAVAILABLE_ERRORS:
            log.warning("maintenance skipped: database unavailable")
        except Exception:  # keep the loop alive no matter what
            log.exception("maintenance failed")


def build_http_client(settings: Settings) -> httpx.AsyncClient:
    """One shared client: pooled, kept-alive connections so each provider call
    skips DNS and TLS handshakes, and HTTP/2 multiplexing where supported."""
    verify: bool | ssl.SSLContext = True
    if settings.upstream_extra_ca_file:
        import certifi

        context = ssl.create_default_context(cafile=certifi.where())
        context.load_verify_locations(settings.upstream_extra_ca_file)
        verify = context
    http2 = settings.upstream_http2 and importlib.util.find_spec("h2") is not None
    return httpx.AsyncClient(
        timeout=httpx.Timeout(settings.upstream_timeout_seconds, connect=settings.upstream_connect_timeout_seconds),
        follow_redirects=False,
        http2=http2,
        verify=verify,
        limits=httpx.Limits(
            max_connections=settings.upstream_max_connections,
            max_keepalive_connections=settings.upstream_max_connections,
            keepalive_expiry=settings.upstream_keepalive_seconds,
        ),
    )


def create_app(
    settings: Settings | None = None,
    *,
    database: Database | None = None,
    http_client: httpx.AsyncClient | None = None,
    run_reconciler: bool = True,
) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        connectors = build_connectors(settings)  # fails fast on bad provider config
        db = database or Database.from_settings(settings)
        http = http_client or build_http_client(settings)
        services = Services(
            settings=settings,
            db=db,
            billing=BillingEngine(db, settings.default_fee_per_request, settings.pricing_cache_seconds),
            connectors=connectors,
            http=http,
            auth_cache=AuthCache(settings.auth_cache_seconds),
        )
        app.state.services = services
        configured = [name for name, c in services.connectors.items() if c.configured]
        log.info(
            "starting",
            extra={"event": "startup", "providers_configured": configured, "providers_available": len(connectors),
                   "admin_enabled": settings.admin_enabled},
        )
        try:
            await opossum_maintenance.seed_sandbox(services)
        except DB_UNAVAILABLE_ERRORS:
            log.warning("opossum sandbox seeding skipped: database unavailable")
        task = asyncio.create_task(_maintenance_forever(services)) if run_reconciler else None
        try:
            yield
        finally:
            if task:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            with contextlib.suppress(*DB_UNAVAILABLE_ERRORS):
                await services.key_usage.flush(db)
            if http_client is None:
                await http.aclose()
            if database is None:
                await db.dispose()

    app = FastAPI(
        title="AI API Proxy",
        version="0.2.0",
        lifespan=lifespan,
        # Off by default: the schema maps every admin route for an attacker.
        docs_url="/docs" if settings.enable_docs else None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
        redoc_url=None,
    )

    app.add_middleware(HttpsOnlyMiddleware, enabled=settings.require_https)
    app.add_exception_handler(OpError, op_error_handler)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"message": str(exc.detail), "type": "error", "code": exc.status_code}},
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=422,
            content={"error": {"message": "invalid request", "type": "invalid_request_error", "details": [
                {"loc": list(e.get("loc", ())), "msg": e.get("msg"), "type": e.get("type")} for e in exc.errors()
            ]}},
        )

    # Connection-level failures only: a missing file or other OS error must not
    # be reported as "database down".
    for exc_type in (SQLAlchemyError, ConnectionError, TimeoutError, socket.gaierror):

        @app.exception_handler(exc_type)
        async def database_down(request: Request, exc: Exception):
            log.exception("database error", exc_info=exc)
            return JSONResponse(
                status_code=503,
                content={"error": {"message": "service temporarily unavailable", "type": "service_unavailable"}},
            )

    @app.get("/healthz", include_in_schema=False)
    async def healthz():
        return {"ok": True}

    @app.get("/readyz", include_in_schema=False)
    async def readyz(request: Request):
        if await request.app.state.services.db.ping():
            return {"ok": True, "database": "up"}
        return JSONResponse(status_code=503, content={"ok": False, "database": "down"})

    app.include_router(transactions_api.router)
    app.include_router(gateway.router)
    app.include_router(payments.router)
    app.include_router(admin_session.router)
    app.include_router(admin.api)
    app.include_router(admin.pages)
    app.include_router(opossum_api.router)
    app.include_router(opossum_merchant.router)
    app.include_router(opossum_admin.router)
    app.include_router(opossum_pages.router)
    return app


def __getattr__(name: str):
    # `uvicorn aiproxy.main:app` builds the app lazily so importing this module
    # (e.g. from tests) does not require a configured environment.
    if name == "app":
        return create_app()
    raise AttributeError(name)
