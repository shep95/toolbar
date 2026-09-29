"""Application factory.

Run with::

    uvicorn aiproxy.main:app --host 0.0.0.0 --port 8000 --proxy-headers
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
from contextlib import asynccontextmanager
from datetime import timedelta

import httpx
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import admin, gateway, payments
from .billing import BillingEngine
from .config import Settings, get_settings
from .connectors import build_connectors
from .db import DB_UNAVAILABLE_ERRORS, Database
from .logging_setup import configure_logging
from .ratelimit import RateLimiter
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
                extra = [(b"x-content-type-options", b"nosniff")]
                if self.enabled:
                    extra.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
                message["headers"] = list(message.get("headers") or []) + extra
            await send(message)

        await self.app(scope, receive, send_with_headers)


async def _reconcile_forever(services: Services) -> None:
    interval = services.settings.reconcile_interval_seconds
    timeout = timedelta(minutes=services.settings.pending_timeout_minutes)
    while True:
        await asyncio.sleep(interval)
        try:
            await services.billing.reconcile_stale(timeout)
        except DB_UNAVAILABLE_ERRORS:
            log.warning("reconciler skipped: database unavailable")
        except Exception:  # keep the loop alive no matter what
            log.exception("reconciler failed")


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
        db = database or Database.from_settings(settings)
        http = http_client or httpx.AsyncClient(
            timeout=httpx.Timeout(settings.upstream_timeout_seconds, connect=settings.upstream_connect_timeout_seconds),
            follow_redirects=False,
            limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
        )
        services = Services(
            settings=settings,
            db=db,
            billing=BillingEngine(db, settings.default_fee_per_request),
            limiter=RateLimiter(),
            auth_failure_limiter=RateLimiter(),
            connectors=build_connectors(settings),
            http=http,
        )
        app.state.services = services
        configured = [name for name, c in services.connectors.items() if c.configured]
        log.info("starting", extra={"event": "startup", "providers_configured": configured, "admin_enabled": settings.admin_enabled})
        task = asyncio.create_task(_reconcile_forever(services)) if run_reconciler else None
        try:
            yield
        finally:
            if task:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            if http_client is None:
                await http.aclose()
            if database is None:
                await db.dispose()

    app = FastAPI(
        title="AI API Proxy",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url=None,
    )

    app.add_middleware(HttpsOnlyMiddleware, enabled=settings.require_https)

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

    app.include_router(gateway.router)
    app.include_router(payments.router)
    app.include_router(admin.api)
    app.include_router(admin.pages)
    return app


def __getattr__(name: str):
    # `uvicorn aiproxy.main:app` builds the app lazily so importing this module
    # (e.g. from tests) does not require a configured environment.
    if name == "app":
        return create_app()
    raise AttributeError(name)
