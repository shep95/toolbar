"""Gateway: the front door for user traffic.

Every user request is authenticated, checked and rate limited here before it
can reach billing or a provider. Anything rejected gets a JSON error and an
audit record.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select

from .audit import record_rejection
from .connectors import UnsupportedRequest
from .db import DB_UNAVAILABLE_ERRORS
from .errors import GatewayError, error_response
from .models import ApiKey, KeyStatus, User, UserStatus
from .router import resolve_unified_model, select_connector
from .security import display_prefix, hash_api_key, is_valid_key_format, looks_like_upstream_key
from .services import Services, get_services
from .upstream import Caller, forward

log = logging.getLogger("aiproxy.gateway")

router = APIRouter()


def new_request_id() -> str:
    return "req_" + uuid.uuid4().hex


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def extract_key(request: Request) -> str | None:
    """Accept ``Authorization: Bearer <key>`` (OpenAI/Mistral SDKs) or ``x-api-key`` (Anthropic SDK)."""
    bearer = None
    auth = request.headers.get("authorization")
    if auth:
        scheme, _, value = auth.partition(" ")
        if scheme.lower() != "bearer" or not value.strip():
            raise GatewayError(401, "invalid_auth_header", "use 'Authorization: Bearer <key>'")
        bearer = value.strip()
    header_key = (request.headers.get("x-api-key") or "").strip() or None
    if bearer and header_key and bearer != header_key:
        # Two different credentials in one request is how a smuggled provider
        # key would arrive. Refuse rather than guess which one is meant.
        raise GatewayError(400, "conflicting_credentials", "send exactly one API key")
    return bearer or header_key


async def authenticate(services: Services, request: Request) -> Caller:
    raw_key = extract_key(request)
    if raw_key is None:
        raise GatewayError(401, "missing_key", "missing API key")
    if not is_valid_key_format(raw_key):
        upstream = looks_like_upstream_key(raw_key)
        if upstream:
            raise GatewayError(
                401,
                "upstream_key_rejected",
                "provider API keys are not accepted here; use the key issued by this service",
                detail=f"credential looks like a {upstream} key",
            )
        raise GatewayError(401, "invalid_key", "invalid API key")

    try:
        async with services.db.session() as session:
            row = (
                await session.execute(
                    select(
                        ApiKey.id,
                        ApiKey.user_id,
                        ApiKey.status,
                        ApiKey.provider,
                        ApiKey.rate_limit_per_minute,
                        ApiKey.key_prefix,
                        User.status,
                    )
                    .join(User, User.id == ApiKey.user_id)
                    .where(ApiKey.key_hash == hash_api_key(raw_key))
                )
            ).first()
    except DB_UNAVAILABLE_ERRORS:
        log.exception("database unavailable during authentication")
        raise GatewayError(503, "database_unavailable", "service temporarily unavailable", write_audit_row=False) from None

    if row is None:
        raise GatewayError(401, "invalid_key", "invalid API key", detail=f"unknown key {display_prefix(raw_key)}")
    key_id, user_id, key_status, key_provider, key_limit, key_prefix, user_status = row
    caller = Caller(
        api_key_id=key_id,
        user_id=user_id,
        key_prefix=key_prefix,
        key_provider=key_provider,
        rate_limit_per_minute=key_limit or services.settings.rate_limit_per_minute,
    )
    request.state.caller = caller
    if key_status != KeyStatus.ACTIVE:
        raise GatewayError(401, "key_revoked", "this API key has been revoked")
    if user_status != UserStatus.ACTIVE:
        raise GatewayError(403, "user_suspended", "account is suspended")
    return caller


def enforce_rate_limit(services: Services, caller: Caller) -> None:
    allowed, retry_after = services.limiter.check(str(caller.api_key_id), caller.rate_limit_per_minute)
    if not allowed:
        raise GatewayError(
            429,
            "rate_limited",
            f"rate limit of {caller.rate_limit_per_minute} requests per minute exceeded",
            headers={"Retry-After": str(retry_after)},
        )


async def read_json_body(services: Services, request: Request) -> dict[str, Any]:
    limit = services.settings.max_request_bytes
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise GatewayError(413, "request_too_large", f"request body exceeds {limit} bytes")
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise GatewayError(413, "request_too_large", f"request body exceeds {limit} bytes")
        chunks.append(chunk)
    try:
        body = json.loads(b"".join(chunks))
    except ValueError:
        raise GatewayError(400, "invalid_json", "request body must be valid JSON") from None
    if not isinstance(body, dict):
        raise GatewayError(400, "invalid_json", "request body must be a JSON object")
    return body


async def run_request(request: Request, work: Callable[[Services, str], Awaitable[Response]]) -> Response:
    services = get_services(request)
    request_id = new_request_id()
    try:
        return await work(services, request_id)
    except GatewayError as exc:
        caller: Caller | None = getattr(request.state, "caller", None)
        write_db = exc.write_audit_row
        if write_db and exc.status_code == 401:
            # Someone hammering us with bad keys must not be able to fill the
            # audit table. Past the threshold the rejection is still logged to
            # stdout, just not stored. Valid keys are never affected.
            allowed, _ = services.auth_failure_limiter.check(
                client_ip(request) or "unknown", services.settings.audit_auth_failures_per_minute_per_ip
            )
            write_db = allowed
        await record_rejection(
            services.db,
            status_code=exc.status_code,
            outcome=exc.outcome,
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            client_ip=client_ip(request),
            detail=exc.detail or exc.message,
            user_id=caller.user_id if caller else None,
            api_key_id=caller.api_key_id if caller else None,
            key_prefix=caller.key_prefix if caller else None,
            write_db=write_db,
        )
        return error_response(exc.status_code, exc.outcome, exc.message, request_id, exc.headers)


@router.post("/v1/chat/completions")
async def unified_chat_completions(request: Request) -> Response:
    """OpenAI-format chat completions for any provider: ``model="<provider>/<model>"``."""

    async def work(services: Services, request_id: str) -> Response:
        caller = await authenticate(services, request)
        enforce_rate_limit(services, caller)
        body = await read_json_body(services, request)
        provider, model = resolve_unified_model(body.get("model"), caller.key_provider, services.connectors)
        connector = select_connector(provider, caller.key_provider, services.connectors)
        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            raise GatewayError(400, "invalid_request", "'messages' must be a non-empty array")
        try:
            call = connector.unified_request(body, model)
        except UnsupportedRequest as exc:
            raise GatewayError(400, "unsupported_request", str(exc)) from None
        return await forward(
            services,
            request_id=request_id,
            caller=caller,
            connector=connector,
            call=call,
            model=model,
            endpoint="chat/completions",
            transform=connector.unified_response,
            stream_handler=connector.unified_stream_handler(body) if call.stream else None,
        )

    return await run_request(request, work)


@router.post("/{provider}/v1/{path:path}")
async def native_passthrough(provider: str, path: str, request: Request) -> Response:
    """Provider-native API. Point an official SDK's base URL at ``/<provider>/v1``."""

    async def work(services: Services, request_id: str) -> Response:
        if provider not in services.connectors:
            raise GatewayError(404, "unknown_provider", f"unknown provider '{provider}'")
        caller = await authenticate(services, request)
        enforce_rate_limit(services, caller)
        connector = select_connector(provider, caller.key_provider, services.connectors)
        body = await read_json_body(services, request)
        model = body.get("model")
        if model is not None and (not isinstance(model, str) or len(model) > 200):
            raise GatewayError(400, "invalid_request", "'model' must be a string")
        try:
            call = connector.native_request(path.strip("/"), body)
        except UnsupportedRequest as exc:
            raise GatewayError(404, "unsupported_endpoint", str(exc)) from None
        return await forward(
            services,
            request_id=request_id,
            caller=caller,
            connector=connector,
            call=call,
            model=model,
            endpoint=call.path,
            transform=None,
            stream_handler=connector.native_stream_handler() if call.stream else None,
        )

    return await run_request(request, work)


@router.get("/v1/account")
async def account(request: Request) -> Response:
    """The caller's own balance and key details. Not billed."""

    async def work(services: Services, request_id: str) -> Response:
        caller = await authenticate(services, request)
        enforce_rate_limit(services, caller)
        try:
            async with services.db.session() as session:
                user = await session.get(User, caller.user_id)
                key = await session.get(ApiKey, caller.api_key_id)
        except DB_UNAVAILABLE_ERRORS:
            raise GatewayError(503, "database_unavailable", "service temporarily unavailable", write_audit_row=False) from None
        return JSONResponse(
            {
                "user_id": str(user.id),
                "email": user.email,
                "balance": f"{user.balance:.6f}",
                "status": user.status,
                "key": {
                    "id": str(key.id),
                    "prefix": key.key_prefix,
                    "name": key.name,
                    "provider": key.provider,
                    "rate_limit_per_minute": caller.rate_limit_per_minute,
                    "created_at": key.created_at.isoformat(),
                    "last_used_at": key.last_used_at.isoformat() if key.last_used_at else None,
                },
            },
            headers={"X-Request-Id": request_id},
        )

    return await run_request(request, work)
