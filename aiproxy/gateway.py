"""Gateway: the front door for user traffic.

Every user request is IP-limited, authenticated, checked and key-rate-limited
here before it can reach billing or a provider. Anything rejected gets a JSON
error and an audit record.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import orjson
from fastapi import APIRouter, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError

from .audit import record_rejection
from .connectors import Connector, UnsupportedRequest
from .countries import plain
from .db import DB_UNAVAILABLE_ERRORS
from .errors import GatewayError, error_response
from .keycache import CachedKey
from .models import PROVIDER_ANY, ApiKey, KeyStatus, User, UserStatus
from .router import resolve_unified_model, select_connector
from .security import display_prefix, hash_api_key, is_valid_key_format, looks_like_upstream_key
from .services import Services, get_services
from .upstream import Caller, forward

log = logging.getLogger("aiproxy.gateway")

router = APIRouter()

# Model IDs across providers: letters, digits and . _ : / @ + - (e.g.
# "meta-llama/Llama-3.3-70B-Instruct:fastest", "ft:gpt-5:org:x", "gpt://f/m/latest").
MODEL_RE = re.compile(r"^[A-Za-z0-9._:/@+\-]{1,200}$")

_TOKEN_LIMIT_FIELDS = ("max_tokens", "max_completion_tokens", "max_output_tokens")


def json_response(payload: Any, status_code: int = 200, headers: dict[str, str] | None = None) -> Response:
    return Response(orjson.dumps(payload), status_code=status_code, media_type="application/json", headers=headers)


def new_request_id() -> str:
    return "req_" + uuid.uuid4().hex


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def extract_key(request: Request) -> str | None:
    """Accept ``Authorization: Bearer <key>`` (OpenAI-style SDKs) or ``x-api-key`` (Anthropic SDK)."""
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


def enforce_ip_limits(services: Services, request: Request) -> None:
    ip = client_ip(request)
    settings = services.settings
    allowed, retry_after = services.ip_limiter.check(ip, settings.ip_rate_limit_per_minute)
    if not allowed:
        raise GatewayError(
            429, "ip_rate_limited", "too many requests from this address",
            headers={"Retry-After": str(retry_after)}, write_audit_row=False,
        )
    blocked, retry_after = services.auth_failure_limiter.is_limited(ip, settings.auth_failures_per_minute_per_ip)
    if blocked:
        raise GatewayError(
            429, "auth_failures_blocked", "too many failed authentication attempts from this address",
            headers={"Retry-After": str(retry_after)}, write_audit_row=False,
        )


async def _lookup_key(services: Services, key_hash: str):
    stmt = (
        select(
            ApiKey.id, ApiKey.user_id, ApiKey.status, ApiKey.provider, ApiKey.rate_limit_per_minute,
            ApiKey.key_prefix, User.status, User.country,
        )
        .join(User, User.id == ApiKey.user_id)
        .where(ApiKey.key_hash == key_hash)
    )
    for attempt in (1, 2):
        try:
            async with services.db.engine.connect() as conn:
                return (await conn.execute(stmt)).first()
        except DBAPIError as exc:
            if attempt == 1 and exc.connection_invalidated:
                continue  # pooled connection was dead (e.g. database restarted)
            raise


async def authenticate(services: Services, request: Request) -> Caller:
    enforce_ip_limits(services, request)
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

    key_hash = hash_api_key(raw_key)
    default_limit = services.settings.rate_limit_per_minute
    cached = services.auth_cache.get(key_hash)
    if cached is not None:
        caller = Caller(
            api_key_id=cached.api_key_id, user_id=cached.user_id, key_prefix=cached.key_prefix,
            key_provider=cached.key_provider, rate_limit_per_minute=cached.rate_limit_per_minute or default_limit,
            country=cached.country,
        )
        request.state.caller = caller
        return caller

    try:
        row = await _lookup_key(services, key_hash)
    except DB_UNAVAILABLE_ERRORS:
        log.exception("database unavailable during authentication")
        raise GatewayError(503, "database_unavailable", "service temporarily unavailable", write_audit_row=False) from None

    if row is None:
        raise GatewayError(401, "invalid_key", "invalid API key", detail=f"unknown key {display_prefix(raw_key)}")
    key_id, user_id, key_status, key_provider, key_limit, key_prefix, user_status, user_country = row
    caller = Caller(
        api_key_id=key_id, user_id=user_id, key_prefix=key_prefix, key_provider=key_provider,
        rate_limit_per_minute=key_limit or default_limit, country=user_country,
    )
    request.state.caller = caller
    if key_status != KeyStatus.ACTIVE:
        raise GatewayError(401, "key_revoked", "this API key has been revoked")
    if user_status != UserStatus.ACTIVE:
        raise GatewayError(403, "user_suspended", "account is suspended")
    services.auth_cache.put(key_hash, CachedKey(key_id, user_id, key_prefix, key_provider, key_limit, user_country))
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
    settings = services.settings
    limit = settings.max_request_bytes
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise GatewayError(413, "request_too_large", f"request body exceeds {limit} bytes")
    chunks: list[bytes] = []
    size = 0
    try:
        # A client trickling its body one byte at a time must not hold a
        # connection open indefinitely.
        async with asyncio.timeout(settings.body_read_timeout_seconds):
            async for chunk in request.stream():
                size += len(chunk)
                if size > limit:
                    raise GatewayError(413, "request_too_large", f"request body exceeds {limit} bytes")
                chunks.append(chunk)
    except TimeoutError:
        raise GatewayError(408, "request_timeout", "request body was not received in time") from None
    try:
        # orjson also rejects pathological nesting (depth > 1024).
        body = orjson.loads(b"".join(chunks))
    except orjson.JSONDecodeError:
        raise GatewayError(400, "invalid_json", "request body must be valid JSON") from None
    if not isinstance(body, dict):
        raise GatewayError(400, "invalid_json", "request body must be a JSON object")
    return body


def enforce_body_policy(services: Services, body: dict[str, Any]) -> None:
    """Refuse requests that would make one flat-fee request cost the operator many times more."""
    settings = services.settings
    n = body.get("n")
    if n is not None and (not isinstance(n, int) or isinstance(n, bool) or n < 1 or n > settings.max_choices):
        raise GatewayError(400, "invalid_request", f"'n' must be between 1 and {settings.max_choices}")
    tier = body.get("service_tier")
    if tier is not None and (not isinstance(tier, str) or tier.lower() in settings.blocked_tiers):
        raise GatewayError(400, "invalid_request", f"service_tier '{tier}' is not available")
    cap = settings.max_output_tokens
    if cap > 0:
        present = False
        for field in _TOKEN_LIMIT_FIELDS:
            value = body.get(field)
            if value is None:
                continue
            present = True
            if not isinstance(value, int) or isinstance(value, bool) or value < 1 or value > cap:
                raise GatewayError(400, "invalid_request", f"'{field}' must be between 1 and {cap}")
        if not present:
            body["max_tokens"] = cap


def validate_model(model: Any, required: bool) -> str | None:
    if model is None and not required:
        return None
    if not isinstance(model, str) or not MODEL_RE.match(model) or ".." in model or model.startswith("/"):
        raise GatewayError(400, "invalid_request", "'model' must be a model ID (letters, digits and . _ : / @ + -)")
    return model


async def run_request(request: Request, work: Callable[[Services, str], Awaitable[Response]]) -> Response:
    services = get_services(request)
    request_id = new_request_id()
    try:
        return await work(services, request_id)
    except GatewayError as exc:
        caller: Caller | None = getattr(request.state, "caller", None)
        write_db = exc.write_audit_row
        ip = client_ip(request)
        if exc.status_code == 401:
            services.auth_failure_limiter.check(ip, 1_000_000)  # count it
            if write_db:
                # Someone hammering us with bad keys must not be able to fill
                # the audit table. Past the threshold the rejection is still
                # logged to stdout, just not stored.
                allowed, _ = services.audit_failure_limiter.check(
                    ip, services.settings.audit_auth_failures_per_minute_per_ip
                )
                write_db = allowed
        await record_rejection(
            services.db,
            status_code=exc.status_code,
            outcome=exc.outcome,
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            client_ip=ip,
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
        validate_model(model, required=True)
        connector = select_connector(provider, caller.key_provider, services.connectors)
        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            raise GatewayError(400, "invalid_request", "'messages' must be a non-empty array")
        enforce_body_policy(services, body)
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


# --------------------------------------------------------------------- discovery


async def _fetch_models(services: Services, connector: Connector) -> tuple[bytes, list[str]] | None:
    """GET <base>/models for one provider, cached. Returns None if the provider cannot list models."""
    now = time.monotonic()
    cached = services.models_cache.get(connector.name)
    if cached and cached[0] > now:
        return cached[1], cached[2]
    try:
        headers = await connector.headers(services.http)
        headers.pop("Content-Type", None)
        response = await services.http.get(connector.url("models"), headers=headers, timeout=8.0)
    except httpx.HTTPError:
        return None
    if response.status_code != 200 or len(response.content) > 5_000_000:
        return None
    try:
        payload = orjson.loads(response.content)
        items = payload.get("data") if isinstance(payload, dict) else payload
        ids = [str(m["id"]) for m in items if isinstance(m, dict) and "id" in m]
    except (orjson.JSONDecodeError, TypeError):
        return None
    services.models_cache[connector.name] = (now + services.settings.models_cache_seconds, response.content, ids)
    return response.content, ids


def _allowed_connectors(services: Services, caller: Caller) -> list[Connector]:
    return [
        c for name, c in services.connectors.items()
        if c.configured and caller.key_provider in (PROVIDER_ANY, name)
    ]


@router.get("/v1/models")
async def list_models(request: Request) -> Response:
    """Every model this key can reach, as ``<provider>/<model>``. Not billed."""

    async def work(services: Services, request_id: str) -> Response:
        caller = await authenticate(services, request)
        enforce_rate_limit(services, caller)
        connectors = [c for c in _allowed_connectors(services, caller) if c.lists_models]
        results = await asyncio.gather(*(_fetch_models(services, c) for c in connectors))
        data = []
        for connector, result in zip(connectors, results):
            for model_id in (result[1] if result else []):
                data.append({"id": f"{connector.name}/{model_id}", "object": "model", "created": 0, "owned_by": connector.name})
        return json_response({"object": "list", "data": data}, headers={"X-Request-Id": request_id})

    return await run_request(request, work)


@router.get("/v1/providers")
async def list_providers(request: Request) -> Response:
    """Providers this key can use, with their home country and native endpoints. Not billed."""

    async def work(services: Services, request_id: str) -> Response:
        caller = await authenticate(services, request)
        enforce_rate_limit(services, caller)
        data = [
            {k: v for k, v in c.describe().items() if k not in ("base_url", "configured")}
            for c in _allowed_connectors(services, caller)
        ]
        return json_response({"object": "list", "data": data}, headers={"X-Request-Id": request_id})

    return await run_request(request, work)


@router.get("/{provider}/v1/models")
async def native_models(provider: str, request: Request) -> Response:
    """The provider's own model list, for official SDKs' ``models.list()``. Not billed."""

    async def work(services: Services, request_id: str) -> Response:
        if provider not in services.connectors:
            raise GatewayError(404, "unknown_provider", f"unknown provider '{provider}'", write_audit_row=False)
        caller = await authenticate(services, request)
        enforce_rate_limit(services, caller)
        connector = select_connector(provider, caller.key_provider, services.connectors)
        result = await _fetch_models(services, connector) if connector.lists_models else None
        if result is None:
            raise GatewayError(404, "models_unavailable", f"{provider} does not provide a model list")
        return Response(result[0], media_type="application/json", headers={"X-Request-Id": request_id})

    return await run_request(request, work)


@router.post("/{provider}/v1/{path:path}")
async def native_passthrough(provider: str, path: str, request: Request) -> Response:
    """Provider-native API. Point an official SDK's base URL at ``/<provider>/v1``."""

    async def work(services: Services, request_id: str) -> Response:
        if provider not in services.connectors:
            raise GatewayError(404, "unknown_provider", f"unknown provider '{provider}'", write_audit_row=False)
        caller = await authenticate(services, request)
        enforce_rate_limit(services, caller)
        connector = select_connector(provider, caller.key_provider, services.connectors)
        body = await read_json_body(services, request)
        model = validate_model(body.get("model"), required=False)
        enforce_body_policy(services, body)
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
        if key is None or key.status != KeyStatus.ACTIVE:
            raise GatewayError(401, "key_revoked", "this API key has been revoked")
        last_used = services.key_usage.last_seen(key.id) or key.last_used_at
        multiplier = await services.billing.country_multiplier(user.country)
        base = await services.billing.price_for("transactions", None)
        return json_response(
            {
                "user_id": str(user.id),
                "email": user.email,
                "balance": f"{user.balance:.6f}",
                "status": user.status,
                "country": user.country,
                "fees": {
                    "currency": "USD",
                    "country_multiplier": plain(multiplier),
                    "per_transaction": f"{base.scaled(multiplier).fee_for(None):.6f}",
                },
                "key": {
                    "id": str(key.id),
                    "prefix": key.key_prefix,
                    "name": key.name,
                    "provider": key.provider,
                    "rate_limit_per_minute": caller.rate_limit_per_minute,
                    "created_at": key.created_at.isoformat(),
                    "last_used_at": last_used.isoformat() if last_used else None,
                },
            },
            headers={"X-Request-Id": request_id},
        )

    return await run_request(request, work)
