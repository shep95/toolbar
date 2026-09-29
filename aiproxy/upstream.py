"""Upstream connector: makes the real call to the provider and settles billing.

By the time ``forward`` runs, the gateway has authenticated the caller, the
router has picked a connector, and the provider-specific request is built.
``forward`` reserves the fee, calls the provider, then either charges
(success) or refunds (any failure) before returning the response.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

import anyio
import httpx
from fastapi.responses import Response, StreamingResponse

from .billing import BillingRejected, Reservation
from .connectors import Connector, StreamHandler, UpstreamCall
from .connectors.base import SSEParser, sse
from .db import DB_UNAVAILABLE_ERRORS
from .errors import GatewayError, error_response
from .models import TxStatus
from .services import Services

log = logging.getLogger("aiproxy.upstream")

# Upstream 4xx responses we pass straight back: they describe a problem with
# the caller's request (bad model name, context too long, ...).
_PASSTHROUGH_CLIENT_ERRORS = {400, 404, 409, 413, 415, 422, 429}


@dataclass
class Caller:
    api_key_id: Any
    user_id: Any
    key_prefix: str
    key_provider: str
    rate_limit_per_minute: int


def _money(value: Decimal) -> str:
    return f"{value:.6f}"


def _elapsed_ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)


async def forward(
    services: Services,
    *,
    request_id: str,
    caller: Caller,
    connector: Connector,
    call: UpstreamCall,
    model: str | None,
    endpoint: str,
    transform: Callable[[dict[str, Any]], dict[str, Any]] | None,
    stream_handler: StreamHandler | None,
) -> Response:
    billing = services.billing

    # 1. Pre-log the transaction as pending and reserve the fee.
    try:
        reservation = await billing.reserve(
            user_id=caller.user_id,
            api_key_id=caller.api_key_id,
            provider=connector.name,
            model=model,
            endpoint=endpoint,
            request_id=request_id,
        )
    except BillingRejected as exc:
        raise GatewayError(exc.status_code, exc.outcome, exc.message) from None
    except DB_UNAVAILABLE_ERRORS:
        log.exception("database unavailable while reserving", extra={"request_id": request_id})
        raise GatewayError(
            503, "database_unavailable", "service temporarily unavailable", write_audit_row=False
        ) from None

    try:
        return await _call_upstream(
            services,
            reservation=reservation,
            request_id=request_id,
            caller=caller,
            connector=connector,
            call=call,
            model=model,
            transform=transform,
            stream_handler=stream_handler,
        )
    except Exception as exc:
        # A bug must never leave the caller charged: refund now rather than
        # waiting for the stale-transaction sweep.
        log.exception("unexpected error after reservation", extra={"request_id": request_id})
        with anyio.CancelScope(shield=True):
            await _refund(services, reservation, request_id, error=f"internal: {exc!r}", latency_ms=0, status=TxStatus.ERROR)
        raise


async def _call_upstream(
    services: Services,
    *,
    reservation: Reservation,
    request_id: str,
    caller: Caller,
    connector: Connector,
    call: UpstreamCall,
    model: str | None,
    transform: Callable[[dict[str, Any]], dict[str, Any]] | None,
    stream_handler: StreamHandler | None,
) -> Response:
    base_headers = {"X-Request-Id": request_id, "X-Transaction-Id": str(reservation.transaction_id)}

    # 2. Call the provider.
    start = time.monotonic()
    upstream_request = services.http.build_request(
        "POST", connector.url(call.path), headers=connector.headers(), json=call.body
    )
    try:
        upstream = await services.http.send(upstream_request, stream=True)
    except httpx.TimeoutException as exc:
        await _refund(services, reservation, request_id, error=f"timeout: {exc!r}", latency_ms=_elapsed_ms(start))
        return error_response(504, "upstream_timeout", f"{connector.name} did not respond in time", request_id, base_headers)
    except httpx.HTTPError as exc:
        await _refund(services, reservation, request_id, error=f"connect: {exc!r}", latency_ms=_elapsed_ms(start))
        return error_response(502, "upstream_unavailable", f"{connector.name} is unreachable", request_id, base_headers)

    # 3a. Provider returned an error: refund and report.
    if upstream.status_code >= 400:
        try:
            content = await upstream.aread()
        except httpx.HTTPError:
            content = b""
        finally:
            await upstream.aclose()
        await _refund(
            services,
            reservation,
            request_id,
            upstream_status=upstream.status_code,
            error=content[:1000].decode("utf-8", errors="replace"),
            latency_ms=_elapsed_ms(start),
        )
        return _upstream_error_response(connector, upstream.status_code, content, request_id, base_headers)

    # 3b. Streaming success: bill when the stream ends.
    if call.stream and stream_handler is not None:
        return StreamingResponse(
            _stream(services, upstream, stream_handler, reservation, request_id, start, model),
            status_code=upstream.status_code,
            media_type="text/event-stream",
            headers={
                **base_headers,
                "X-Fee-Reserved": _money(reservation.reserved),
                "Cache-Control": "no-cache",
            },
        )

    # 3c. Non-streaming success.
    try:
        content = await upstream.aread()
    except httpx.HTTPError as exc:
        await _refund(services, reservation, request_id, error=f"read: {exc!r}", latency_ms=_elapsed_ms(start))
        return error_response(502, "upstream_unavailable", f"{connector.name} connection dropped", request_id, base_headers)
    finally:
        await upstream.aclose()

    try:
        data = json.loads(content)
        body = json.dumps(transform(data)).encode("utf-8") if transform else content
    except (ValueError, TypeError, AttributeError, KeyError) as exc:
        await _refund(
            services, reservation, request_id, upstream_status=upstream.status_code,
            error=f"unparseable upstream response: {exc!r}", latency_ms=_elapsed_ms(start),
        )
        return error_response(502, "upstream_bad_response", f"{connector.name} returned an invalid response", request_id, base_headers)

    usage = connector.extract_usage(data)
    headers = dict(base_headers)
    try:
        settlement = await services.billing.complete(
            reservation,
            usage=usage,
            model=(data.get("model") if isinstance(data, dict) else None) or model,
            upstream_status=upstream.status_code,
            latency_ms=_elapsed_ms(start),
        )
        headers["X-Fee-Charged"] = _money(settlement.fee)
        if settlement.balance is not None:
            headers["X-Balance-Remaining"] = _money(settlement.balance)
    except DB_UNAVAILABLE_ERRORS:
        # The provider already did the work, so the caller still gets the answer.
        # The transaction stays pending and the reconciler closes it later.
        log.exception("could not settle transaction", extra={"request_id": request_id})
    log.info(
        "proxied",
        extra={
            "event": "request_success",
            "request_id": request_id,
            "provider": connector.name,
            "user_id": str(caller.user_id),
            "tokens": usage.total,
            "latency_ms": _elapsed_ms(start),
        },
    )
    return Response(content=body, status_code=upstream.status_code, media_type="application/json", headers=headers)


async def _stream(
    services: Services,
    upstream: httpx.Response,
    handler: StreamHandler,
    reservation: Reservation,
    request_id: str,
    start: float,
    model: str | None,
):
    parser = SSEParser()
    interrupted: str | None = None
    try:
        async for chunk in upstream.aiter_bytes():
            for event in parser.feed(chunk):
                out = handler.handle(event)
                if out:
                    yield out
        for event in parser.flush():
            out = handler.handle(event)
            if out:
                yield out
        tail = handler.finish()
        if tail:
            yield tail
    except httpx.HTTPError as exc:
        interrupted = f"stream interrupted: {exc!r}"
        yield sse(json.dumps({"error": {"message": "upstream stream interrupted", "type": "upstream_error", "request_id": request_id}}))
    finally:
        # Shielded so billing still settles if the client disconnects mid-stream.
        with anyio.CancelScope(shield=True):
            await upstream.aclose()
            error = interrupted or handler.state.error
            try:
                if error:
                    await services.billing.fail(
                        reservation,
                        status=TxStatus.FAILED,
                        upstream_status=upstream.status_code,
                        error=error,
                        latency_ms=_elapsed_ms(start),
                    )
                else:
                    # Also reached when the client hangs up early: the provider
                    # served the request, so it is billed.
                    await services.billing.complete(
                        reservation,
                        usage=handler.state.usage,
                        model=handler.state.model or model,
                        upstream_status=upstream.status_code,
                        latency_ms=_elapsed_ms(start),
                    )
            except DB_UNAVAILABLE_ERRORS:
                log.exception("could not settle streamed transaction", extra={"request_id": request_id})


async def _refund(
    services: Services,
    reservation: Reservation,
    request_id: str,
    *,
    error: str,
    latency_ms: int,
    upstream_status: int | None = None,
    status: str = TxStatus.FAILED,
) -> None:
    log.warning(
        "upstream failure; not charging",
        extra={"event": "upstream_failed", "request_id": request_id, "upstream_status": upstream_status, "detail": error[:300]},
    )
    try:
        await services.billing.fail(
            reservation, status=status, upstream_status=upstream_status, error=error, latency_ms=latency_ms
        )
    except DB_UNAVAILABLE_ERRORS:
        log.exception("could not record upstream failure; reconciler will refund", extra={"request_id": request_id})


def _upstream_error_response(
    connector: Connector, status: int, content: bytes, request_id: str, headers: dict[str, str]
) -> Response:
    headers = {**headers, "X-Upstream-Status": str(status)}
    if status in _PASSTHROUGH_CLIENT_ERRORS:
        media_type = "application/json"
        try:
            json.loads(content)
        except ValueError:
            media_type = "text/plain"
        return Response(content=content, status_code=status, media_type=media_type, headers=headers)
    if status in (401, 403):
        # Our provider credentials were rejected. Never tell the caller their
        # own key is bad; this is an operator problem.
        log.error("%s rejected the proxy's credentials (HTTP %s)", connector.name, status)
        return error_response(502, "upstream_auth_failed", f"{connector.name} is unavailable right now", request_id, headers)
    return error_response(502, "upstream_error", f"{connector.name} returned an error (HTTP {status})", request_id, headers)
