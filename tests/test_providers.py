"""Connectors, upstream failures and billing outcomes per request."""

from __future__ import annotations

import json
from decimal import Decimal

import httpx
from sqlalchemy import select

from aiproxy.models import Transaction, User

from .conftest import ADMIN, ANTHROPIC_KEY, MISTRAL_KEY
from .test_gateway import CHAT, auth, openai_ok


async def only_tx(database) -> Transaction:
    async with database.session() as s:
        rows = (await s.execute(select(Transaction))).scalars().all()
    assert len(rows) == 1
    return rows[0]


async def balance_of(database, user) -> Decimal:
    async with database.session() as s:
        return Decimal((await s.get(User, __import__("uuid").UUID(user["id"]))).balance)


def sse_body(*events: tuple[str | None, object]) -> bytes:
    out = b""
    for name, data in events:
        if name:
            out += f"event: {name}\n".encode()
        payload = data if isinstance(data, str) else json.dumps(data)
        out += f"data: {payload}\n\n".encode()
    return out


def sse_response(body: bytes) -> httpx.Response:
    return httpx.Response(200, content=body, headers={"content-type": "text/event-stream"})


def parse_sse(text: str) -> list[str]:
    return [line[len("data: ") :] for line in text.splitlines() if line.startswith("data: ")]


# ------------------------------------------------------------------ OpenAI


async def test_openai_success_charges_flat_fee(client, make_user, upstream, database):
    upstream.on("/v1/chat/completions", openai_ok)
    user, key = await make_user(balance="1")
    r = await client.post("/v1/chat/completions", json=CHAT, headers=auth(key))
    assert r.status_code == 200
    assert r.json()["choices"][0]["message"]["content"] == "hello"
    assert r.headers["X-Fee-Charged"] == "0.030000"
    assert r.headers["X-Balance-Remaining"] == "0.970000"
    assert upstream.json_body()["model"] == "gpt-5"
    tx = await only_tx(database)
    assert (tx.status, tx.provider, tx.model_called, tx.tokens_used) == ("success", "openai", "gpt-5", 12)
    assert (tx.input_tokens, tx.output_tokens) == (5, 7)
    assert Decimal(tx.fee_charged) == Decimal("0.03")
    assert tx.upstream_status == 200 and tx.latency_ms is not None
    assert await balance_of(database, user) == Decimal("0.97")


async def test_openai_stream_bills_usage_and_hides_injected_usage_chunk(client, make_user, upstream, database):
    chunks = [
        {"id": "c", "model": "gpt-5", "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}}]},
        {"id": "c", "model": "gpt-5", "choices": [{"index": 0, "delta": {"content": "Hel"}}]},
        {"id": "c", "model": "gpt-5", "choices": [{"index": 0, "delta": {"content": "lo"}, "finish_reason": "stop"}]},
        {"id": "c", "model": "gpt-5", "choices": [], "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}},
    ]
    body = sse_body(*[(None, c) for c in chunks], (None, "[DONE]"))
    upstream.on("/v1/chat/completions", sse_response(body))
    user, key = await make_user(balance="1")
    r = await client.post("/v1/chat/completions", json={**CHAT, "stream": True}, headers=auth(key))
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")
    events = parse_sse(r.text)
    assert events[-1] == "[DONE]"
    # We asked OpenAI for usage; the client did not, so they do not see it.
    assert all("usage" not in json.loads(e) for e in events[:-1])
    assert upstream.json_body()["stream_options"] == {"include_usage": True}
    tx = await only_tx(database)
    assert (tx.status, tx.tokens_used) == ("success", 5)
    assert await balance_of(database, user) == Decimal("0.97")


async def test_openai_stream_keeps_usage_chunk_when_client_asks(client, make_user, upstream):
    body = sse_body(
        (None, {"id": "c", "choices": [{"index": 0, "delta": {"content": "x"}}]}),
        (None, {"id": "c", "choices": [], "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}),
        (None, "[DONE]"),
    )
    upstream.on("/v1/chat/completions", sse_response(body))
    _, key = await make_user()
    r = await client.post(
        "/v1/chat/completions",
        json={**CHAT, "stream": True, "stream_options": {"include_usage": True}},
        headers=auth(key),
    )
    assert any("usage" in e for e in parse_sse(r.text) if e != "[DONE]")


# ------------------------------------------------------------------ Anthropic


def anthropic_ok(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-5-5",
            "content": [{"type": "text", "text": "Bonjour"}],
            "stop_reason": "max_tokens",
            "usage": {"input_tokens": 10, "output_tokens": 4, "cache_read_input_tokens": 2},
        },
    )


async def test_anthropic_unified_translation(client, make_user, upstream, database):
    upstream.on("/v1/messages", anthropic_ok)
    _, key = await make_user()
    body = {
        "model": "anthropic/claude-sonnet-5-5",
        "messages": [
            {"role": "system", "content": "Be brief."},
            {"role": "user", "content": [{"type": "text", "text": "hi"}, {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}}]},
        ],
        "max_tokens": 50,
        "temperature": 0.2,
        "stop": "END",
    }
    r = await client.post("/v1/chat/completions", json=body, headers=auth(key))
    assert r.status_code == 200, r.text

    sent = upstream.requests[0]
    assert sent.headers["x-api-key"] == ANTHROPIC_KEY
    assert sent.headers["anthropic-version"] == "2023-06-01"
    assert "authorization" not in sent.headers
    payload = upstream.json_body()
    assert payload["model"] == "claude-sonnet-5-5"
    assert payload["system"] == "Be brief."
    assert payload["max_tokens"] == 50
    assert payload["stop_sequences"] == ["END"]
    assert payload["messages"][0]["content"][1] == {
        "type": "image",
        "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"},
    }

    data = r.json()
    assert data["object"] == "chat.completion"
    assert data["choices"][0]["message"] == {"role": "assistant", "content": "Bonjour"}
    assert data["choices"][0]["finish_reason"] == "length"
    assert data["usage"] == {"prompt_tokens": 12, "completion_tokens": 4, "total_tokens": 16}
    assert (await only_tx(database)).tokens_used == 16


async def test_anthropic_default_max_tokens_and_unsupported_fields(client, make_user, upstream):
    upstream.on("/v1/messages", anthropic_ok)
    _, key = await make_user()
    r = await client.post(
        "/v1/chat/completions", json={**CHAT, "model": "anthropic/claude-haiku-4-5"}, headers=auth(key)
    )
    assert r.status_code == 200
    assert upstream.json_body()["max_tokens"] == 4096
    r = await client.post(
        "/v1/chat/completions",
        json={**CHAT, "model": "anthropic/claude-haiku-4-5", "tools": [{"type": "function"}]},
        headers=auth(key),
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "unsupported_request"
    assert len(upstream.requests) == 1  # the rejected request never went out


async def test_anthropic_stream_is_translated_to_openai_chunks(client, make_user, upstream, database):
    body = sse_body(
        ("message_start", {"type": "message_start", "message": {"id": "msg_9", "model": "claude-sonnet-5-5", "usage": {"input_tokens": 8, "output_tokens": 1}}}),
        ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        ("ping", {"type": "ping"}),
        ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hi "}}),
        ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "there"}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 6}}),
        ("message_stop", {"type": "message_stop"}),
    )
    upstream.on("/v1/messages", sse_response(body))
    _, key = await make_user()
    r = await client.post(
        "/v1/chat/completions",
        json={**CHAT, "model": "anthropic/claude-sonnet-5-5", "stream": True, "stream_options": {"include_usage": True}},
        headers=auth(key),
    )
    assert r.status_code == 200
    events = parse_sse(r.text)
    assert events[-1] == "[DONE]"
    chunks = [json.loads(e) for e in events[:-1]]
    assert chunks[0]["choices"][0]["delta"] == {"role": "assistant", "content": ""}
    text = "".join(c["choices"][0]["delta"].get("content", "") for c in chunks if c["choices"])
    assert text == "Hi there"
    assert [c["choices"][0]["finish_reason"] for c in chunks if c["choices"]][-1] == "stop"
    assert chunks[-1]["usage"] == {"prompt_tokens": 8, "completion_tokens": 6, "total_tokens": 14}
    assert all(c["object"] == "chat.completion.chunk" and c["id"] == "msg_9" for c in chunks)
    tx = await only_tx(database)
    assert (tx.status, tx.tokens_used, tx.model_called) == ("success", 14, "claude-sonnet-5-5")


async def test_anthropic_stream_error_event_is_not_charged(client, make_user, upstream, database):
    body = sse_body(
        ("message_start", {"type": "message_start", "message": {"id": "m", "model": "c", "usage": {"input_tokens": 1}}}),
        ("error", {"type": "error", "error": {"type": "overloaded_error", "message": "Overloaded"}}),
    )
    upstream.on("/v1/messages", sse_response(body))
    user, key = await make_user(balance="1")
    r = await client.post(
        "/v1/chat/completions", json={**CHAT, "model": "anthropic/c", "stream": True}, headers=auth(key)
    )
    assert "overloaded_error" in r.text
    tx = await only_tx(database)
    assert tx.status == "failed" and Decimal(tx.fee_charged) == 0
    assert await balance_of(database, user) == Decimal("1")


async def test_anthropic_native_passthrough_with_sdk_style_auth(client, make_user, upstream, database):
    upstream.on("/v1/messages", anthropic_ok)
    _, key = await make_user(provider="anthropic")
    native = {"model": "claude-sonnet-5-5", "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]}
    r = await client.post(
        "/anthropic/v1/messages", json=native, headers={"x-api-key": key["api_key"], "anthropic-version": "2023-06-01"}
    )
    assert r.status_code == 200
    assert r.json()["content"][0]["text"] == "Bonjour"  # untouched native response
    assert upstream.json_body() == native
    assert (await only_tx(database)).endpoint == "messages"


async def test_native_passthrough_rejects_unlisted_endpoints(client, make_user, upstream):
    _, key = await make_user()
    for path in ("/openai/v1/files", "/openai/v1/fine_tuning/jobs", "/nope/v1/chat/completions"):
        r = await client.post(path, json={}, headers=auth(key))
        assert r.status_code == 404, path
    assert upstream.requests == []


# ------------------------------------------------------------------ Mistral


async def test_mistral_unified_adjusts_parameters(client, make_user, upstream, database):
    upstream.on("/v1/chat/completions", openai_ok)
    _, key = await make_user()
    body = {**CHAT, "model": "mistral/mistral-large-latest", "seed": 7, "user": "u1", "max_completion_tokens": 20}
    r = await client.post("/v1/chat/completions", json=body, headers=auth(key))
    assert r.status_code == 200
    sent = upstream.requests[0]
    assert sent.url.host == "api.mistral.test"
    assert sent.headers["authorization"] == f"Bearer {MISTRAL_KEY}"
    payload = upstream.json_body()
    assert payload["model"] == "mistral-large-latest"
    assert payload["random_seed"] == 7 and "seed" not in payload
    assert payload["max_tokens"] == 20 and "max_completion_tokens" not in payload
    assert "user" not in payload
    assert (await only_tx(database)).provider == "mistral"


# ------------------------------------------------------------------ failures


async def test_upstream_down_is_502_and_not_charged(client, make_user, upstream, database):
    def down(request):
        raise httpx.ConnectError("connection refused")

    upstream.on("/v1/chat/completions", down)
    user, key = await make_user(balance="1")
    r = await client.post("/v1/chat/completions", json=CHAT, headers=auth(key))
    assert r.status_code == 502
    assert r.json()["error"]["code"] == "upstream_unavailable"
    tx = await only_tx(database)
    assert tx.status == "failed" and Decimal(tx.fee_charged) == 0
    assert await balance_of(database, user) == Decimal("1")


async def test_upstream_timeout_is_504_and_not_charged(client, make_user, upstream, database):
    def slow(request):
        raise httpx.ReadTimeout("timed out")

    upstream.on("/v1/chat/completions", slow)
    user, key = await make_user(balance="1")
    r = await client.post("/v1/chat/completions", json=CHAT, headers=auth(key))
    assert r.status_code == 504
    assert await balance_of(database, user) == Decimal("1")


async def test_upstream_5xx_is_502_and_not_charged(client, make_user, upstream, database):
    upstream.on("/v1/chat/completions", httpx.Response(503, json={"error": "overloaded"}))
    user, key = await make_user(balance="1")
    r = await client.post("/v1/chat/completions", json=CHAT, headers=auth(key))
    assert r.status_code == 502
    assert r.headers["X-Upstream-Status"] == "503"
    tx = await only_tx(database)
    assert (tx.status, tx.upstream_status) == ("failed", 503)
    assert await balance_of(database, user) == Decimal("1")


async def test_upstream_client_error_is_passed_through_and_not_charged(client, make_user, upstream, database):
    upstream.on("/v1/chat/completions", httpx.Response(404, json={"error": {"message": "model not found"}}))
    user, key = await make_user(balance="1")
    r = await client.post("/v1/chat/completions", json=CHAT, headers=auth(key))
    assert r.status_code == 404
    assert r.json()["error"]["message"] == "model not found"
    assert await balance_of(database, user) == Decimal("1")


async def test_upstream_rejecting_our_credentials_is_not_blamed_on_caller(client, make_user, upstream):
    upstream.on("/v1/chat/completions", httpx.Response(401, json={"error": "bad key"}))
    _, key = await make_user()
    r = await client.post("/v1/chat/completions", json=CHAT, headers=auth(key))
    assert r.status_code == 502
    assert r.json()["error"]["code"] == "upstream_auth_failed"


async def test_upstream_garbage_is_502_and_not_charged(client, make_user, upstream, database):
    upstream.on("/v1/chat/completions", httpx.Response(200, content=b"<html>oops</html>"))
    user, key = await make_user(balance="1")
    r = await client.post("/v1/chat/completions", json=CHAT, headers=auth(key))
    assert r.status_code == 502
    assert await balance_of(database, user) == Decimal("1")


async def test_stream_interrupted_mid_way_is_not_charged(client, make_user, upstream, database):
    class Broken(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b'data: {"id":"c","choices":[{"index":0,"delta":{"content":"x"}}]}\n\n'
            raise httpx.ReadError("connection reset")

    upstream.on(
        "/v1/chat/completions",
        lambda request: httpx.Response(200, stream=Broken(), headers={"content-type": "text/event-stream"}),
    )
    user, key = await make_user(balance="1")
    r = await client.post("/v1/chat/completions", json={**CHAT, "stream": True}, headers=auth(key))
    assert "upstream stream interrupted" in r.text
    assert (await only_tx(database)).status == "failed"
    assert await balance_of(database, user) == Decimal("1")


# ------------------------------------------------------------------ pricing


async def test_token_based_pricing_rule(client, make_user, upstream, database):
    upstream.on("/v1/chat/completions", openai_ok)  # 12 tokens
    await client.put(
        "/admin/api/pricing",
        json={"provider": "openai", "model": "gpt-5", "fee_per_request": "0.01", "fee_per_1k_tokens": "0.5"},
        headers=ADMIN,
    )
    user, key = await make_user(balance="1")
    r = await client.post("/v1/chat/completions", json=CHAT, headers=auth(key))
    # 0.01 + 0.5 * 12 / 1000 = 0.016
    assert r.headers["X-Fee-Charged"] == "0.016000"
    assert await balance_of(database, user) == Decimal("0.984")


async def test_pricing_lookup_prefers_most_specific_rule(client, make_user, upstream):
    upstream.on("/v1/chat/completions", openai_ok)
    upstream.on("/v1/messages", anthropic_ok)
    for rule in (
        {"provider": "*", "model": "*", "fee_per_request": "0.05"},
        {"provider": "openai", "model": "*", "fee_per_request": "0.02"},
        {"provider": "openai", "model": "gpt-5", "fee_per_request": "0.10"},
    ):
        assert (await client.put("/admin/api/pricing", json=rule, headers=ADMIN)).status_code == 200
    _, key = await make_user()

    async def fee(model):
        r = await client.post("/v1/chat/completions", json={**CHAT, "model": model}, headers=auth(key))
        return r.headers["X-Fee-Charged"]

    assert await fee("openai/gpt-5") == "0.100000"
    assert await fee("openai/gpt-5-mini") == "0.020000"
    assert await fee("anthropic/claude-sonnet-5-5") == "0.050000"
