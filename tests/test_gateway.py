"""Gateway: authentication, rejection paths and the failure model."""

from __future__ import annotations

import httpx
from sqlalchemy import select

from aiproxy.models import AuditLog, Transaction
from aiproxy.security import generate_api_key

from .conftest import ADMIN, OPENAI_KEY

CHAT = {"model": "openai/gpt-5", "messages": [{"role": "user", "content": "hi"}]}


def openai_ok(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "model": "gpt-5",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "hello"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 7, "total_tokens": 12},
        },
    )


def auth(key: dict) -> dict:
    return {"Authorization": f"Bearer {key['api_key']}"}


async def audit_outcomes(database) -> list[str]:
    async with database.session() as s:
        return [r.outcome for r in (await s.execute(select(AuditLog).order_by(AuditLog.id))).scalars()]


async def test_health(client):
    assert (await client.get("/healthz")).json() == {"ok": True}
    assert (await client.get("/readyz")).json()["database"] == "up"


async def test_plain_http_is_rejected(app, make_user):
    _, key = await make_user()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy.test") as plain:
        r = await plain.post("/v1/chat/completions", json=CHAT, headers=auth(key))
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "https_required"
        # Health checks still work over HTTP for the platform's probes.
        assert (await plain.get("/healthz")).status_code == 200


async def test_forwarded_proto_https_is_accepted(app, make_user, upstream):
    upstream.on("/v1/chat/completions", openai_ok)
    _, key = await make_user()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy.test") as behind_proxy:
        r = await behind_proxy.post(
            "/v1/chat/completions", json=CHAT, headers={**auth(key), "X-Forwarded-Proto": "https"}
        )
    assert r.status_code == 200
    assert "strict-transport-security" in r.headers


async def test_missing_key(client, upstream, database):
    r = await client.post("/v1/chat/completions", json=CHAT)
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "missing_key"
    assert upstream.requests == []
    assert await audit_outcomes(database) == ["missing_key"]


async def test_unknown_key_is_401_and_logged(client, upstream, database):
    r = await client.post("/v1/chat/completions", json=CHAT, headers={"Authorization": f"Bearer {generate_api_key()}"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "invalid_key"
    assert upstream.requests == []
    assert await audit_outcomes(database) == ["invalid_key"]


async def test_provider_key_injection_is_rejected(client, upstream, database):
    for smuggled in ("sk-ant-api03-abcdefghijklmnopqrstuvwxyz", "sk-proj-abcdefghijklmnopqrstuvwxyz123456"):
        r = await client.post("/v1/chat/completions", json=CHAT, headers={"Authorization": f"Bearer {smuggled}"})
        assert r.status_code == 401
        assert r.json()["error"]["code"] == "upstream_key_rejected"
    assert upstream.requests == []
    assert await audit_outcomes(database) == ["upstream_key_rejected", "upstream_key_rejected"]


async def test_two_different_credentials_are_rejected(client, make_user, upstream):
    _, key = await make_user()
    r = await client.post(
        "/v1/chat/completions",
        json=CHAT,
        headers={**auth(key), "x-api-key": "sk-ant-api03-smuggled-provider-key"},
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "conflicting_credentials"
    assert upstream.requests == []


async def test_client_headers_never_reach_upstream(client, make_user, upstream):
    upstream.on("/v1/chat/completions", openai_ok)
    _, key = await make_user()
    r = await client.post(
        "/v1/chat/completions", json=CHAT, headers={**auth(key), "OpenAI-Organization": "org-evil", "Cookie": "a=b"}
    )
    assert r.status_code == 200
    sent = upstream.requests[0]
    assert sent.headers["authorization"] == f"Bearer {OPENAI_KEY}"
    assert "openai-organization" not in sent.headers
    assert "cookie" not in sent.headers
    assert key["api_key"] not in str(sent.headers)


async def test_revoked_key(client, make_user, upstream):
    _, key = await make_user()
    assert (await client.delete(f"/admin/api/keys/{key['id']}", headers=ADMIN)).status_code == 200
    r = await client.post("/v1/chat/completions", json=CHAT, headers=auth(key))
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "key_revoked"
    assert upstream.requests == []


async def test_suspended_user(client, make_user, upstream, database):
    user, key = await make_user()
    await client.patch(f"/admin/api/users/{user['id']}", json={"status": "suspended"}, headers=ADMIN)
    r = await client.post("/v1/chat/completions", json=CHAT, headers=auth(key))
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "user_suspended"
    assert upstream.requests == []
    assert "user_suspended" in await audit_outcomes(database)


async def test_zero_balance_is_402_and_not_forwarded(client, make_user, upstream, database):
    _, key = await make_user(balance="0")
    r = await client.post("/v1/chat/completions", json=CHAT, headers=auth(key))
    assert r.status_code == 402
    assert r.json()["error"]["code"] == "insufficient_balance"
    assert upstream.requests == []
    async with database.session() as s:
        assert (await s.execute(select(Transaction))).scalars().all() == []


async def test_balance_below_fee_is_402(client, make_user, upstream):
    _, key = await make_user(balance="0.02")
    r = await client.post("/v1/chat/completions", json=CHAT, headers=auth(key))
    assert r.status_code == 402
    assert upstream.requests == []


async def test_key_restricted_to_other_provider(client, make_user, upstream):
    _, key = await make_user(provider="openai")
    body = {**CHAT, "model": "anthropic/claude-sonnet-5-5"}
    r = await client.post("/v1/chat/completions", json=body, headers=auth(key))
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "key_provider_mismatch"
    r = await client.post("/anthropic/v1/messages", json={"model": "x"}, headers={"x-api-key": key["api_key"]})
    assert r.status_code == 403
    assert upstream.requests == []


async def test_bound_key_may_omit_provider_prefix(client, make_user, upstream):
    upstream.on("/v1/chat/completions", openai_ok)
    _, key = await make_user(provider="openai")
    r = await client.post("/v1/chat/completions", json={**CHAT, "model": "gpt-5"}, headers=auth(key))
    assert r.status_code == 200
    assert upstream.json_body()["model"] == "gpt-5"


async def test_any_key_needs_provider_prefix(client, make_user, upstream):
    _, key = await make_user(provider="any")
    r = await client.post("/v1/chat/completions", json={**CHAT, "model": "gpt-5"}, headers=auth(key))
    assert r.status_code == 400
    assert upstream.requests == []


async def test_rate_limit_per_key(client, make_user, upstream):
    upstream.on("/v1/chat/completions", openai_ok)
    _, key = await make_user(rate_limit_per_minute=3)
    _, other = await make_user()
    codes = [(await client.post("/v1/chat/completions", json=CHAT, headers=auth(key))).status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    r = await client.post("/v1/chat/completions", json=CHAT, headers=auth(key))
    assert int(r.headers["Retry-After"]) >= 1
    assert r.json()["error"]["code"] == "rate_limited"
    # Other keys are unaffected.
    assert (await client.post("/v1/chat/completions", json=CHAT, headers=auth(other))).status_code == 200
    assert len(upstream.requests) == 4


async def test_invalid_json_and_oversized_body(client, make_user, app, upstream):
    _, key = await make_user()
    r = await client.post("/v1/chat/completions", content=b"{nope", headers={**auth(key), "Content-Type": "application/json"})
    assert r.status_code == 400
    r = await client.post("/v1/chat/completions", json={"model": "openai/gpt-5", "messages": []}, headers=auth(key))
    assert r.status_code == 400
    app.state.services.settings.max_request_bytes = 100
    r = await client.post("/v1/chat/completions", json={**CHAT, "pad": "x" * 200}, headers=auth(key))
    assert r.status_code == 413
    assert upstream.requests == []


async def test_provider_not_configured(client, make_user, app, upstream):
    _, key = await make_user()
    app.state.services.connectors["mistral"]._api_key = None
    r = await client.post("/v1/chat/completions", json={**CHAT, "model": "mistral/mistral-large"}, headers=auth(key))
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "provider_not_configured"
    assert upstream.requests == []


async def test_database_down_returns_503_and_nothing_goes_upstream(client, make_user, app, upstream):
    from sqlalchemy.ext.asyncio import create_async_engine

    from aiproxy.db import Database

    _, key = await make_user()
    services = app.state.services
    broken = Database(create_async_engine("postgresql+asyncpg://nobody@127.0.0.1:1/none", connect_args={"timeout": 1}))
    services.db = broken
    services.billing.db = broken
    try:
        r = await client.post("/v1/chat/completions", json=CHAT, headers=auth(key))
        assert r.status_code == 503
        assert r.json()["error"]["code"] == "database_unavailable"
        assert upstream.requests == []
        assert (await client.get("/readyz")).status_code == 503
    finally:
        await broken.dispose()


async def test_account_endpoint(client, make_user):
    user, key = await make_user(balance="4.5", name="laptop")
    r = await client.get("/v1/account", headers=auth(key))
    assert r.status_code == 200
    data = r.json()
    assert data["balance"] == "4.500000"
    assert data["key"]["name"] == "laptop"
    assert data["key"]["prefix"] == key["api_key"][:12]


async def test_bad_key_flood_does_not_fill_audit_table(client, app, database, make_user, upstream):
    upstream.on("/v1/chat/completions", openai_ok)
    app.state.services.settings.audit_auth_failures_per_minute_per_ip = 3
    for _ in range(10):
        r = await client.post("/v1/chat/completions", json=CHAT, headers={"Authorization": "Bearer apx_" + "b" * 43})
        assert r.status_code == 401
    assert await audit_outcomes(database) == ["invalid_key"] * 3
    # A valid key from the same address still works.
    _, key = await make_user()
    assert (await client.post("/v1/chat/completions", json=CHAT, headers=auth(key))).status_code == 200


async def test_unexpected_error_after_reservation_refunds_immediately(client, app, make_user, upstream, database):
    from decimal import Decimal

    from .test_providers import balance_of, only_tx

    def boom(data):
        raise RuntimeError("bug in a connector")

    upstream.on("/v1/chat/completions", openai_ok)
    user, key = await make_user(balance="1")
    app.state.services.connectors["openai"].extract_usage = boom
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="https://proxy.test") as real_server:
        r = await real_server.post("/v1/chat/completions", json=CHAT, headers=auth(key))
    assert r.status_code == 500
    assert (await only_tx(database)).status == "error"
    assert await balance_of(database, user) == Decimal("1")
