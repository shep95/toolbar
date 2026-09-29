"""Abuse patterns an attacker would try, and the defence for each."""

from __future__ import annotations

import asyncio
import json
import uuid
from decimal import Decimal

import httpx
import pytest
from sqlalchemy import func, select, update

from aiproxy.models import ApiKey, AuditLog, User
from aiproxy.payments import sign_stripe_payload

from .conftest import ADMIN, ADMIN_TOKEN, OPENAI_KEY
from .test_billing_admin_payments import checkout_event
from .test_gateway import CHAT, auth, openai_ok
from .test_providers import balance_of, only_tx, sse_body, sse_response


async def audit_count(database) -> int:
    async with database.session() as s:
        return (await s.execute(select(func.count(AuditLog.id)))).scalar_one()


# ------------------------------------------------------------------ cost amplification


async def test_many_choices_and_premium_tiers_are_refused(client, make_user, upstream):
    upstream.on("/v1/chat/completions", openai_ok)
    _, key = await make_user()
    for extra in ({"n": 64}, {"n": 0}, {"n": "5"}, {"service_tier": "priority"}, {"service_tier": "SCALE"}):
        r = await client.post("/v1/chat/completions", json={**CHAT, **extra}, headers=auth(key))
        assert r.status_code == 400, extra
    r = await client.post("/openai/v1/chat/completions", json={"model": "gpt-5", "messages": [], "n": 10}, headers=auth(key))
    assert r.status_code == 400
    assert upstream.requests == []
    ok = await client.post("/v1/chat/completions", json={**CHAT, "n": 1, "service_tier": "auto"}, headers=auth(key))
    assert ok.status_code == 200


@pytest.mark.parametrize("settings_overrides", [{"max_output_tokens": 1000}])
async def test_output_token_cap(client, make_user, upstream):
    upstream.on("/v1/chat/completions", openai_ok)
    _, key = await make_user()
    r = await client.post("/v1/chat/completions", json={**CHAT, "max_tokens": 50_000}, headers=auth(key))
    assert r.status_code == 400
    r = await client.post("/v1/chat/completions", json=CHAT, headers=auth(key))
    assert r.status_code == 200
    assert json.loads(upstream.requests[-1].content)["max_tokens"] == 1000


# ------------------------------------------------------------------ input validation


async def test_malicious_model_names_are_refused(client, make_user, upstream):
    _, key = await make_user()
    for model in ("openai/gpt-5\r\nX-Evil: 1", "openai/../../admin", "openai/" + "a" * 300, "openai/<script>", "openai/"):
        r = await client.post("/v1/chat/completions", json={**CHAT, "model": model}, headers=auth(key))
        assert r.status_code == 400, model
    assert upstream.requests == []


async def test_json_bomb_is_refused(client, make_user):
    _, key = await make_user()
    bomb = b'{"model":"openai/gpt-5","messages":' + b"[" * 5000 + b"]" * 5000 + b"}"
    r = await client.post("/v1/chat/completions", content=bomb, headers={**auth(key), "Content-Type": "application/json"})
    assert r.status_code == 400


@pytest.mark.parametrize("settings_overrides", [{"body_read_timeout_seconds": 0.2}])
async def test_slow_body_is_cut_off(client, make_user):
    _, key = await make_user()

    async def trickle():
        yield b'{"model": "openai/gpt-5",'
        await asyncio.sleep(1)
        yield b'"messages": []}'

    r = await client.post("/v1/chat/completions", content=trickle(), headers={**auth(key), "Content-Type": "application/json"})
    assert r.status_code == 408


# ------------------------------------------------------------------ information leaks


async def test_upstream_errors_are_scrubbed(client, make_user, upstream):
    leak = {
        "error": {
            "message": f"Rate limit reached for gpt-5 in organization org-AbCdEf123456 on project proj_Zyx987654321. "
                       f"Incorrect API key provided: sk-proj-abcdEFGH1234****wxyz. raw={OPENAI_KEY}",
        }
    }
    upstream.on("/v1/chat/completions", httpx.Response(429, json=leak))
    _, key = await make_user()
    r = await client.post("/v1/chat/completions", json=CHAT, headers=auth(key))
    assert r.status_code == 429
    text = r.text
    for secret in ("org-AbCdEf123456", "proj_Zyx987654321", "sk-proj-abcdEFGH1234", OPENAI_KEY):
        assert secret not in text
    assert "org-***" in text


async def test_stream_error_events_are_scrubbed(client, make_user, upstream):
    body = sse_body((None, {"error": {"message": "quota exceeded for org-AbCdEf123456"}}))
    upstream.on("/v1/chat/completions", sse_response(body))
    _, key = await make_user()
    r = await client.post("/v1/chat/completions", json={**CHAT, "stream": True}, headers=auth(key))
    assert "org-AbCdEf123456" not in r.text and "org-***" in r.text


async def test_operator_key_never_reaches_the_caller(client, make_user, upstream):
    upstream.on("/v1/chat/completions", openai_ok)
    _, key = await make_user()
    r = await client.post("/v1/chat/completions", json=CHAT, headers=auth(key))
    assert OPENAI_KEY not in r.text and OPENAI_KEY not in str(r.headers)


async def test_security_headers_and_docs_disabled(client, make_user):
    _, key = await make_user()
    r = await client.get("/v1/account", headers=auth(key))
    h = r.headers
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-frame-options"] == "DENY"
    assert h["cache-control"] == "no-store"
    assert h["referrer-policy"] == "no-referrer"
    assert "default-src 'none'" in h["content-security-policy"]
    assert "max-age" in h["strict-transport-security"]
    assert (await client.get("/docs")).status_code == 404
    assert (await client.get("/openapi.json")).status_code == 404
    page = await client.get("/admin")
    csp = page.headers["content-security-policy"]
    assert "script-src 'sha256-" in csp and "unsafe-inline' ;" not in csp and "script-src 'unsafe-inline'" not in csp


# ------------------------------------------------------------------ brute force and flooding


@pytest.mark.parametrize("settings_overrides", [{"auth_failures_per_minute_per_ip": 5}])
async def test_key_guessing_gets_blocked_without_touching_the_database(client, make_user, database):
    _, key = await make_user()
    codes = []
    for _ in range(8):
        r = await client.post("/v1/chat/completions", json=CHAT, headers={"Authorization": "Bearer apx_" + "z" * 43})
        codes.append(r.status_code)
    assert codes[:5] == [401] * 5 and codes[5:] == [429] * 3
    before = await audit_count(database)
    r = await client.post("/v1/chat/completions", json=CHAT, headers=auth(key))
    assert r.status_code == 429 and r.json()["error"]["code"] == "auth_failures_blocked"
    assert await audit_count(database) == before  # blocked requests are not stored


@pytest.mark.parametrize("settings_overrides", [{"ip_rate_limit_per_minute": 3}])
async def test_per_ip_limit_applies_before_authentication(client):
    codes = [(await client.get("/v1/account", headers={"Authorization": "Bearer apx_" + "q" * 43})).status_code for _ in range(5)]
    assert codes[-1] == 429


async def test_admin_token_guessing_is_locked_out(client):
    for _ in range(10):
        assert (await client.get("/admin/api/users", headers={"Authorization": "Bearer wrong"})).status_code == 401
    r = await client.get("/admin/api/users", headers=ADMIN)
    assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1


@pytest.mark.parametrize("settings_overrides", [{"admin_allowed_ips": "10.0.0.0/8"}])
async def test_admin_ip_allowlist_hides_admin(client):
    assert (await client.get("/admin/api/users", headers=ADMIN)).status_code == 404
    assert (await client.get("/admin")).status_code == 404


# ------------------------------------------------------------------ cached auth can't outlive revocation


async def test_revocation_and_suspension_apply_immediately_despite_cache(client, make_user, upstream, database):
    upstream.on("/v1/chat/completions", openai_ok)
    user, key = await make_user()
    assert (await client.post("/v1/chat/completions", json=CHAT, headers=auth(key))).status_code == 200  # now cached
    async with database.session() as s, s.begin():  # revoke behind the cache's back (e.g. another instance)
        await s.execute(update(ApiKey).where(ApiKey.id == uuid.UUID(key["id"])).values(status="revoked"))
    r = await client.post("/v1/chat/completions", json=CHAT, headers=auth(key))
    assert r.status_code == 401 and r.json()["error"]["code"] == "key_revoked"

    user2, key2 = await make_user()
    assert (await client.post("/v1/chat/completions", json=CHAT, headers=auth(key2))).status_code == 200
    async with database.session() as s, s.begin():
        await s.execute(update(User).where(User.id == uuid.UUID(user2["id"])).values(status="suspended"))
    r = await client.post("/v1/chat/completions", json=CHAT, headers=auth(key2))
    assert r.status_code == 403
    assert len(upstream.requests) == 2  # neither blocked request reached the provider


async def test_pricing_change_applies_immediately(client, make_user, upstream):
    upstream.on("/v1/chat/completions", openai_ok)
    _, key = await make_user()
    assert (await client.post("/v1/chat/completions", json=CHAT, headers=auth(key))).headers["X-Fee-Charged"] == "0.030000"
    await client.put("/admin/api/pricing", json={"provider": "openai", "fee_per_request": "0.05"}, headers=ADMIN)
    assert (await client.post("/v1/chat/completions", json=CHAT, headers=auth(key))).headers["X-Fee-Charged"] == "0.050000"


# ------------------------------------------------------------------ free-ride attempts


async def test_hanging_up_after_the_provider_is_called_is_still_charged(client, make_user, upstream, database):
    started = asyncio.Event()

    async def slow(request):
        started.set()
        await asyncio.sleep(10)
        return openai_ok(request)

    upstream.on("/v1/chat/completions", slow)
    user, key = await make_user(balance="1")
    task = asyncio.create_task(client.post("/v1/chat/completions", json=CHAT, headers=auth(key)))
    await asyncio.wait_for(started.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    tx = await only_tx(database)
    assert tx.status == "success" and Decimal(tx.fee_charged) == Decimal("0.03")
    assert await balance_of(database, user) == Decimal("0.97")


@pytest.mark.parametrize("settings_overrides", [{"max_upstream_response_bytes": 1000}])
async def test_oversized_upstream_response_is_refused_and_refunded(client, make_user, upstream, database):
    upstream.on("/v1/chat/completions", httpx.Response(200, content=b'{"x":"' + b"a" * 5000 + b'"}'))
    user, key = await make_user(balance="1")
    r = await client.post("/v1/chat/completions", json=CHAT, headers=auth(key))
    assert r.status_code == 502
    assert await balance_of(database, user) == Decimal("1")


# ------------------------------------------------------------------ payments


async def test_stripe_discount_cannot_over_credit(client, make_user, database):
    user, _ = await make_user(balance="0")
    event = json.loads(checkout_event(user["id"], session_id="cs_discount", cents=2000))
    event["data"]["object"]["amount_total"] = 500  # $20 of credit bought for $5 with a coupon
    payload = json.dumps(event).encode()
    r = await client.post("/stripe/webhook", content=payload, headers={"Stripe-Signature": sign_stripe_payload(payload, "whsec_test")})
    assert r.json()["credited"] == "5"
    assert await balance_of(database, user) == Decimal("5")


async def test_stripe_webhook_size_limit(client):
    payload = b"{" + b" " * 1_100_000 + b"}"
    r = await client.post("/stripe/webhook", content=payload, headers={"Stripe-Signature": sign_stripe_payload(payload, "whsec_test")})
    assert r.status_code == 413


async def test_admin_bearer_is_compared_exactly(client):
    for token in (ADMIN_TOKEN.upper(), ADMIN_TOKEN + "x", ADMIN_TOKEN[:-1], ADMIN_TOKEN[:-1] + "y", ""):
        r = await client.get("/admin/api/users", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401
