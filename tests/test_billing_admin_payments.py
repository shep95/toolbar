"""Billing guarantees, admin layer and Stripe top-ups."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
import uuid
from datetime import timedelta
from decimal import Decimal
from urllib.parse import parse_qs

import httpx
import pytest
from sqlalchemy import select

from aiproxy.connectors import Usage
from aiproxy.models import ApiKey, BalanceAdjustment, Transaction, User, utcnow
from aiproxy.payments import sign_stripe_payload, verify_stripe_signature

from .conftest import ADMIN, ADMIN_TOKEN
from .test_gateway import CHAT, auth, openai_ok
from .test_providers import balance_of

# ------------------------------------------------------------------ billing


async def test_concurrent_requests_cannot_overspend(client, make_user, upstream, database):
    async def slow_ok(request):
        await asyncio.sleep(0.05)
        return openai_ok(request)

    upstream.on("/v1/chat/completions", slow_ok)
    user, key = await make_user(balance="0.09")  # exactly three requests
    results = await asyncio.gather(
        *[client.post("/v1/chat/completions", json=CHAT, headers=auth(key)) for _ in range(8)]
    )
    codes = sorted(r.status_code for r in results)
    assert codes == [200] * 3 + [402] * 5
    assert len(upstream.requests) == 3
    assert await balance_of(database, user) == Decimal("0")


async def test_settlement_happens_once(app, make_user, database):
    user, key = await make_user(balance="1")
    billing = app.state.services.billing
    reservation = await billing.reserve(
        user_id=uuid.UUID(user["id"]), api_key_id=uuid.UUID(key["id"]), provider="openai",
        model="gpt-5", endpoint="chat/completions", request_id="r1",
    )
    assert reservation.balance_after == Decimal("0.97")
    assert await billing.fail(reservation) is True
    assert await billing.fail(reservation) is False  # no double refund
    settled = await billing.complete(reservation, usage=Usage(), model=None, upstream_status=200, latency_ms=1)
    assert settled.applied is False  # cannot charge a refunded transaction
    assert await balance_of(database, user) == Decimal("1")


async def test_reconciler_refunds_abandoned_pending(app, make_user, database):
    user, key = await make_user(balance="1")
    billing = app.state.services.billing
    reservation = await billing.reserve(
        user_id=uuid.UUID(user["id"]), api_key_id=uuid.UUID(key["id"]), provider="openai",
        model="gpt-5", endpoint="chat/completions", request_id="r1",
    )
    assert await balance_of(database, user) == Decimal("0.97")
    assert await billing.reconcile_stale(timedelta(minutes=60)) == 0  # too fresh
    assert await billing.reconcile_stale(timedelta(minutes=60), now=utcnow() + timedelta(hours=2)) == 1
    assert await balance_of(database, user) == Decimal("1")
    async with database.session() as s:
        tx = await s.get(Transaction, reservation.transaction_id)
    assert tx.status == "error" and Decimal(tx.fee_charged) == 0
    # A stream that finishes after the sweep does not charge.
    late = await billing.complete(reservation, usage=Usage(), model=None, upstream_status=200, latency_ms=1)
    assert late.applied is False


# ------------------------------------------------------------------ admin


async def test_admin_requires_its_own_token(client, make_user):
    _, key = await make_user()
    assert (await client.get("/admin/api/users")).status_code == 401
    assert (await client.get("/admin/api/users", headers=auth(key))).status_code == 401
    assert (await client.get("/admin/api/users", headers={"Authorization": "Bearer " + ADMIN_TOKEN[:-1]})).status_code == 401
    # ...and the admin token cannot be used to proxy traffic.
    r = await client.post("/v1/chat/completions", json=CHAT, headers=ADMIN)
    assert r.status_code == 401


async def test_admin_disabled_without_strong_token(database, upstream):
    from aiproxy.main import create_app

    from .conftest import make_settings

    app = create_app(make_settings(admin_api_token="short"), database=database, run_reconciler=False,
                     http_client=httpx.AsyncClient(transport=httpx.MockTransport(upstream)))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://p.test") as c:
            r = await c.get("/admin/api/users", headers={"Authorization": "Bearer short"})
    assert r.status_code == 503


async def test_raw_key_is_shown_once_and_only_hash_is_stored(client, make_user, database):
    user, key = await make_user()
    raw = key["api_key"]
    assert raw.startswith("apx_") and len(raw) == 47
    listed = (await client.get(f"/admin/api/users/{user['id']}/keys", headers=ADMIN)).json()
    assert "api_key" not in listed[0] and raw not in json.dumps(listed)
    async with database.session() as s:
        stored = (await s.execute(select(ApiKey))).scalar_one()
    assert stored.key_hash == hashlib.sha256(raw.encode()).hexdigest()
    assert stored.key_prefix == raw[:12]


async def test_admin_user_lifecycle_and_credits(client):
    r = await client.post("/admin/api/users", json={"email": "A@Example.com", "initial_balance": "2"}, headers=ADMIN)
    assert r.status_code == 201
    user = r.json()
    assert user["email"] == "a@example.com" and user["balance"] == "2.000000"
    assert (await client.post("/admin/api/users", json={"email": "a@example.com"}, headers=ADMIN)).status_code == 409
    assert (await client.post("/admin/api/users", json={"email": "not-an-email"}, headers=ADMIN)).status_code == 422

    r = await client.post(f"/admin/api/users/{user['id']}/credits", json={"amount": "3.5", "note": "promo"}, headers=ADMIN)
    assert r.json()["balance"] == "5.500000"
    detail = (await client.get(f"/admin/api/users/{user['id']}", headers=ADMIN)).json()
    assert [a["amount"] for a in detail["balance_adjustments"]] == ["3.500000", "2.000000"] or \
        sorted(a["amount"] for a in detail["balance_adjustments"]) == ["2.000000", "3.500000"]

    assert (await client.post(f"/admin/api/users/{user['id']}/keys", json={"provider": "bogus"}, headers=ADMIN)).status_code == 422
    assert (await client.get(f"/admin/api/users/{uuid.uuid4()}", headers=ADMIN)).status_code == 404
    found = (await client.get("/admin/api/users", params={"q": "example"}, headers=ADMIN)).json()
    assert [u["id"] for u in found] == [user["id"]]


async def test_admin_usage_views(client, make_user, upstream):
    upstream.on("/v1/chat/completions", openai_ok)
    user, key = await make_user(balance="1")
    for _ in range(2):
        await client.post("/v1/chat/completions", json=CHAT, headers=auth(key))
    await client.post("/v1/chat/completions", json=CHAT, headers={"Authorization": "Bearer apx_" + "a" * 43})

    overview = (await client.get("/admin/api/overview", headers=ADMIN)).json()
    assert overview["last_24h"] == {
        "requests": 2, "successful": 2, "revenue": "0.060000", "tokens": 24,
        "transactions": 0, "transaction_revenue": "0.000000", "total_revenue": "0.060000",
    }
    assert overview["providers"]["openai"]["configured"] is True
    assert "sk-" not in json.dumps(overview)

    usage = (await client.get("/admin/api/usage", params={"days": 7}, headers=ADMIN)).json()
    assert usage["daily"][0]["provider"] == "openai" and usage["daily"][0]["revenue"] == "0.060000"
    assert usage["top_users"][0]["email"] == user["email"]

    txs = (await client.get("/admin/api/transactions", params={"user_id": user["id"]}, headers=ADMIN)).json()
    assert len(txs) == 2 and {t["status"] for t in txs} == {"success"}

    audit = (await client.get("/admin/api/audit", headers=ADMIN)).json()
    assert audit[0]["outcome"] == "invalid_key" and audit[0]["status_code"] == 401

    assert (await client.get("/admin", headers={})).status_code == 200  # dashboard shell


async def test_admin_pricing_crud(client):
    r = await client.put("/admin/api/pricing", json={"provider": "anthropic", "fee_per_request": "0.04"}, headers=ADMIN)
    rule = r.json()
    assert rule["model"] == "*"
    r = await client.put("/admin/api/pricing", json={"provider": "anthropic", "fee_per_request": "0.05"}, headers=ADMIN)
    assert r.json()["id"] == rule["id"]  # upsert, not duplicate
    listed = (await client.get("/admin/api/pricing", headers=ADMIN)).json()
    assert listed["default_fee_per_request"] == "0.030000"
    assert [x["fee_per_request"] for x in listed["rules"]] == ["0.050000"]
    assert (await client.put("/admin/api/pricing", json={"provider": "nope", "fee_per_request": "1"}, headers=ADMIN)).status_code == 422
    assert (await client.put("/admin/api/pricing", json={"provider": "openai", "fee_per_request": "-1"}, headers=ADMIN)).status_code == 422
    assert (await client.delete(f"/admin/api/pricing/{rule['id']}", headers=ADMIN)).status_code == 200


# ------------------------------------------------------------------ Stripe


def test_stripe_signature_verification():
    payload = b'{"id":"evt_1"}'
    header = sign_stripe_payload(payload, "whsec_test")
    assert verify_stripe_signature(payload, header, "whsec_test")
    assert not verify_stripe_signature(payload + b" ", header, "whsec_test")
    assert not verify_stripe_signature(payload, header, "whsec_other")
    old = sign_stripe_payload(payload, "whsec_test", timestamp=int(time.time()) - 3600)
    assert not verify_stripe_signature(payload, old, "whsec_test")
    assert not verify_stripe_signature(payload, "garbage", "whsec_test")


def checkout_event(user_id: str, session_id: str = "cs_test_1", cents: int = 2000) -> bytes:
    return json.dumps(
        {
            "id": "evt_" + session_id,
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": session_id,
                    "client_reference_id": user_id,
                    "payment_status": "paid",
                    "currency": "usd",
                    "amount_subtotal": cents,
                    "amount_total": cents,
                    "metadata": {"purpose": "aiproxy_topup", "user_id": user_id},
                }
            },
        }
    ).encode()


async def test_stripe_webhook_credits_exactly_once(client, make_user, database):
    user, _ = await make_user(balance="1")
    payload = checkout_event(user["id"])
    headers = {"Stripe-Signature": sign_stripe_payload(payload, "whsec_test"), "Content-Type": "application/json"}
    r = await client.post("/stripe/webhook", content=payload, headers=headers)
    assert r.json() == {"received": True, "credited": "20"}
    r = await client.post("/stripe/webhook", content=payload, headers=headers)
    assert r.json()["duplicate"] is True
    assert await balance_of(database, user) == Decimal("21")
    async with database.session() as s:
        rows = (await s.execute(select(BalanceAdjustment).where(BalanceAdjustment.source == "stripe"))).scalars().all()
    assert [r.external_id for r in rows] == ["cs_test_1"]


async def test_stripe_webhook_rejects_bad_signature(client, make_user, database):
    user, _ = await make_user(balance="1")
    payload = checkout_event(user["id"])
    r = await client.post("/stripe/webhook", content=payload, headers={"Stripe-Signature": sign_stripe_payload(payload, "wrong")})
    assert r.status_code == 400
    assert await balance_of(database, user) == Decimal("1")


async def test_stripe_webhook_ignores_unknown_user(client):
    payload = checkout_event(str(uuid.uuid4()))
    r = await client.post("/stripe/webhook", content=payload, headers={"Stripe-Signature": sign_stripe_payload(payload, "whsec_test")})
    assert r.json()["ignored"] == "unknown user"


async def test_checkout_session_creation(client, make_user, upstream):
    captured = {}

    def stripe(request: httpx.Request):
        captured["form"] = parse_qs(request.content.decode())
        captured["auth"] = request.headers["authorization"]
        return httpx.Response(200, json={"id": "cs_1", "url": "https://checkout.stripe.test/cs_1"})

    upstream.on("/v1/checkout/sessions", stripe)
    user, key = await make_user()
    r = await client.post("/v1/billing/checkout", json={"amount_usd": 25}, headers=auth(key))
    assert r.status_code == 200, r.text
    assert r.json()["checkout_url"] == "https://checkout.stripe.test/cs_1"
    form = captured["form"]
    assert form["line_items[0][price_data][unit_amount]"] == ["2500"]
    assert form["client_reference_id"] == [user["id"]]
    assert captured["auth"] == "Bearer sk_test_stripe"
    for bad in (1, 5000, "abc", 10.001):
        r = await client.post("/v1/billing/checkout", json={"amount_usd": bad}, headers=auth(key))
        assert r.status_code == 400, bad


async def test_user_model_rejects_money_as_float_drift(database):
    # Balances are NUMERIC, so repeated small charges do not drift.
    async with database.session() as s, s.begin():
        user = User(email="drift@example.com", balance=Decimal("0"))
        s.add(user)
    for _ in range(100):
        async with database.session() as s, s.begin():
            u = await s.get(User, user.id)
            u.balance = Decimal(u.balance) + Decimal("0.03")
    async with database.session() as s:
        assert Decimal((await s.get(User, user.id)).balance) == Decimal("3.00")


async def test_checkout_return_pages(client, database):
    ok = await client.get("/billing/success", params={"session_id": "cs_test_<script>alert(1)</script>"})
    assert ok.status_code == 200 and "Payment received" in ok.text
    assert "<script>" not in ok.text  # the page never echoes the URL
    assert "default-src 'none'" in ok.headers["content-security-policy"]
    cancel = await client.get("/billing/cancel")
    assert cancel.status_code == 200 and "No payment was taken" in cancel.text
    async with database.session() as s:  # visiting the page never credits anything
        assert (await s.execute(select(BalanceAdjustment))).scalars().all() == []


@pytest.mark.parametrize("settings_overrides", [{"stripe_secret_key": None}])
async def test_webhook_credits_with_only_the_signing_secret(client, make_user, database):
    user, key = await make_user(balance="0")
    payload = checkout_event(user["id"], session_id="cs_only_whsec")
    r = await client.post("/stripe/webhook", content=payload, headers={"Stripe-Signature": sign_stripe_payload(payload, "whsec_test")})
    assert r.json()["credited"] == "20"
    # Starting a checkout still needs the API key.
    r = await client.post("/v1/billing/checkout", json={"amount_usd": 10}, headers=auth(key))
    assert r.status_code == 503


async def test_other_stripe_sales_are_ignored(client, make_user, database):
    user, _ = await make_user(balance="0")
    event = json.loads(checkout_event(user["id"], session_id="cs_other_product"))
    event["data"]["object"]["metadata"] = {"order": "t-shirt"}  # a sale from another product on the same account
    payload = json.dumps(event).encode()
    r = await client.post("/stripe/webhook", content=payload, headers={"Stripe-Signature": sign_stripe_payload(payload, "whsec_test")})
    assert r.status_code == 200 and r.json()["ignored"] == "not a paid top-up"
    assert await balance_of(database, user) == Decimal("0")


async def test_local_currency_payment_is_credited_in_usd(client, make_user, database):
    user, _ = await make_user(balance="0")
    event = json.loads(checkout_event(user["id"], session_id="cs_inr", cents=2000))
    event["data"]["object"]["presentment_details"] = {"presentment_amount": 165000, "presentment_currency": "inr"}
    payload = json.dumps(event).encode()
    r = await client.post("/stripe/webhook", content=payload, headers={"Stripe-Signature": sign_stripe_payload(payload, "whsec_test")})
    assert r.json()["credited"] == "20"
    detail = (await client.get(f"/admin/api/users/{user['id']}", headers=ADMIN)).json()
    assert "customer paid 1650.00 INR" in detail["balance_adjustments"][0]["note"]


async def test_admin_stripe_test_checkout(client, upstream):
    captured = {}

    def stripe(request: httpx.Request):
        captured["form"] = parse_qs(request.content.decode())
        return httpx.Response(200, json={"id": "cs_test", "url": "https://checkout.stripe.com/c/pay/cs_test"})

    upstream.on("/v1/checkout/sessions", stripe)
    r = (await client.post("/admin/api/stripe/test-checkout", headers=ADMIN)).json()
    assert r == {"ok": True, "checkout_url": "https://checkout.stripe.com/c/pay/cs_test", "session_id": "cs_test"}
    assert captured["form"]["metadata[purpose]"] == ["admin_test"]  # a paid test credits no one
    assert "client_reference_id" not in captured["form"]
    assert (await client.post("/admin/api/stripe/test-checkout")).status_code == 401

    upstream.on("/v1/checkout/sessions", httpx.Response(403, json={"error": {"message": "The provided key does not have the required permissions"}}))
    r = (await client.post("/admin/api/stripe/test-checkout", headers=ADMIN)).json()
    assert r["ok"] is False and "required permissions" in r["reason"]


@pytest.mark.parametrize("settings_overrides", [{"stripe_secret_key": None}])
async def test_admin_stripe_test_reports_missing_key(client):
    r = (await client.post("/admin/api/stripe/test-checkout", headers=ADMIN)).json()
    assert r == {"ok": False, "reason": "missing Railway variable: STRIPE_SECRET_KEY"}
