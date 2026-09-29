"""Transaction domains: AI APIs, brokerage, crypto, payments, remittance, commerce, digital goods."""

from __future__ import annotations

import uuid
from decimal import Decimal

import pytest

from aiproxy.domains import DOMAINS
from aiproxy.models import Charge

from .conftest import ADMIN
from .test_gateway import CHAT, auth, openai_ok

# One realistic transaction per domain.
SAMPLES = {
    "general": {"type": "booking", "attributes": None},
    "ai": {"type": "completion", "attributes": {"provider": "self-hosted", "model": "llama-4-70b", "input_tokens": 812, "output_tokens": 240}},
    "brokerage": {"type": "buy", "attributes": {"symbol": "aapl", "asset_class": "stock", "quantity": "10", "price": "227.52", "order_type": "limit"}},
    "crypto": {"type": "onramp", "attributes": {"asset": "btc", "quantity": "0.0021", "network": "Bitcoin", "wallet_address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"}},
    "payments": {"type": "charge", "attributes": {"method": "card", "card_brand": "visa", "counterparty": "Coffee Shop"}},
    "remittance": {"type": "send", "attributes": {"destination_country": "ph", "destination_currency": "php", "channel": "mobile_money"}},
    "commerce": {"type": "order", "attributes": {"items": 3, "merchant": "Blue Shirts Ltd", "sku": "BS-1"}},
    "digital_goods": {"type": "in_app", "attributes": {"sku": "gems_500", "platform": "ios", "title": "500 Gems"}},
}


def body(domain: str | None = None, reference: str | None = None, **overrides) -> dict:
    sample = SAMPLES[domain or "general"]
    out = {"reference": reference or f"ref-{uuid.uuid4().hex[:10]}", "type": sample["type"], "amount": "25", "currency": "USD"}
    if domain:
        out["domain"] = domain
    if sample["attributes"]:
        out["attributes"] = dict(sample["attributes"])
    out.update(overrides)
    return out


def test_every_domain_has_a_sample():
    assert set(SAMPLES) == set(DOMAINS)


@pytest.mark.parametrize("domain", sorted(SAMPLES))
async def test_every_domain_records_and_charges(client, make_user, domain):
    _, key = await make_user(balance="1")
    r = await client.post("/v1/transactions", json=body(domain), headers=auth(key))
    assert r.status_code == 201, r.text
    data = r.json()
    assert data["domain"] == domain and data["fee"]["amount_usd"] == "0.030000"
    if SAMPLES[domain]["attributes"]:
        assert set(data["attributes"]) == set(SAMPLES[domain]["attributes"])


async def test_brokerage_trade_is_normalised(client, make_user):
    _, key = await make_user()
    r = await client.post("/v1/transactions", json=body("brokerage"), headers=auth(key))
    attrs = r.json()["attributes"]
    assert attrs["symbol"] == "AAPL" and attrs["quantity"] == "10" and attrs["price"] == "227.52"


async def test_crypto_onramp_is_normalised(client, make_user):
    _, key = await make_user()
    r = await client.post("/v1/transactions", json=body("crypto"), headers=auth(key))
    attrs = r.json()["attributes"]
    assert attrs["asset"] == "BTC" and attrs["network"] == "bitcoin"


@pytest.mark.parametrize(
    "domain, overrides, needle",
    [
        ("brokerage", {"attributes": {"quantity": "1"}}, "needs: symbol"),
        ("brokerage", {"attributes": {"symbol": "AAPL", "quantity": "0"}}, "positive"),
        ("brokerage", {"attributes": {"symbol": "AAPL", "quantity": "1", "leverage": 10}}, "unknown brokerage attributes"),
        ("brokerage", {"type": "mint"}, "not a brokerage transaction type"),
        ("brokerage", {"type": None}, "'type' is required"),
        ("crypto", {"type": "swap", "attributes": {"asset": "ETH"}}, "needs: to_asset"),
        ("crypto", {"attributes": {"asset": "BTC", "tx_hash": "not a hash!"}}, "invalid format"),
        ("crypto", {"attributes": {"asset": "BTC", "network": "Ethereum Mainnet"}}, "invalid format"),
        ("remittance", {"attributes": {"destination_currency": "PHP"}}, "needs: destination_country"),
        ("remittance", {"attributes": {"destination_country": "Philippines"}}, "ISO"),
        ("payments", {"attributes": {"method": "barter"}}, "must be one of"),
        ("commerce", {"attributes": {"items": 0}}, "at least 1"),
        ("digital_goods", {"attributes": "gems"}, "must be an object"),
        ("space_travel", {}, "'domain' must be one of"),
    ],
)
async def test_domain_validation(client, make_user, database, domain, overrides, needle):
    user, key = await make_user(balance="1")
    payload = body(domain if domain in SAMPLES else None, **overrides)
    if domain not in SAMPLES:
        payload["domain"] = domain
    if payload.get("type") is None:
        payload.pop("type")
    r = await client.post("/v1/transactions", json=payload, headers=auth(key))
    assert r.status_code == 400, r.text
    assert needle in r.json()["error"]["message"]
    from .test_providers import balance_of

    assert await balance_of(database, user) == Decimal("1")  # nothing charged


async def test_same_reference_with_different_attributes_conflicts(client, make_user):
    _, key = await make_user()
    first = body("brokerage", reference="trade-1")
    assert (await client.post("/v1/transactions", json=first, headers=auth(key))).status_code == 201
    assert (await client.post("/v1/transactions", json=first, headers=auth(key))).status_code == 200
    changed = {**first, "attributes": {**first["attributes"], "quantity": "11"}}
    assert (await client.post("/v1/transactions", json=changed, headers=auth(key))).status_code == 409


# ------------------------------------------------------------------ keys locked to a domain


async def test_domain_locked_key(client, make_user, upstream):
    upstream.on("/v1/chat/completions", openai_ok)
    _, key = await make_user(domain="crypto")
    assert key["domain"] == "crypto"
    implicit = body("crypto")
    implicit.pop("domain")  # a crypto key defaults to its own domain
    r = await client.post("/v1/transactions", json=implicit, headers=auth(key))
    assert r.status_code == 201 and r.json()["domain"] == "crypto"
    r = await client.post("/v1/transactions", json=body("brokerage"), headers=auth(key))
    assert r.status_code == 403 and r.json()["error"]["code"] == "key_domain_mismatch"
    for method, path, payload in (
        ("post", "/v1/chat/completions", CHAT),
        ("post", "/openai/v1/chat/completions", {"model": "gpt-5", "messages": []}),
        ("get", "/v1/models", None),
        ("get", "/v1/providers", None),
    ):
        r = await getattr(client, method)(path, headers=auth(key), **({"json": payload} if payload else {}))
        assert r.status_code == 403, path
    assert upstream.requests == []  # a crypto key never spends on AI providers
    listed = (await client.get("/v1/domains", headers=auth(key))).json()["data"]
    assert [d["name"] for d in listed] == ["crypto"]


async def test_ai_locked_key_can_use_gateway(client, make_user, upstream):
    upstream.on("/v1/chat/completions", openai_ok)
    _, key = await make_user(domain="ai")
    assert (await client.post("/v1/chat/completions", json=CHAT, headers=auth(key))).status_code == 200
    assert (await client.post("/v1/transactions", json=body("ai"), headers=auth(key))).status_code == 201


async def test_unknown_domain_for_key_is_refused(client, make_user):
    user, _ = await make_user()
    r = await client.post(f"/admin/api/users/{user['id']}/keys", json={"domain": "space"}, headers=ADMIN)
    assert r.status_code == 422


# ------------------------------------------------------------------ pricing per domain


async def test_domain_and_type_pricing_with_country(client, make_user):
    user, key = await make_user(balance="5")
    for rule in (
        {"provider": "brokerage", "model": "*", "fee_per_request": "0.05"},
        {"provider": "crypto", "model": "onramp", "fee_per_request": "0.10"},
    ):
        assert (await client.put("/admin/api/pricing", json=rule, headers=ADMIN)).status_code == 200

    async def fee(domain, **overrides):
        r = await client.post("/v1/transactions", json=body(domain, **overrides), headers=auth(key))
        assert r.status_code == 201, r.text
        return r.json()["fee"]["amount_usd"]

    assert await fee("brokerage") == "0.050000"
    assert await fee("crypto") == "0.100000"  # onramp
    assert await fee("crypto", type="send") == "0.030000"
    assert await fee("payments") == "0.030000"
    await client.patch(f"/admin/api/users/{user['id']}", json={"country": "IN"}, headers=ADMIN)
    assert await fee("crypto") == "0.035000"  # 0.10 x 0.35
    domains = (await client.get("/v1/domains", headers=auth(key))).json()["data"]
    fees = {d["name"]: d["fee_usd"] for d in domains}
    assert fees["brokerage"] == "0.017500" and fees["general"] == "0.010500"
    assert (await client.put("/admin/api/pricing", json={"provider": "domain:nope", "fee_per_request": "1"}, headers=ADMIN)).status_code == 422


# ------------------------------------------------------------------ reporting


async def test_admin_domain_reporting(client, make_user, database):
    user, key = await make_user(balance="5")
    await make_user(domain="brokerage")
    for domain in ("brokerage", "brokerage", "crypto"):
        await client.post("/v1/transactions", json=body(domain), headers=auth(key))
    # A row recorded before domains existed counts as general.
    async with database.session() as s, s.begin():
        s.add(Charge(user_id=uuid.UUID(user["id"]), api_key_id=uuid.UUID(key["id"]), reference="legacy-1",
                     type="payment", fee_charged=Decimal("0.03"), fee_multiplier=Decimal("1")))
    report = {d["name"]: d for d in (await client.get("/admin/api/domains", headers=ADMIN)).json()["domains"]}
    assert report["brokerage"]["transactions"] == 2 and report["brokerage"]["revenue"] == "0.060000"
    assert report["brokerage"]["locked_keys"] == 1
    assert report["crypto"]["transactions"] == 1
    assert report["general"]["transactions"] == 1
    assert "gateway_requests" in report["ai"]
    only = (await client.get("/admin/api/charges", params={"domain": "brokerage"}, headers=ADMIN)).json()
    assert len(only) == 2 and {c["domain"] for c in only} == {"brokerage"}
    general = (await client.get("/admin/api/charges", params={"domain": "general"}, headers=ADMIN)).json()
    assert [c["reference"] for c in general] == ["legacy-1"]
    usage = (await client.get("/admin/api/usage", headers=ADMIN)).json()["daily"]
    assert {r["provider"] for r in usage} >= {"domain:brokerage", "domain:crypto", "domain:general"}
    mine = (await client.get("/v1/transactions", params={"domain": "crypto"}, headers=auth(key))).json()["data"]
    assert len(mine) == 1
