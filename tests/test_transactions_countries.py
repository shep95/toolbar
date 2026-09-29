"""General transactions and country-adjusted fees."""

from __future__ import annotations

import asyncio
import uuid
from decimal import Decimal

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import create_async_engine

from aiproxy.countries import DEFAULT_MULTIPLIERS, INCOME_GROUP, income_group
from aiproxy.db import Database
from aiproxy.models import Charge, Transaction

from .conftest import ADMIN
from .test_gateway import CHAT, auth, openai_ok
from .test_providers import balance_of


def tx(reference: str | None = None, **fields) -> dict:
    return {"reference": reference or f"ref-{uuid.uuid4().hex[:10]}", "type": "payment", **fields}


async def fee_of(client, key, **fields) -> str:
    r = await client.post("/v1/transactions", json=tx(**fields), headers=auth(key))
    assert r.status_code == 201, r.text
    return r.json()["fee"]["amount_usd"]


# ------------------------------------------------------------------ recording transactions


async def test_record_any_transaction_and_charge_fee(client, make_user, database):
    user, key = await make_user(balance="1")
    r = await client.post(
        "/v1/transactions",
        json=tx("order-1001", type="order", amount="49.90", currency="eur", country="de",
                description="Blue shirt", metadata={"sku": "BS-1", "qty": 2}),
        headers=auth(key),
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["reference"] == "order-1001" and body["type"] == "order"
    assert (body["amount"], body["currency"], body["country"]) == ("49.9", "EUR", "DE")
    assert body["metadata"] == {"qty": 2, "sku": "BS-1"}
    assert body["fee"] == {"amount_usd": "0.030000", "country": None, "multiplier": "1"}
    assert body["balance_remaining_usd"] == "0.970000" and body["replayed"] is False
    assert r.headers["X-Fee-Charged"] == "0.030000"
    assert await balance_of(database, user) == Decimal("0.97")


async def test_same_reference_is_never_charged_twice(client, make_user, database):
    user, key = await make_user(balance="1")
    first = await client.post("/v1/transactions", json=tx("pay-7", amount="10", currency="USD"), headers=auth(key))
    again = await client.post("/v1/transactions", json=tx("pay-7", amount="10.00", currency="usd"), headers=auth(key))
    assert first.status_code == 201 and again.status_code == 200
    assert again.json()["replayed"] is True and again.json()["id"] == first.json()["id"]
    assert again.headers["X-Fee-Charged"] == "0.000000"
    conflict = await client.post("/v1/transactions", json=tx("pay-7", amount="99", currency="USD"), headers=auth(key))
    assert conflict.status_code == 409
    assert await balance_of(database, user) == Decimal("0.97")


async def test_concurrent_duplicates_charge_once(client, make_user, database):
    user, key = await make_user(balance="1")
    results = await asyncio.gather(
        *[client.post("/v1/transactions", json=tx("race-1", amount="5"), headers=auth(key)) for _ in range(10)]
    )
    assert sorted(r.status_code for r in results) == [200] * 9 + [201]
    assert await balance_of(database, user) == Decimal("0.97")
    async with database.session() as s:
        assert len((await s.execute(select(Charge))).scalars().all()) == 1


async def test_references_are_per_account(client, make_user):
    _, key_a = await make_user()
    _, key_b = await make_user()
    for key in (key_a, key_b):
        r = await client.post("/v1/transactions", json=tx("shared-ref"), headers=auth(key))
        assert r.status_code == 201


@pytest.mark.parametrize(
    "fields",
    [
        {"reference": None},
        {"reference": "has space"},
        {"reference": "x" * 201},
        {"type": "bad type!"},
        {"amount": -1},
        {"amount": "lots"},
        {"amount": True},
        {"currency": "EURO"},
        {"country": "Germany"},
        {"description": "x" * 501},
        {"metadata": {str(i): i for i in range(21)}},
        {"metadata": {"nested": {"a": 1}}},
    ],
)
async def test_invalid_transactions_are_refused_without_charge(client, make_user, database, fields):
    user, key = await make_user(balance="1")
    body = {**tx(), **fields}
    if body.get("reference") is None:
        body.pop("reference")
    r = await client.post("/v1/transactions", json=body, headers=auth(key))
    assert r.status_code == 400
    assert await balance_of(database, user) == Decimal("1")


async def test_transaction_rejections(client, make_user):
    _, broke = await make_user(balance="0")
    assert (await client.post("/v1/transactions", json=tx(), headers=auth(broke))).status_code == 402
    assert (await client.post("/v1/transactions", json=tx())).status_code == 401
    user, key = await make_user()
    await client.patch(f"/admin/api/users/{user['id']}", json={"status": "suspended"}, headers=ADMIN)
    assert (await client.post("/v1/transactions", json=tx(), headers=auth(key))).status_code == 403


async def test_listing_shows_only_own_transactions(client, make_user):
    _, key_a = await make_user()
    _, key_b = await make_user()
    await client.post("/v1/transactions", json=tx("a-1"), headers=auth(key_a))
    await client.post("/v1/transactions", json=tx("b-1"), headers=auth(key_b))
    mine = (await client.get("/v1/transactions", headers=auth(key_a))).json()["data"]
    assert [t["reference"] for t in mine] == ["a-1"]
    one = (await client.get("/v1/transactions", params={"reference": "a-1"}, headers=auth(key_a))).json()["data"]
    assert len(one) == 1
    everything = (await client.get("/admin/api/charges", headers=ADMIN)).json()
    assert {t["reference"] for t in everything} == {"a-1", "b-1"}


# ------------------------------------------------------------------ country-adjusted fees


def test_income_groups_are_consistent():
    assert set(INCOME_GROUP.values()) <= set(DEFAULT_MULTIPLIERS)
    assert income_group("US") == income_group("DE") == income_group("JP") == "high"
    assert income_group("IN") == "lower_middle" and income_group("BR") == "upper_middle"
    assert income_group("ET") == "low"
    assert income_group(None) == income_group("ZZ") == "high"  # unknown never gets a discount


@pytest.mark.parametrize(
    "country, expected",
    [("US", "0.030000"), ("DE", "0.030000"), ("BR", "0.018000"), ("IN", "0.010500"), ("ET", "0.006000"),
     ("ZZ", "0.030000"), (None, "0.030000")],
)
async def test_fee_follows_account_country(client, make_user, country, expected):
    user, key = await make_user()
    if country:
        r = await client.patch(f"/admin/api/users/{user['id']}", json={"country": country}, headers=ADMIN)
        assert r.status_code == 200
    assert await fee_of(client, key) == expected


async def test_ai_requests_are_country_adjusted_too(client, make_user, upstream, database):
    upstream.on("/v1/chat/completions", openai_ok)
    user, key = await make_user(balance="1")
    await client.patch(f"/admin/api/users/{user['id']}", json={"country": "IN"}, headers=ADMIN)
    r = await client.post("/v1/chat/completions", json=CHAT, headers=auth(key))
    assert r.headers["X-Fee-Charged"] == "0.010500" and r.headers["X-Fee-Country"] == "IN"
    async with database.session() as s:
        row = (await s.execute(select(Transaction))).scalar_one()
    assert (row.fee_country, Decimal(row.fee_multiplier)) == ("IN", Decimal("0.35"))
    assert await balance_of(database, user) == Decimal("0.9895")


async def test_users_cannot_pick_a_cheaper_country(client, make_user):
    _, key = await make_user()  # no country set: full fee
    r = await client.post("/v1/transactions", json=tx(country="ET"), headers=auth(key))
    assert r.json()["country"] == "ET"  # recorded for reporting...
    assert r.json()["fee"]["amount_usd"] == "0.030000"  # ...but does not lower the fee


@pytest.mark.parametrize("settings_overrides", [{"price_by_transaction_country": True}])
async def test_optional_pricing_by_transaction_country(client, make_user):
    _, key = await make_user()
    assert await fee_of(client, key, country="ET") == "0.006000"
    assert await fee_of(client, key) == "0.030000"


async def test_admin_country_overrides(client, make_user):
    user, key = await make_user()
    await client.patch(f"/admin/api/users/{user['id']}", json={"country": "IN"}, headers=ADMIN)
    assert (await client.put("/admin/api/countries/in", json={"multiplier": "0.5"}, headers=ADMIN)).status_code == 200
    assert await fee_of(client, key) == "0.015000"
    table = (await client.get("/admin/api/countries", headers=ADMIN)).json()
    assert table["base_fee_usd"] == "0.030000"
    assert table["groups"]["low"]["fee_usd"] == "0.006000"
    assert table["overrides"][0]["country"] == "IN" and table["overrides"][0]["default_group"] == "lower_middle"
    assert (await client.delete("/admin/api/countries/IN", headers=ADMIN)).status_code == 200
    assert await fee_of(client, key) == "0.010500"
    for bad in ({"multiplier": "0"}, {"multiplier": "11"}, {"multiplier": "abc"}):
        assert (await client.put("/admin/api/countries/IN", json=bad, headers=ADMIN)).status_code == 422
    assert (await client.put("/admin/api/countries/India", json={"multiplier": "1"}, headers=ADMIN)).status_code == 422


async def test_country_change_applies_immediately_despite_auth_cache(client, make_user):
    user, key = await make_user()
    assert await fee_of(client, key) == "0.030000"  # key now cached
    await client.patch(f"/admin/api/users/{user['id']}", json={"country": "ET"}, headers=ADMIN)
    assert await fee_of(client, key) == "0.006000"
    await client.patch(f"/admin/api/users/{user['id']}", json={"country": None}, headers=ADMIN)
    assert await fee_of(client, key) == "0.030000"


async def test_per_type_pricing_rules_combine_with_country(client, make_user):
    user, key = await make_user()
    await client.patch(f"/admin/api/users/{user['id']}", json={"country": "BR"}, headers=ADMIN)
    r = await client.put(
        "/admin/api/pricing", json={"provider": "transactions", "model": "transfer", "fee_per_request": "0.10"},
        headers=ADMIN,
    )
    assert r.status_code == 200
    assert await fee_of(client, key, type="transfer") == "0.060000"  # 0.10 x 0.6
    assert await fee_of(client, key, type="payment") == "0.018000"  # default 0.03 x 0.6


async def test_account_shows_country_fee(client, make_user):
    user, key = await make_user()
    await client.patch(f"/admin/api/users/{user['id']}", json={"country": "IN"}, headers=ADMIN)
    account = (await client.get("/v1/account", headers=auth(key))).json()
    assert account["country"] == "IN"
    assert account["fees"] == {"currency": "USD", "country_multiplier": "0.35", "per_transaction": "0.010500"}


async def test_admin_reporting_includes_transactions(client, make_user):
    _, key = await make_user()
    await client.post("/v1/transactions", json=tx(), headers=auth(key))
    overview = (await client.get("/admin/api/overview", headers=ADMIN)).json()["last_24h"]
    assert overview["transactions"] == 1 and overview["transaction_revenue"] == "0.030000"
    assert overview["total_revenue"] == "0.030000"
    usage = (await client.get("/admin/api/usage", headers=ADMIN)).json()
    assert any(r["provider"] == "domain:general" and r["revenue"] == "0.030000" for r in usage["daily"])


async def test_user_created_with_country(client):
    r = await client.post("/admin/api/users", json={"email": "c@example.com", "country": "ng"}, headers=ADMIN)
    assert r.status_code == 201 and r.json()["country"] == "NG"
    r = await client.post("/admin/api/users", json={"email": "d@example.com", "country": "Nigeria"}, headers=ADMIN)
    assert r.status_code == 422


# ------------------------------------------------------------------ live-database upgrade


async def test_existing_database_gets_new_columns_and_tables(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'old.db'}")
    async with engine.begin() as conn:  # a users table from before the country column existed
        await conn.execute(text(
            "CREATE TABLE users (id CHAR(32) PRIMARY KEY, email VARCHAR(320) NOT NULL UNIQUE, "
            "created_at DATETIME NOT NULL, balance NUMERIC(18, 6) NOT NULL, status VARCHAR(16) NOT NULL)"
        ))
        await conn.execute(text(
            "INSERT INTO users VALUES ('0123456789abcdef0123456789abcdef', 'old@example.com', "
            "'2026-01-01 00:00:00', 5, 'active')"
        ))
    db = Database(engine)
    await db.create_all()
    await db.create_all()  # idempotent
    async with engine.connect() as conn:
        columns = {r[1] for r in (await conn.execute(text("PRAGMA table_info(users)"))).all()}
        tables = {r[0] for r in (await conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))).all()}
        kept = (await conn.execute(text("SELECT email, balance FROM users"))).one()
    assert "country" in columns
    assert {"charges", "country_pricing", "transactions"} <= tables
    assert kept[0] == "old@example.com" and Decimal(str(kept[1])) == 5  # existing data untouched
    await engine.dispose()


def test_plain_number_format():
    from aiproxy.countries import plain

    assert [plain(v) for v in ("250", "250.000000", "49.90", "0.35", "10", "0.000001")] == [
        "250", "250", "49.9", "0.35", "10", "0.000001"
    ]


async def test_round_amounts_are_not_scientific(client, make_user):
    _, key = await make_user()
    r = await client.post("/v1/transactions", json=tx(amount="250", currency="USD"), headers=auth(key))
    assert r.json()["amount"] == "250"
