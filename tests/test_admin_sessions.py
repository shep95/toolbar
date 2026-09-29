"""Dashboard sign-in: session cookie, CSRF defences, expiry, host lock, page headers."""

from __future__ import annotations

import base64
import hashlib
import re
from datetime import timedelta

import pytest
from sqlalchemy import func, select, update

from aiproxy import admin_session
from aiproxy.admin import _DASHBOARD_HTML
from aiproxy.models import AdminSession, AuditLog, utcnow

from .conftest import ADMIN, ADMIN_TOKEN

SAME = {"Origin": "https://proxy.test", "X-Admin-Request": "1"}
COOKIE = admin_session.COOKIE


async def sign_in(client, token: str = ADMIN_TOKEN, headers: dict | None = None):
    return await client.post("/admin/session", json={"token": token}, headers=SAME if headers is None else headers)


async def session_rows(database) -> list[AdminSession]:
    async with database.session() as session:
        return list((await session.execute(select(AdminSession))).scalars())


# ------------------------------------------------------------------ sign-in


async def test_sign_in_sets_a_locked_down_cookie_and_opens_the_api(client):
    assert (await client.get("/admin/session")).json() == {"signed_in": False}
    r = await sign_in(client)
    assert r.status_code == 200 and r.json()["signed_in"] is True and r.json()["idle_minutes"] == 30
    cookie = r.headers["set-cookie"]
    assert cookie.startswith(COOKIE + "=")
    for flag in ("HttpOnly", "Secure", "SameSite=strict", "Path=/"):
        assert flag.lower() in cookie.lower()
    assert "max-age" not in cookie.lower() and "domain=" not in cookie.lower()
    assert ADMIN_TOKEN not in r.text and ADMIN_TOKEN not in cookie

    # The cookie alone now reads the admin API; no Authorization header.
    assert (await client.get("/admin/api/users")).status_code == 200
    assert (await client.get("/admin/session")).json()["signed_in"] is True


async def test_only_a_hash_of_the_session_id_is_stored(client, database):
    await sign_in(client)
    raw = client.cookies[COOKIE]
    [row] = await session_rows(database)
    assert row.id_hash == hashlib.sha256(raw.encode()).hexdigest() and row.id_hash != raw
    assert len(raw) >= 40


async def test_wrong_token_is_refused_audited_and_locked_out(client, database):
    codes = [(await sign_in(client, "wrong-" + "x" * 40)).status_code for _ in range(10)]
    assert codes == [401] * 10
    assert COOKIE not in client.cookies
    r = await sign_in(client)  # even the right token waits out the lockout
    assert r.status_code == 429 and "retry-after" in r.headers
    async with database.session() as session:
        failed = await session.scalar(select(func.count()).where(AuditLog.outcome == "admin_signin_failed"))
    assert failed == 10


@pytest.mark.parametrize(
    "headers",
    [
        {},  # no dashboard header
        {"Origin": "https://proxy.test"},  # header missing
        {"Origin": "https://evil.example", "X-Admin-Request": "1"},
        {"Origin": "null", "X-Admin-Request": "1"},
        {"X-Admin-Request": "1"},  # no Origin and no Sec-Fetch-Site
        {"Origin": "https://proxy.test", "X-Admin-Request": "1", "Sec-Fetch-Site": "cross-site"},
        {"Origin": "https://proxy.test", "X-Admin-Request": "1", "Sec-Fetch-Site": "same-site"},
    ],
)
async def test_sign_in_only_from_the_dashboard_itself(client, headers):
    r = await sign_in(client, headers=headers)
    assert r.status_code == 403
    assert COOKIE not in client.cookies


async def test_sign_in_accepts_same_origin_fetch_metadata_without_origin(client):
    r = await sign_in(client, headers={"X-Admin-Request": "1", "Sec-Fetch-Site": "same-origin"})
    assert r.status_code == 200


async def test_sign_in_rejects_non_json_and_oversized_bodies(client):
    r = await client.post("/admin/session", content=b"token=x", headers={**SAME, "Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 415
    r = await client.post("/admin/session", content=b'{"token":"' + b"a" * 5000 + b'"}', headers={**SAME, "Content-Type": "application/json"})
    assert r.status_code == 413


# ------------------------------------------------------------------ using the session


async def test_cookie_writes_need_the_dashboard_origin_and_header(client):
    await sign_in(client)
    body = {"email": "csrf@example.com"}
    assert (await client.post("/admin/api/users", json=body)).status_code == 403
    assert (await client.post("/admin/api/users", json=body, headers={"X-Admin-Request": "1", "Origin": "https://evil.example"})).status_code == 403
    assert (await client.post("/admin/api/users", json=body, headers={"Origin": "https://proxy.test"})).status_code == 403
    r = await client.post("/admin/api/users", json=body, headers=SAME)
    assert r.status_code == 201


async def test_session_cookie_is_useless_from_another_browser(client):
    await sign_in(client)
    r = await client.get("/admin/api/users", headers={"User-Agent": "curl/8.0"})
    assert r.status_code == 401
    # ...and the session is gone for the original browser too.
    assert (await client.get("/admin/api/users")).status_code == 401


async def test_session_cookie_does_not_open_the_user_api(client):
    await sign_in(client)
    assert (await client.get("/v1/account")).status_code == 401


async def test_bearer_token_still_works_for_scripts(client):
    client.cookies.set(COOKIE, "stale-session-value", domain="proxy.test")
    assert (await client.get("/admin/api/users", headers=ADMIN)).status_code == 200
    assert (await client.post("/admin/api/users", json={"email": "script@example.com"}, headers=ADMIN)).status_code == 201


async def test_unknown_session_is_401_and_does_not_count_as_a_guess(client):
    client.cookies.set(COOKIE, "made-up", domain="proxy.test")
    for _ in range(15):
        assert (await client.get("/admin/api/users")).status_code == 401
    client.cookies.clear()
    assert (await sign_in(client)).status_code == 200


# ------------------------------------------------------------------ ending sessions


async def test_sign_out_ends_the_session_on_the_server(client):
    await sign_in(client)
    raw = client.cookies[COOKIE]
    r = await client.delete("/admin/session", headers=SAME)
    assert r.status_code == 200 and COOKIE in r.headers["set-cookie"]
    client.cookies.set(COOKIE, raw, domain="proxy.test")  # a copied cookie is dead
    assert (await client.get("/admin/api/users")).status_code == 401


async def test_sign_out_needs_the_dashboard_origin(client):
    await sign_in(client)
    assert (await client.delete("/admin/session")).status_code == 403
    assert (await client.get("/admin/api/users")).status_code == 200


@pytest.mark.parametrize(
    "column, age",
    [("last_seen_at", timedelta(minutes=31)), ("expires_at", timedelta(seconds=1))],
)
async def test_idle_and_absolute_expiry(client, database, column, age):
    await sign_in(client)
    async with database.session() as session, session.begin():
        await session.execute(update(AdminSession).values({column: utcnow() - age}))
    assert (await client.get("/admin/api/users")).status_code == 401
    assert await session_rows(database) == []


async def test_activity_keeps_the_session_alive(client, database):
    await sign_in(client)
    async with database.session() as session, session.begin():
        await session.execute(update(AdminSession).values(last_seen_at=utcnow() - timedelta(minutes=20)))
    assert (await client.get("/admin/api/users")).status_code == 200
    [row] = await session_rows(database)
    last_seen = row.last_seen_at if row.last_seen_at.tzinfo else row.last_seen_at.replace(tzinfo=utcnow().tzinfo)
    assert utcnow() - last_seen < timedelta(minutes=1)


@pytest.mark.parametrize("settings_overrides", [{"admin_max_sessions": 2}])
async def test_old_sessions_make_way_past_the_limit(client, database):
    await sign_in(client)
    first = client.cookies[COOKIE]
    client.cookies.clear()
    async with database.session() as session, session.begin():
        await session.execute(update(AdminSession).values(last_seen_at=utcnow() - timedelta(minutes=5)))
    for _ in range(2):
        client.cookies.clear()
        assert (await sign_in(client)).status_code == 200
    assert len(await session_rows(database)) == 2
    client.cookies.set(COOKIE, first, domain="proxy.test")
    assert (await client.get("/admin/api/users")).status_code == 401


async def test_list_and_end_every_session(client, database):
    await sign_in(client)
    other = client.cookies[COOKIE]
    client.cookies.clear()
    await sign_in(client)
    listed = (await client.get("/admin/api/sessions")).json()
    assert len(listed) == 2 and sum(s["current"] for s in listed) == 1
    assert {"created_at", "last_seen_at", "expires_at", "ip", "user_agent"} <= set(listed[0])
    assert all(other not in str(s) for s in listed)

    r = await client.post("/admin/api/sessions/end-all", headers=SAME)
    assert r.status_code == 200 and r.json()["ended"] == 2
    assert await session_rows(database) == []
    client.cookies.set(COOKIE, other, domain="proxy.test")
    assert (await client.get("/admin/api/users")).status_code == 401


async def test_purge_drops_only_expired_sessions(app, client, database):
    await sign_in(client)
    client.cookies.clear()
    await sign_in(client)
    async with database.session() as session, session.begin():
        oldest = (await session.execute(select(AdminSession).limit(1))).scalar_one()
        oldest.last_seen_at = utcnow() - timedelta(hours=2)
    assert await admin_session.purge_expired(app.state.services) == 1
    assert len(await session_rows(database)) == 1


# ------------------------------------------------------------------ where the dashboard answers


@pytest.mark.parametrize("settings_overrides", [{"admin_allowed_hosts": "admin.example.com"}])
async def test_admin_answers_only_on_its_own_hostname(client):
    for path in ("/admin", "/admin/session", "/admin/api/users"):
        assert (await client.get(path, headers=ADMIN)).status_code == 404
    host = {"Host": "admin.example.com"}
    assert (await client.get("/admin", headers=host)).status_code == 200
    assert (await client.get("/admin/api/users", headers={**ADMIN, **host})).status_code == 200
    assert (await client.get("/admin/api/users", headers={**ADMIN, "Host": "admin.example.com:443"})).status_code == 200
    # The user API is unaffected.
    assert (await client.get("/v1/domains")).status_code != 404


async def test_railway_domain_is_the_default_admin_host(client, monkeypatch):
    monkeypatch.setenv("RAILWAY_PUBLIC_DOMAIN", "toolbar-production.up.railway.app")
    assert (await client.get("/admin")).status_code == 404
    assert (await client.get("/admin", headers={"Host": "toolbar-production.up.railway.app"})).status_code == 200


# ------------------------------------------------------------------ the page itself


def _sha(block: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(block.encode()).digest()).decode() + "'"


async def test_dashboard_page_headers_pin_everything(client):
    r = await client.get("/admin")
    h = r.headers
    csp = h["content-security-policy"]
    [script] = re.findall(r"<script>(.*?)</script>", _DASHBOARD_HTML, flags=re.S)
    [style] = re.findall(r"<style>(.*?)</style>", _DASHBOARD_HTML, flags=re.S)
    assert f"script-src {_sha(script)};" in csp and f"style-src {_sha(style)};" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    for directive in ("default-src 'none'", "connect-src 'self'", "frame-ancestors 'none'", "base-uri 'none'",
                      "form-action 'none'", "require-trusted-types-for 'script'", "trusted-types 'none'"):
        assert directive in csp
    assert h["cross-origin-opener-policy"] == "same-origin"
    assert h["cross-origin-embedder-policy"] == "require-corp"
    assert h["cross-origin-resource-policy"] == "same-origin"
    assert "camera=()" in h["permissions-policy"] and "clipboard-write=(self)" in h["permissions-policy"]
    assert "noindex" in h["x-robots-tag"]
    assert h["cache-control"] == "no-store" and h["x-frame-options"] == "DENY"


def test_dashboard_page_never_holds_the_token_or_builds_markup_from_strings():
    page = _DASHBOARD_HTML
    for banned in ("sessionStorage", "localStorage", "indexedDB", "innerHTML", "outerHTML", "insertAdjacentHTML",
                   "document.write", "eval(", "new Function", "Authorization", ' style="', " onclick="):
        assert banned not in page, banned
    assert "X-Admin-Request" in page and "credentials: 'same-origin'" in page
    assert "checkout.stripe.com" in page  # the Stripe test link is checked before it is shown
