"""Opossum's connections to outside systems: Stripe (payments, refunds, Connect,
Identity), the OFAC sanctions list, and merchants' webhooks."""

from __future__ import annotations

import hashlib
import hmac
import json
from urllib.parse import parse_qs

import httpx
import pytest
from sqlalchemy import select

from aiproxy.opossum import sanctions, webhooks
from aiproxy.opossum.models import OpAccount, OpRecipient, OpTransaction, OpWebhookDelivery
from aiproxy.payments import sign_stripe_payload

from .conftest import ADMIN
from .test_opossum import SAME, User, admin_create_recipient, merchant_key

HOOK = "https://93.184.216.34/opossum-hook"


def form(request: httpx.Request) -> dict:
    return {k: v[0] for k, v in parse_qs(request.content.decode()).items()}


async def stripe_event(client, event_type: str, obj: dict):
    payload = json.dumps({"id": "evt_" + event_type, "type": event_type, "data": {"object": obj}}).encode()
    return await client.post("/stripe/webhook", content=payload, headers={"Stripe-Signature": sign_stripe_payload(payload, "whsec_test")})


@pytest.fixture
async def ready(client):
    u = User(client)
    await u.sign_up()
    await u.enable_mfa()
    await u.set_identity("Ada Lovelace")
    return u


async def paid_by_stripe(client, upstream, user, amount="50.00", recipient="acme-store"):
    upstream.on("/v1/checkout/sessions", lambda req: httpx.Response(200, json={"id": "cs_live_1", "url": "https://checkout.stripe.com/c/pay/cs_live_1"}))
    tx = (await user.pay(recipient=recipient, amount=amount)).json()
    cents = int(float(tx["total_cost"]) * 100)
    r = await stripe_event(client, "checkout.session.completed", {
        "id": "cs_live_1", "payment_status": "paid", "currency": "usd", "amount_total": cents, "payment_intent": "pi_live_1",
        "metadata": {"purpose": "opossum_payment", "opossum_tx": tx["id"]}})
    assert r.json()["settled"] == tx["id"]
    return tx


# ================================================================== Stripe money


async def test_platform_recipient_is_a_plain_charge(client, upstream, ready):
    await admin_create_recipient(client, handle="zorak", display_name="Zorak", processor="stripe", processor_account="platform")
    await paid_by_stripe(client, upstream, ready, recipient="zorak")
    sent = form(upstream.requests[0])
    assert not any("transfer_data" in k or "application_fee" in k for k in sent)
    assert sent["metadata[purpose]"] == "opossum_payment"


async def test_refund_reverses_transfer_and_fee(client, upstream, ready):
    await admin_create_recipient(client, processor="stripe", processor_account="acct_1TestConnect0001")
    tx = await paid_by_stripe(client, upstream, ready)
    upstream.on("/v1/refunds", lambda req: httpx.Response(200, json={"id": "re_1", "status": "succeeded"}))
    r = await client.post(f"/admin/api/opossum/transactions/{tx['id']}/refund", headers=ADMIN, json={"reason": "customer asked"})
    assert r.status_code == 200 and r.json()["status"] == "refunded"
    sent = form(upstream.requests[-1])
    assert sent["payment_intent"] == "pi_live_1" and sent["reverse_transfer"] == "true" and sent["refund_application_fee"] == "true"
    assert upstream.requests[-1].headers["Idempotency-Key"] == "opossum-refund-" + tx["id"]
    mine = (await client.get(f"/opossum/api/payments/{tx['id']}")).json()
    assert mine["status"] == "refunded" and mine["refunded_at"]
    again = await client.post(f"/admin/api/opossum/transactions/{tx['id']}/refund", headers=ADMIN)
    assert again.json()["status"] == "refunded" and len([q for q in upstream.requests if q.url.path == "/v1/refunds"]) == 1


async def test_refund_made_in_stripe_is_mirrored(client, upstream, ready):
    await admin_create_recipient(client, processor="stripe", processor_account="acct_1TestConnect0001")
    tx = await paid_by_stripe(client, upstream, ready)
    r = await stripe_event(client, "charge.refunded", {"id": "ch_1", "payment_intent": "pi_live_1", "refunded": True,
                                                       "refunds": {"data": [{"id": "re_dash"}]}})
    assert r.json()["refunded"] == tx["id"]
    assert (await client.get(f"/opossum/api/payments/{tx['id']}")).json()["status"] == "refunded"
    other = await stripe_event(client, "charge.refunded", {"id": "ch_2", "payment_intent": "pi_other", "refunded": True})
    assert other.json()["ignored"] == "not an opossum payment"


async def test_merchant_refunds_only_its_own_payments(client, ready):
    shop = await admin_create_recipient(client)
    other = await admin_create_recipient(client, handle="other-shop", display_name="Other")
    mine, theirs = await merchant_key(client, shop["id"]), await merchant_key(client, other["id"])
    tx = (await ready.pay(recipient="acme-store", amount="12.00")).json()
    assert (await client.post(f"/opossum/merchant/api/payments/{tx['id']}/refund", headers=theirs)).status_code == 404
    r = await client.post(f"/opossum/merchant/api/payments/{tx['id']}/refund", headers=mine)
    assert r.json()["status"] == "refunded"
    seen = (await client.get("/opossum/merchant/api/payments", headers=mine)).json()[0]
    assert seen["status"] == "refunded" and seen["refunded_at"]


async def test_connect_onboarding_readiness(client, upstream):
    shop = await admin_create_recipient(client, processor="stripe", processor_account="acct_1TestConnect0001")
    await client.patch(f"/admin/api/opossum/recipients/{shop['id']}", headers=ADMIN, json={"status": "onboarding"})
    assert "acme-store" not in [r["handle"] for r in (await client.get("/opossum/api/recipients")).json()]
    upstream.on("/v1/accounts/acct_1TestConnect0001", httpx.Response(200, json={"charges_enabled": False, "payouts_enabled": False,
                                                                               "requirements": {"currently_due": ["external_account"]}}))
    r = (await client.post(f"/admin/api/opossum/recipients/{shop['id']}/check-onboarding", headers=ADMIN)).json()
    assert r["ready"] is False and "external_account" in r["detail"]
    upstream.on("/v1/accounts/acct_1TestConnect0001", httpx.Response(200, json={"charges_enabled": True, "payouts_enabled": True}))
    r = (await client.post(f"/admin/api/opossum/recipients/{shop['id']}/check-onboarding", headers=ADMIN)).json()
    assert r["ready"] is True and r["status"] == "active"
    assert "acme-store" in [r["handle"] for r in (await client.get("/opossum/api/recipients")).json()]


# ================================================================== Stripe Identity


async def test_identity_check_through_stripe(client, upstream, ready, database):
    captured = {}

    def create(req):
        captured.update(form(req))
        return httpx.Response(200, json={"id": "vs_live_1", "url": "https://verify.stripe.com/start/abc"})

    upstream.on("/v1/identity/verification_sessions", create)
    r = await client.post("/opossum/api/identity/verify", headers=SAME)
    assert r.status_code == 200 and r.json()["url"].startswith("https://verify.stripe.com/")
    ref = captured["metadata[opossum_ref]"]
    assert ref.startswith("kyc_") and ready.email not in json.dumps(captured) and "Ada" not in json.dumps(captured)
    assert captured["type"] == "document" and captured["return_url"].endswith("/opossum#privacy")

    assert (await ready.pay(amount="600.00")).json()["error"]["code"] == "over_limit"
    wrong = await stripe_event(client, "identity.verification_session.verified", {"id": "vs_other", "status": "verified", "metadata": {"opossum_ref": ref}})
    assert wrong.json()["ignored"] == "unknown identity check"
    ok = await stripe_event(client, "identity.verification_session.verified", {"id": "vs_live_1", "status": "verified", "metadata": {"opossum_ref": ref}})
    assert ok.json()["identity"] == "verified"
    assert (await client.get("/opossum/api/me")).json()["kyc_status"] == "verified"
    await client.put("/admin/api/opossum/jurisdictions/US", headers=ADMIN, json={
        "unverified_tx_limit": "500", "unverified_daily_limit": "1000", "verified_tx_limit": "10000", "retention_days": 1825})
    assert (await ready.pay(amount="600.00")).status_code == 200
    assert (await client.post("/opossum/api/identity/verify", headers=SAME)).json()["error"]["code"] == "already_verified"


async def test_identity_check_failure_leaves_a_note(client, upstream, ready, database):
    upstream.on("/v1/identity/verification_sessions", httpx.Response(200, json={"id": "vs_2", "url": "https://verify.stripe.com/start/x"}))
    await client.post("/opossum/api/identity/verify", headers=SAME)
    async with database.session() as session:
        ref = (await session.execute(select(OpAccount.kyc_ref))).scalar_one()
    await stripe_event(client, "identity.verification_session.requires_input",
                       {"id": "vs_2", "status": "requires_input", "last_error": {"code": "document_expired"}, "metadata": {"opossum_ref": ref}})
    async with database.session() as session:
        account = (await session.execute(select(OpAccount))).scalar_one()
    assert account.kyc_status == "self_attested" and "document_expired" in account.kyc_note


async def test_identity_check_needs_identity_first(client, upstream):
    u = User(client)
    await u.sign_up()
    assert (await client.post("/opossum/api/identity/verify", headers=SAME)).json()["error"]["code"] == "identity_required"


async def test_identity_provider_not_activated_is_explained(client, upstream, ready):
    upstream.on("/v1/identity/verification_sessions", httpx.Response(400, json={"error": {"message": "Your account is not activated for Identity."}}))
    r = await client.post("/opossum/api/identity/verify", headers=SAME)
    assert r.status_code == 502 and "not activated" in r.json()["error"]["message"]


# ================================================================== OFAC


SDN_ROWS = [f'{1000 + i},"PERSON{i}, Synthetic{i}","individual","SDGT","-0- ","-0- ","-0- ","-0- ","-0- ","-0- ","-0- ","-0- "' for i in range(1200)]
SDN_CSV = "\n".join(SDN_ROWS + ['36,"SMITH, John","individual","SDGT","-0- ","-0- ","-0- ","-0- ","-0- ","-0- ","-0- ","-0- "',
                                '37,"BLACKSTAR SHIPPING CO","-0- ","IRAN","-0- ","-0- ","-0- ","-0- ","-0- ","-0- ","-0- ","-0- "']) + "\n"
ALT_CSV = '36,12,"aka","SMYTHE, Johnny","-0- "\n'


def test_parsing_and_matching():
    assert "SMITH, John" in sanctions.parse_sdn(SDN_CSV) and sanctions.parse_alt(ALT_CSV) == ["SMYTHE, Johnny"]
    assert sanctions.key_for("SMITH, John") == "john smith"
    assert "john smith" in sanctions.candidate_keys("John Michael Smith")
    assert sanctions.candidate_keys("Madonna") == []


async def test_ofac_refresh_loads_list_and_rescreens(client, upstream, ready, app, database):
    await admin_create_recipient(client, handle="blackstar", display_name="Blackstar Shipping Co")
    await ready.set_identity("John Michael Smith")
    upstream.on("/api/PublicationPreview/exports/SDN.CSV", httpx.Response(200, text=SDN_CSV))
    upstream.on("/api/PublicationPreview/exports/ALT.CSV", httpx.Response(200, text=ALT_CSV + "x" * 1000))
    r = await client.post("/admin/api/opossum/sanctions/refresh", headers=ADMIN)
    assert r.status_code == 200 and r.json()["entries"] >= 1200 and r.json()["new_matches"] == 2
    status = (await client.get("/admin/api/opossum/sanctions", headers=ADMIN)).json()["lists"][0]
    assert status["list"] == "ofac-sdn" and status["loaded_at"] and status["last_error"] is None
    assert (await client.get("/opossum/api/me")).json()["kyc_status"] == "review"
    assert (await ready.pay(amount="5.00")).json()["error"]["code"] == "account_under_review"
    async with database.session() as session:
        assert (await session.scalar(select(OpRecipient.status).where(OpRecipient.handle == "blackstar"))) == "review"
    # an alias on the list matches too
    other = User(client)
    await other.sign_up()
    assert (await other.set_identity("Johnny Smythe"))["kyc_status"] == "review"


async def test_ofac_failure_keeps_old_list(client, upstream):
    upstream.on("/api/PublicationPreview/exports/SDN.CSV", httpx.Response(503, text="down"))
    upstream.on("/ofac/downloads/sdn.csv", httpx.Response(503, text="down"))
    r = await client.post("/admin/api/opossum/sanctions/refresh", headers=ADMIN)
    assert r.status_code == 502 and "HTTP 503" in r.json()["error"]["message"]
    status = (await client.get("/admin/api/opossum/sanctions", headers=ADMIN)).json()["lists"][0]
    assert status["last_error"] and status["loaded_at"] is None


# ================================================================== merchant webhooks


@pytest.mark.parametrize("url", ["http://93.184.216.34/x", "https://10.0.0.5/x", "https://127.0.0.1/x", "https://localhost/x",
                                 "https://169.254.169.254/latest", "https://user:pw@93.184.216.34/x", "https://[::1]/x"])
async def test_webhook_url_must_be_public_https(client, url):
    shop = await admin_create_recipient(client)
    mkey = await merchant_key(client, shop["id"])
    r = await client.put("/opossum/merchant/api/webhook", headers=mkey, json={"url": url})
    assert r.status_code == 400 and r.json()["error"]["code"] == "invalid_webhook_url"


async def test_signed_webhooks_are_delivered_and_retried(client, upstream, ready, app, database):
    shop = await admin_create_recipient(client)
    mkey = await merchant_key(client, shop["id"])
    setup = (await client.put("/opossum/merchant/api/webhook", headers=mkey, json={"url": HOOK})).json()
    secret = setup["secret"]
    assert secret.startswith("whsec_op_")
    received = []
    upstream.on("/opossum-hook", lambda req: (received.append(req), httpx.Response(200))[1])
    tx = (await ready.pay(recipient="acme-store", amount="20.00", mode="private")).json()
    keys = app.state.services.opossum_keys
    assert await webhooks.deliver(app.state.services, keys) == 2  # webhook.test + payment.settled
    events = [json.loads(r.content) for r in received]
    assert [e["type"] for e in events] == ["webhook.test", "payment.settled"]
    settled = events[1]
    assert settled["data"]["id"] == tx["id"] and settled["data"]["payer"] == {"pseudonym": tx["payer_pseudonym"]}
    assert ready.email not in received[1].content.decode()
    ts, sig = dict(p.split("=", 1) for p in received[1].headers["Opossum-Signature"].split(",")).values()
    assert hmac.compare_digest(sig, hmac.new(secret.encode(), ts.encode() + b"." + received[1].content, hashlib.sha256).hexdigest())

    upstream.on("/opossum-hook", httpx.Response(500))
    await client.post(f"/opossum/merchant/api/payments/{tx['id']}/refund", headers=mkey)
    assert await webhooks.deliver(app.state.services, keys) == 0
    async with database.session() as session:
        pending = (await session.execute(select(OpWebhookDelivery).where(OpWebhookDelivery.delivered_at.is_(None)))).scalar_one()
    assert pending.event_type == "payment.refunded" and pending.attempts == 1 and pending.last_error == "HTTP 500"
    status = (await client.get("/opossum/merchant/api/webhook", headers=mkey)).json()
    assert status["recent"][0]["last_error"] == "HTTP 500"


async def test_no_webhook_no_outbox(client, ready, database):
    await admin_create_recipient(client)
    await ready.pay(recipient="acme-store", amount="7.00")
    async with database.session() as session:
        assert (await session.execute(select(OpWebhookDelivery))).first() is None
        assert (await session.execute(select(OpTransaction))).scalar_one().status == "settled"
