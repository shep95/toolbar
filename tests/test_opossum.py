"""Opossum Protocol: crypto, fees, privacy modes, relay, compliance, recovery."""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from datetime import timedelta
from decimal import Decimal

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from sqlalchemy import select, update

from aiproxy.models import utcnow
from aiproxy.opossum import audit
from aiproxy.opossum.crypto import (
    RelayKeys,
    ReceiptInvalid,
    b64u,
    b64u_decode,
    check_memo,
    check_totp,
    totp_code,
    verify_presentation,
)
from aiproxy.opossum.fees import Rule, choose_rule, quote
from aiproxy.opossum.models import OpAccount, OpAuditEntry, OpBackup, OpRecipient, OpTransaction
from aiproxy.payments import sign_stripe_payload

from .conftest import ADMIN, OPOSSUM_MASTER_KEY

SAME = {"Origin": "https://proxy.test", "X-Opossum-Request": "1"}
KEYS = RelayKeys.from_master(OPOSSUM_MASTER_KEY)


# ================================================================== helpers


class Device:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        n = self.key.public_key().public_numbers()
        self.jwk = {"kty": "EC", "crv": "P-256", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}
        self.id = None

    def sign(self, body: bytes) -> str:
        r, s = decode_dss_signature(self.key.sign(body, ec.ECDSA(hashes.SHA256())))
        return b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


class User:
    """Plays the browser: derived keys are random hex here; the real app uses PBKDF2."""

    def __init__(self, client: httpx.AsyncClient, email: str | None = None, country: str = "US"):
        self.client = client
        self.email = email or f"p-{secrets.token_hex(4)}@example.com"
        self.auth_key = secrets.token_hex(32)
        self.recovery_key = secrets.token_hex(32)
        self.country = country
        self.device = Device()
        self.totp_secret = None
        self.last_step = None

    async def sign_up(self):
        r = await self.client.post("/opossum/api/accounts", headers=SAME, json={
            "email": self.email, "auth_key": self.auth_key, "recovery_key": self.recovery_key,
            "kdf_salt": b64u(secrets.token_bytes(16)), "kdf_iterations": 600000, "jurisdiction": self.country,
            "device": {"name": "test browser", "public_jwk": self.device.jwk},
            "wrapped_keys": {"password": {"iv": "x", "ct": "y"}, "recovery": {"iv": "x", "ct": "y"}},
        })
        assert r.status_code == 201, r.text
        self.device.id = r.json()["device_id"]
        return r

    def code(self) -> str:
        step = int(time.time() // 30)
        step = max(step - 1, (self.last_step or -1) + 1)
        self.last_step = step
        return totp_code(self.totp_secret, step)

    async def enable_mfa(self):
        r = await self.client.post("/opossum/api/mfa/setup", headers=SAME)
        assert r.status_code == 200, r.text
        self.totp_secret = r.json()["secret"]
        r = await self.client.post("/opossum/api/mfa/confirm", headers=SAME, json={"code": self.code()})
        assert r.status_code == 200, r.text

    async def set_identity(self, name="Ada Lovelace"):
        r = await self.client.put("/opossum/api/identity", headers=SAME, json={
            "legal_name": name, "address_line1": "1 Engine Way", "city": "London", "country": "GB"})
        assert r.status_code == 200, r.text
        return r.json()

    async def quote(self, recipient="north-coffee", amount="100.00", **extra):
        r = await self.client.post("/opossum/api/quote", json={"recipient": recipient, "amount": amount, **extra})
        assert r.status_code == 200, r.text
        return r.json()

    def payment_body(self, recipient="north-coffee", amount="100.00", **extra) -> dict:
        return {"recipient": recipient, "amount": amount, "currency": "USD", "type": "purchase", "mode": "pseudonymous",
                "fee_bearer": "recipient", "nonce": secrets.token_hex(16), "ts": int(time.time()),
                "idempotency_key": secrets.token_hex(16), **extra}

    async def pay(self, body: dict | None = None, *, expected_total=None, raw: bytes | None = None, signer: Device | None = None, **extra):
        body = body or self.payment_body(**extra)
        if expected_total is None and "expected_total" not in body:
            q = await self.quote(body["recipient"], body["amount"], fee_bearer=body.get("fee_bearer", "recipient"),
                                 type=body.get("type", "purchase"))
            body["expected_total"] = q["total_cost"]
        elif expected_total is not None:
            body["expected_total"] = expected_total
        data = raw if raw is not None else json.dumps(body).encode()
        signer = signer or self.device
        return await self.client.post("/opossum/api/payments", content=data, headers={
            **SAME, "Content-Type": "application/json", "X-Opossum-Device": self.device.id,
            "X-Opossum-Signature": signer.sign(data)})


@pytest.fixture
async def user(client):
    u = User(client)
    await u.sign_up()
    return u


@pytest.fixture
async def ready(user):
    await user.enable_mfa()
    return user


async def admin_create_recipient(client, **fields):
    r = await client.post("/admin/api/opossum/recipients", headers=ADMIN, json={
        "handle": "acme-store", "display_name": "Acme Store", "category": "shopping", **fields})
    assert r.status_code == 201, r.text
    return r.json()


async def merchant_key(client, recipient_id):
    r = await client.post(f"/admin/api/opossum/recipients/{recipient_id}/merchant-key", headers=ADMIN)
    return {"Authorization": f"Bearer {r.json()['merchant_key']}"}


def present(receipt: dict, names) -> str:
    return receipt["sd_jwt"] + "~" + "".join(receipt["disclosures"][n] + "~" for n in names)


# ================================================================== crypto units


def test_receipt_selective_disclosure_and_tampering():
    jwt, disclosures = KEYS.issue_receipt({"amount": "500.00", "currency": "USD", "recipient_name": "Acme"}, {"iss": "opossum-relay", "test": True})
    one = verify_presentation(jwt + "~" + disclosures[0] + "~", KEYS.jwks())
    assert one["disclosed"] == {"amount": "500.00"} and one["hidden"] == 2 and one["issuer_claims"]["test"] is True
    assert verify_presentation(jwt + "~", KEYS.jwks())["disclosed"] == {}

    header, payload, sig = jwt.split(".")
    body = json.loads(b64u_decode(payload))
    body["test"] = False
    forged = header + "." + b64u(json.dumps(body).encode()) + "." + sig
    with pytest.raises(ReceiptInvalid, match="altered"):
        verify_presentation(forged + "~", KEYS.jwks())
    fake = b64u(json.dumps(["salt", "amount", "5000.00"]).encode())
    with pytest.raises(ReceiptInvalid, match="not part of the signed receipt"):
        verify_presentation(jwt + "~" + fake + "~", KEYS.jwks())
    other = RelayKeys.from_master(b64u(secrets.token_bytes(32)))
    with pytest.raises(ReceiptInvalid):
        verify_presentation(jwt + "~", other.jwks())


def test_vault_is_bound_to_its_row_and_field():
    sealed = KEYS.seal({"legal_name": "Ada"}, "op_identities:1:doc")
    assert KEYS.open(sealed, "op_identities:1:doc") == {"legal_name": "Ada"}
    with pytest.raises(ValueError):
        KEYS.open(sealed, "op_identities:2:doc")  # moved to another account's row
    assert "Ada" not in sealed


def test_pseudonyms_do_not_link_across_recipients():
    a = KEYS.pairwise_pseudonym("acct-1", "shop-1")
    assert a == KEYS.pairwise_pseudonym("acct-1", "shop-1")
    assert a != KEYS.pairwise_pseudonym("acct-1", "shop-2")
    assert a != KEYS.pairwise_pseudonym("acct-2", "shop-1")
    assert KEYS.one_time_pseudonym() != KEYS.one_time_pseudonym()


def test_memo_commitment_and_totp():
    salt = secrets.token_hex(16)
    commitment = hashlib.sha256(f"{salt}:client lunch".encode()).hexdigest()
    assert check_memo(commitment, "client lunch", salt) and not check_memo(commitment, "birthday gift", salt)
    secret = "JBSWY3DPEHPK3PXP"
    now = time.time()
    code = totp_code(secret, int(now // 30))
    step = check_totp(secret, code, None, now)
    assert step is not None and check_totp(secret, code, step, now) is None  # no reuse


# ================================================================== fees


def test_default_three_percent_and_full_breakdown():
    q = quote(Decimal("100.00"), "USD", Rule("default", "standard", Decimal("3")),
              processor_percent=Decimal("2.9"), processor_flat=Decimal("0.30"))
    assert q.as_dict() | {} == {
        "currency": "USD", "amount_sent": "100.00", "opossum_fee": "3.00", "processor_fee": "3.20",
        "total_cost": "100.00", "recipient_receives": "93.80", "fee_bearer": "recipient",
        "fee_rule": "standard (3%)", "effective_rate_percent": "6.20",
    }
    payer = quote(Decimal("100.00"), "USD", Rule("default", "standard", Decimal("3")),
                  processor_percent=Decimal("2.9"), processor_flat=Decimal("0.30"), fee_bearer="payer")
    assert payer.recipient_receives == Decimal("100.00") and payer.opossum_fee == Decimal("3.00")
    # After the processor takes 2.9% + 0.30 of the larger charge, the recipient still gets 100.
    assert payer.total_cost - payer.processor_fee - payer.opossum_fee == Decimal("100.00")
    assert payer.processor_fee >= (payer.total_cost * Decimal("0.029") + Decimal("0.30")).quantize(Decimal("0.01"))


def test_fee_rules_min_max_specificity_and_promotions():
    now = utcnow()
    default = Rule("d", "standard", Decimal("3"))
    capped = Rule("c", "capped", Decimal("3"), minimum=Decimal("0.50"), maximum=Decimal("10"))
    assert quote(Decimal("5.00"), "USD", capped, processor_percent=Decimal(0), processor_flat=Decimal(0)).opossum_fee == Decimal("0.50")
    assert quote(Decimal("1000.00"), "USD", capped, processor_percent=Decimal(0), processor_flat=Decimal(0)).opossum_fee == Decimal("10.00")
    merchant = Rule("m", "merchant", Decimal("2"), recipient_id="shop")
    donation = Rule("t", "donations", Decimal("0"), tx_type="donation")
    promo = Rule("p", "launch week", Decimal("1"), recipient_id="shop", starts_at=now - timedelta(days=1), ends_at=now + timedelta(days=1))
    expired = Rule("x", "old promo", Decimal("0.5"), recipient_id="shop", ends_at=now - timedelta(days=1))
    rules = [merchant, donation, promo, expired]
    assert choose_rule(rules, default, "shop", "purchase", now).id == "p"
    assert choose_rule([merchant, donation, expired], default, "shop", "purchase", now).id == "m"
    assert choose_rule(rules, default, "other", "donation", now).id == "t"
    assert choose_rule(rules, default, "other", "purchase", now).id == "d"


# ================================================================== accounts


async def test_sign_up_sign_in_and_no_email_enumeration(client, user, database):
    async with database.session() as session:
        account = (await session.execute(select(OpAccount))).scalar_one()
    assert user.email not in json.dumps({c.name: str(getattr(account, c.name)) for c in OpAccount.__table__.columns})
    known = (await client.get("/opossum/api/auth/params", params={"email": user.email})).json()
    unknown1 = (await client.get("/opossum/api/auth/params", params={"email": "nobody@example.com"})).json()
    unknown2 = (await client.get("/opossum/api/auth/params", params={"email": "nobody@example.com"})).json()
    assert known["kdf_salt"] == account.kdf_salt and unknown1 == unknown2 and set(unknown1) == set(known)

    client.cookies.clear()
    r = await client.post("/opossum/api/session", headers=SAME, json={"email": user.email, "auth_key": secrets.token_hex(32)})
    assert r.status_code == 401 and r.json()["error"]["code"] == "wrong_credentials"
    r = await client.post("/opossum/api/session", headers=SAME, json={"email": user.email, "auth_key": user.auth_key})
    assert r.status_code == 200 and "__Host-opossum_session" in r.headers["set-cookie"]
    assert "httponly" in r.headers["set-cookie"].lower()


async def test_sign_in_requires_authenticator_once_enabled(client, ready):
    client.cookies.clear()
    r = await client.post("/opossum/api/session", headers=SAME, json={"email": ready.email, "auth_key": ready.auth_key})
    assert r.json()["error"]["code"] == "mfa_required"
    r = await client.post("/opossum/api/session", headers=SAME, json={"email": ready.email, "auth_key": ready.auth_key, "totp": ready.code()})
    assert r.status_code == 200


async def test_cross_site_requests_are_refused(client, user):
    r = await client.post("/opossum/api/mfa/setup", headers={"Origin": "https://evil.example", "X-Opossum-Request": "1"})
    assert r.status_code == 403
    r = await client.put("/opossum/api/identity", json={"legal_name": "x" * 5, "address_line1": "aa", "city": "b", "country": "US"})
    assert r.status_code == 403


# ================================================================== payments and privacy


async def test_payment_needs_mfa(user):
    r = await user.pay()
    assert r.status_code == 403 and r.json()["error"]["code"] == "mfa_required"


async def test_sandbox_payment_settles_with_signed_receipt(client, ready):
    r = await ready.pay()
    assert r.status_code == 200, r.text
    tx = r.json()
    assert tx["status"] == "settled" and tx["test_money"] is True
    assert (tx["amount"], tx["opossum_fee"], tx["processor_fee"], tx["recipient_receives"]) == ("100.00", "3.00", "3.20", "93.80")
    receipt = tx["receipt"]
    # "I paid $100 on this date" without anything else:
    proof = present(receipt, ["amount", "currency", "date", "recipient_name"])
    v = (await client.post("/opossum/api/verify", json={"presentation": proof})).json()
    assert v["valid"] is True and set(v["disclosed"]) == {"amount", "currency", "date", "recipient_name"}
    assert v["issuer_claims"]["test"] is True and v["hidden"] > 5
    jwks = (await client.get("/opossum/.well-known/jwks.json")).json()
    assert verify_presentation(proof, jwks)["disclosed"]["amount"] == "100.00"


async def test_what_the_recipient_sees_in_each_mode(client, ready):
    shop = await admin_create_recipient(client)
    mkey = await merchant_key(client, shop["id"])
    await ready.set_identity("Ada Lovelace")

    await ready.pay(recipient="acme-store", amount="10.00", mode="private")
    await ready.pay(recipient="acme-store", amount="11.00", mode="pseudonymous")
    await ready.pay(recipient="acme-store", amount="12.00", mode="pseudonymous")
    await ready.pay(recipient="acme-store", amount="13.00", mode="disclosure", disclose=["legal_name"], message_to_recipient="order #88")
    await ready.pay(recipient="acme-store", amount="14.00", mode="public")
    seen = {p["amount"]: p for p in (await client.get("/opossum/merchant/api/payments", headers=mkey)).json()}

    assert set(seen["10.00"]["payer"]) == {"pseudonym"} and seen["10.00"]["payer"]["pseudonym"].startswith("opx_")
    assert seen["11.00"]["payer"] == seen["12.00"]["payer"]  # a returning customer, still anonymous
    assert seen["13.00"]["payer"] == {"pseudonym": seen["11.00"]["payer"]["pseudonym"], "legal_name": "Ada Lovelace", "message": "order #88"}
    assert seen["14.00"]["payer"]["email"] == ready.email
    blob = json.dumps(seen)
    for secret in ("London", "Engine Way", "account", "device"):
        assert secret not in blob
    assert seen["10.00"]["you_receive"] == "9.11"  # 10 - 0.30 (3%) - 0.59 (2.9% + 0.30)


async def test_pseudonyms_differ_between_recipients(client, ready):
    await admin_create_recipient(client)
    a = (await ready.pay(recipient="acme-store", amount="5.00")).json()["payer_pseudonym"]
    b = (await ready.pay(recipient="harbor-books", amount="5.00")).json()["payer_pseudonym"]
    assert a != b


async def test_replay_idempotency_signature_and_quote_checks(client, ready):
    body = ready.payment_body(amount="20.00")
    q = await ready.quote(amount="20.00")
    body["expected_total"] = q["total_cost"]
    raw = json.dumps(body).encode()
    first = await ready.pay(raw=raw)
    assert first.status_code == 200
    replay = await ready.pay(raw=raw)
    assert replay.json()["error"]["code"] == "replayed_request"

    retry = dict(body, nonce=secrets.token_hex(16), ts=int(time.time()))
    again = await ready.pay(retry)
    assert again.status_code == 200 and again.json()["id"] == first.json()["id"] and again.json()["replayed"] is True

    other = dict(body, nonce=secrets.token_hex(16), amount="21.00")
    assert (await ready.pay(other, expected_total="21.00")).json()["error"]["code"] == "idempotency_conflict"

    assert (await ready.pay(signer=Device(), amount="22.00")).json()["error"]["code"] == "bad_signature"
    assert (await ready.pay(amount="23.00", expected_total="1.00")).json()["error"]["code"] == "quote_changed"
    stale = ready.payment_body(amount="24.00", ts=int(time.time()) - 3600)
    assert (await ready.pay(stale)).json()["error"]["code"] == "stale_request"


async def test_duplicate_guard_and_limits(client, ready):
    assert (await ready.pay(amount="30.00")).status_code == 200
    dup = await ready.pay(amount="30.00")
    assert dup.status_code == 409 and dup.json()["error"]["code"] == "possible_duplicate"
    assert (await ready.pay(amount="30.00", confirm_duplicate=True)).status_code == 200
    over = await ready.pay(amount="600.00")
    assert over.json()["error"]["code"] == "over_limit"


async def test_real_money_needs_identity_and_blocked_countries(client, ready, upstream):
    await admin_create_recipient(client, processor="stripe", processor_account="acct_123")
    r = await ready.pay(recipient="acme-store", amount="10.00")
    assert r.json()["error"]["code"] == "identity_required"
    blocked = User(client, country="KP")
    await blocked.sign_up()
    await blocked.enable_mfa()
    assert (await blocked.pay(amount="10.00")).json()["error"]["code"] == "jurisdiction_blocked"


async def test_stripe_connect_checkout_and_webhook_settlement(client, ready, upstream):
    await admin_create_recipient(client, processor="stripe", processor_account="acct_123")
    await ready.set_identity()
    upstream.on("/v1/checkout/sessions", lambda req: httpx.Response(200, json={"id": "cs_test_1", "url": "https://checkout.stripe.com/c/pay/cs_test_1"}))
    r = await ready.pay(recipient="acme-store", amount="50.00")
    tx = r.json()
    assert r.status_code == 200 and tx["status"] == "pending_payment" and tx["checkout_url"].startswith("https://checkout.stripe.com/")
    form = dict(x.split("=", 1) for x in upstream.requests[-1].content.decode().split("&"))
    assert form["payment_intent_data%5Btransfer_data%5D%5Bdestination%5D"] == "acct_123"
    assert form["payment_intent_data%5Bapplication_fee_amount%5D"] == str(150 + 175)  # 3% + (2.9% + 0.30)
    assert not any(ready.email.split("@")[0] in v for v in form.values())

    event = {"id": "evt_1", "type": "checkout.session.completed", "data": {"object": {
        "id": "cs_test_1", "payment_status": "paid", "currency": "usd", "amount_total": 5000,
        "metadata": {"purpose": "opossum_payment", "opossum_tx": tx["id"]}}}}
    payload = json.dumps(event).encode()
    w = await client.post("/stripe/webhook", content=payload, headers={"Stripe-Signature": sign_stripe_payload(payload, "whsec_test")})
    assert w.json()["settled"] == tx["id"]
    done = (await client.get(f"/opossum/api/payments/{tx['id']}")).json()
    assert done["status"] == "settled" and done["receipt"]["disclosures"]["payer_legal_name"]
    assert (await client.post("/stripe/webhook", content=payload, headers={"Stripe-Signature": sign_stripe_payload(payload, "whsec_test")})).status_code == 200


async def test_invoice_paid_and_provable(client, ready):
    shop = await admin_create_recipient(client)
    mkey = await merchant_key(client, shop["id"])
    inv = (await client.post("/opossum/merchant/api/invoices", headers=mkey, json={"reference": "INV-2041", "amount": "500.00"})).json()
    assert (await client.get(f"/opossum/api/invoices/{inv['id']}")).json()["amount"] == "500.00"
    wrong = await ready.pay(recipient="acme-store", amount="499.00", invoice=inv["id"])
    assert wrong.json()["error"]["code"] == "invoice_mismatch"
    await client.put("/admin/api/opossum/jurisdictions/US", headers=ADMIN, json={
        "unverified_tx_limit": "1000", "unverified_daily_limit": "2000", "verified_tx_limit": "10000", "retention_days": 1825})
    tx = (await ready.pay(recipient="acme-store", amount="500.00", invoice=inv["id"])).json()
    assert tx["status"] == "settled"
    paid = (await client.get("/opossum/merchant/api/invoices", headers=mkey)).json()[0]
    assert paid["status"] == "paid" and paid["paid_transaction"] == tx["id"]
    proof = present(tx["receipt"], ["invoice_reference", "amount", "date"])
    v = (await client.post("/opossum/api/verify", json={"presentation": proof})).json()
    assert v["disclosed"]["invoice_reference"] == "INV-2041"


async def test_memo_commitment_proves_a_private_note(client, ready):
    salt = secrets.token_hex(16)
    commitment = hashlib.sha256(f"{salt}:business: client dinner".encode()).hexdigest()
    tx = (await ready.pay(amount="40.00", memo_commitment=commitment)).json()
    proof = present(tx["receipt"], ["memo_commitment", "amount"])
    good = (await client.post("/opossum/api/verify", json={"presentation": proof, "memo": "business: client dinner", "memo_salt": salt})).json()
    bad = (await client.post("/opossum/api/verify", json={"presentation": proof, "memo": "personal", "memo_salt": salt})).json()
    assert good["memo_valid"] is True and bad["memo_valid"] is False


async def test_relay_never_stores_personal_accounting(client, ready, database):
    await ready.pay(amount="15.00", memo_commitment="a" * 64)
    async with database.session() as session:
        tx = (await session.execute(select(OpTransaction))).scalar_one()
    stored = json.dumps({c.name: str(getattr(tx, c.name)) for c in OpTransaction.__table__.columns})
    assert ready.email not in stored and "category" not in stored


# ================================================================== backup and recovery


async def test_backup_is_opaque_and_versioned(client, user):
    assert (await client.put("/opossum/api/backup", headers=SAME, json={"expected_version": 0, "ciphertext": '{"plain":1}'})).status_code == 400
    assert (await client.put("/opossum/api/backup", headers=SAME, json={"expected_version": 0, "ciphertext": "v1.abc"})).json()["version"] == 1
    conflict = await client.put("/opossum/api/backup", headers=SAME, json={"expected_version": 0, "ciphertext": "v1.def"})
    assert conflict.status_code == 409 and conflict.json()["error"]["version"] == 1
    got = (await client.get("/opossum/api/backup")).json()
    assert got["ciphertext"] == "v1.abc" and got["wrapped_keys"]["recovery"]


async def test_recovery_code_restores_access_and_revokes_old_devices(client, ready):
    client.cookies.clear()
    new_device, new_key = Device(), secrets.token_hex(32)
    r = await client.post("/opossum/api/recovery", headers=SAME, json={
        "email": ready.email, "recovery_key": ready.recovery_key, "new_auth_key": new_key,
        "device": {"name": "new phone", "public_jwk": new_device.jwk}})
    assert r.status_code == 200 and r.json()["mfa_enabled"] is False
    devices = (await client.get("/opossum/api/devices")).json()
    assert [d["status"] for d in devices].count("active") == 1
    client.cookies.clear()
    ok = await client.post("/opossum/api/session", headers=SAME, json={"email": ready.email, "auth_key": new_key})
    assert ok.status_code == 200
    bad = await client.post("/opossum/api/recovery", headers=SAME, json={
        "email": ready.email, "recovery_key": secrets.token_hex(32), "new_auth_key": new_key,
        "device": {"name": "x", "public_jwk": new_device.jwk}})
    assert bad.status_code == 401


async def test_new_device_needs_authenticator_code(client, ready):
    other = Device()
    r = await client.post("/opossum/api/devices", headers=SAME, json={"name": "laptop", "public_jwk": other.jwk})
    assert r.json()["error"]["code"] == "mfa_required"
    r = await client.post("/opossum/api/devices", headers=SAME, json={"name": "laptop", "public_jwk": other.jwk, "totp": ready.code()})
    assert r.status_code == 201 and r.json()["approved_via"] == "mfa"


# ================================================================== compliance


async def test_case_discloses_only_requested_fields_and_is_logged(client, ready, database):
    await ready.set_identity("Ada Lovelace")
    tx = (await ready.pay(amount="25.00")).json()
    no_case = await client.post("/admin/api/opossum/cases/case_nope/disclose", headers=ADMIN, json={"transaction_id": tx["id"], "fields": ["legal_name"]})
    assert no_case.status_code == 409
    case = (await client.post("/admin/api/opossum/cases", headers=ADMIN, json={
        "legal_basis": "court_order", "reference": "Case 24-cv-1", "authority": "District Court",
        "scope": "payer of one transaction", "notify": "now"})).json()
    out = (await client.post(f"/admin/api/opossum/cases/{case['id']}/disclose", headers=ADMIN,
                             json={"transaction_id": tx["id"], "fields": ["legal_name"]})).json()["disclosed"]
    assert out["legal_name"] == "Ada Lovelace" and "email" not in out and "address" not in out and "account_id" not in out
    mine = (await client.get("/opossum/api/disclosures")).json()
    assert mine[0]["fields"] == ["legal_name"] and mine[0]["authority"] == "District Court"

    gag = (await client.post("/admin/api/opossum/cases", headers=ADMIN, json={
        "legal_basis": "law_enforcement_request", "reference": "LE-1", "authority": "Agency",
        "scope": "sealed request for one payment", "notify": "prohibited"})).json()
    await client.post(f"/admin/api/opossum/cases/{gag['id']}/disclose", headers=ADMIN, json={"transaction_id": tx["id"], "fields": ["email"]})
    assert len((await client.get("/opossum/api/disclosures")).json()) == 1

    routine = (await client.get("/admin/api/opossum/transactions", headers=ADMIN)).json()
    assert "Ada" not in json.dumps(routine) and ready.email not in json.dumps(routine)
    actions = [e["action"] for e in (await client.get("/admin/api/opossum/audit", headers=ADMIN)).json()]
    assert actions.count("case_disclosure") == 2


async def test_audit_chain_detects_tampering(client, ready, database):
    await ready.pay(amount="12.00")
    assert (await client.get("/admin/api/opossum/audit/verify", headers=ADMIN)).json()["ok"] is True
    async with database.session() as session, session.begin():
        first = (await session.execute(select(OpAuditEntry).order_by(OpAuditEntry.id).limit(1))).scalar_one()
        first.details = json.dumps({"rewritten": True})
    result = (await client.get("/admin/api/opossum/audit/verify", headers=ADMIN)).json()
    assert result["ok"] is False and result["broken_at"] == first.id


async def test_audit_chain_detects_truncation(database):
    async with database.session() as session, session.begin():
        await audit.append(session, "test", "one")
        await audit.append(session, "test", "two")
    async with database.session() as session, session.begin():
        last = (await session.execute(select(OpAuditEntry).order_by(OpAuditEntry.id.desc()).limit(1))).scalar_one()
        await session.delete(last)
    async with database.session() as session:
        assert (await audit.verify_chain(session))["ok"] is False


async def test_screening_match_pauses_payments(client, ready):
    await client.post("/admin/api/opossum/screening", headers=ADMIN, json={"names": ["Mallory Blocked"], "list_name": "test list"})
    assert (await ready.set_identity("Mallory  Blocked"))["kyc_status"] == "review"
    assert (await ready.pay(amount="5.00")).json()["error"]["code"] == "account_under_review"
    queue = (await client.get("/admin/api/opossum/kyc", headers=ADMIN)).json()
    assert queue[0]["kyc_status"] == "review" and "Mallory" not in json.dumps(queue)


async def test_admin_fee_rule_changes_quotes(client, ready):
    r = await client.post("/admin/api/opossum/fee-rules", headers=ADMIN, json={
        "name": "donations free", "percent": "0", "tx_type": "donation"})
    assert r.status_code == 201
    q = await ready.quote("open-shelter", "50.00", type="donation")
    assert q["opossum_fee"] == "0.00" and "donations free" in q["fee_rule"]


async def test_retention_purge(client, ready, app, database):
    from aiproxy.opossum import maintenance

    tx = (await ready.pay(amount="9.00")).json()
    async with database.session() as session, session.begin():
        await session.execute(update(OpTransaction).values(retain_until=utcnow() - timedelta(days=1)))
    await maintenance.run(app.state.services)
    assert (await client.get(f"/opossum/api/payments/{tx['id']}")).status_code == 404


async def test_close_account_deletes_backup_and_ends_sessions(client, user, database):
    await client.put("/opossum/api/backup", headers=SAME, json={"expected_version": 0, "ciphertext": "v1.abc"})
    r = await client.post("/opossum/api/account/close", headers=SAME, json={"auth_key": user.auth_key})
    assert r.status_code == 200
    assert (await client.get("/opossum/api/me")).status_code == 401
    async with database.session() as session:
        backup = (await session.execute(select(OpBackup))).scalar_one()
    assert backup.ciphertext is None


# ================================================================== pages and public surface


async def test_pages_are_locked_down(client):
    for path in ("/opossum", "/opossum/verify", "/opossum/app.js", "/opossum/app.css"):
        r = await client.get(path)
        assert r.status_code == 200, path
        csp = r.headers["content-security-policy"]
        assert "script-src 'self'" in csp and "trusted-types 'none'" in csp and "unsafe" not in csp
    data_map = (await client.get("/opossum/api/data-map")).json()
    assert any("card" in item["data"] for item in data_map["items"])
    recipients = (await client.get("/opossum/api/recipients")).json()
    assert {r["handle"] for r in recipients} >= {"north-coffee", "harbor-books"} and all(r["test_money"] for r in recipients)


@pytest.mark.parametrize("settings_overrides", [{"opossum_master_key": None}])
async def test_opossum_off_without_master_key(client):
    r = await client.get("/opossum/api/recipients")
    assert r.status_code == 503 and r.json()["error"]["code"] == "opossum_not_configured"


async def test_sandbox_recipients_seeded_once(database, app):
    async with database.session() as session:
        count = len((await session.execute(select(OpRecipient))).scalars().all())
    assert count == 4
