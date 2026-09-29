"""Direct on-chain payments (Bitcoin and USDC) to a merchant's own wallet.

The chain, the price feed and the RPC nodes are faked; everything else (quote,
signed payment request, watcher, receipt, refunds, fees billed) is real.
"""

from __future__ import annotations

import json
from datetime import timedelta
from decimal import Decimal

import httpx
import pytest
from sqlalchemy import func, select, update

from aiproxy.models import utcnow
from aiproxy.opossum import chains, sanctions
from aiproxy.opossum import chainutil as cu
from aiproxy.opossum.models import OpTransaction

from .conftest import ADMIN
from .test_opossum import User, admin_create_recipient, merchant_key, present
from .test_opossum_integrations import paid_by_stripe

ZPUB = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"
FIRST = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"  # BIP84 test vector m/84'/0'/0'/0/0
SECOND = "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"  # .../0/1
MERCHANT_EVM = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
PAYER_BTC = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
PAYER_EVM = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"


@pytest.fixture
def settings_overrides():
    return {
        "opossum_btc_api": "https://btc.test/api",
        "opossum_evm_rpc": json.dumps({"base": "https://base.test/rpc", "ethereum": "https://eth.test/rpc"}),
        "opossum_price_api": "https://price.test/v2/prices/{pair}/spot",
    }


@pytest.fixture(autouse=True)
def fresh_prices():
    chains._PRICE_CACHE.clear()
    yield
    chains._PRICE_CACHE.clear()


class Chain:
    """A tiny Bitcoin + EVM world behind the fake upstream."""

    def __init__(self, upstream):
        self.btc_tip = 800_000
        self.btc_txs: dict[str, list[dict]] = {}
        self.evm_tip = 5_000_000
        self.logs: list[dict] = []
        self.price = "50000.00"
        upstream.on("/v2/prices/BTC-USD/spot", lambda req: httpx.Response(200, json={"data": {"amount": self.price}}))
        upstream.on("/api/blocks/tip/height", lambda req: httpx.Response(200, text=str(self.btc_tip)))
        upstream.on("/rpc", self._rpc)
        upstream.default = self._esplora

    def _esplora(self, req):
        parts = req.url.path.split("/")
        if req.url.host == "btc.test" and len(parts) == 4 and parts[2] == "block-height":
            return httpx.Response(200, text="00" * 32)
        if req.url.host == "btc.test" and len(parts) == 5 and parts[2] == "block" and parts[4] == "txs":
            return httpx.Response(200, json=[{"txid": "coinbase", "vout": [{"scriptpubkey_address": PAYER_BTC, "value": 1}]}]
                                  + [t for txs in self.btc_txs.values() for t in txs])
        if req.url.host == "btc.test" and len(parts) == 5 and parts[2] == "address" and parts[4] == "txs":
            return httpx.Response(200, json=self.btc_txs.get(parts[3], []))
        return httpx.Response(404, json={"error": "no fake handler for " + req.url.path})

    def _rpc(self, req):
        body = json.loads(req.content)
        if body["method"] == "eth_blockNumber":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": hex(self.evm_tip)})
        f = body["params"][0]
        start, end = int(f["fromBlock"], 16), int(f["toBlock"], 16)
        to = f["topics"][2] if len(f["topics"]) > 2 else None
        hits = [lg for lg in self.logs if lg["address"].lower() == f["address"].lower() and (to is None or lg["topics"][2] == to)
                and start <= int(lg["blockNumber"], 16) <= end]
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": hits})

    def send_btc(self, address, sats, *, txid="aa" * 32, sender=PAYER_BTC, height=None):
        status = {"confirmed": height is not None, **({"block_height": height} if height is not None else {})}
        self.btc_txs.setdefault(address, []).append({
            "txid": txid, "status": status, "vin": [{"prevout": {"scriptpubkey_address": sender}}],
            "vout": [{"scriptpubkey_address": address, "value": sats}, {"scriptpubkey_address": sender, "value": 1234}]})

    def send_usdc(self, network, to, atomic, *, txid="0x" + "bb" * 32, sender=PAYER_EVM, block=None):
        self.logs.append({
            "address": chains.EVM[network].usdc, "blockNumber": hex(block or self.evm_tip), "transactionHash": txid,
            "data": hex(atomic), "removed": False,
            "topics": [chains.TRANSFER_TOPIC, "0x" + "0" * 24 + sender[2:].lower(), "0x" + "0" * 24 + to[2:].lower()]})


@pytest.fixture
def chain(upstream):
    return Chain(upstream)


@pytest.fixture
async def payer(client):
    u = User(client)
    await u.sign_up()
    await u.enable_mfa()
    await u.set_identity("Ada Lovelace")
    return u


@pytest.fixture
async def merchant(client):
    r = await admin_create_recipient(client, handle="zorak", display_name="Zorak", processor="stripe", processor_account="platform")
    s = await client.put(f"/admin/api/opossum/recipients/{r['id']}/chain", headers=ADMIN, json={
        "btc_xpub": ZPUB, "btc_first_address": FIRST, "usdc_address": MERCHANT_EVM})
    assert s.status_code == 200, s.text
    return r


async def pay_on_chain(user: User, rail: str, amount="100.00", **extra):
    q = await user.quote("zorak", amount, rail=rail)
    body = user.payment_body("zorak", amount, rail=rail, **extra)
    r = await user.pay(body, expected_total=q["total_cost"])
    assert r.status_code == 200, r.text
    return q, r.json()


async def watch(app):
    return await chains.watch(app.state.services)


async def payment(client, tx_id):
    return (await client.get(f"/opossum/api/payments/{tx_id}")).json()


# ================================================================== merchant setup


async def test_setup_needs_the_wallets_first_address(client):
    r = await admin_create_recipient(client, handle="zorak", display_name="Zorak", processor="stripe", processor_account="platform")
    bad = await client.put(f"/admin/api/opossum/recipients/{r['id']}/chain", headers=ADMIN, json={"btc_xpub": ZPUB, "btc_first_address": SECOND})
    assert bad.status_code == 400 and FIRST in bad.json()["error"]["message"]
    wrong_case = await client.put(f"/admin/api/opossum/recipients/{r['id']}/chain", headers=ADMIN, json={"usdc_address": MERCHANT_EVM.replace("a", "A")})
    assert wrong_case.status_code == 400
    xprv = await client.put(f"/admin/api/opossum/recipients/{r['id']}/chain", headers=ADMIN, json={
        "btc_xpub": "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LL7Gj6AVxDMMCCh9MUoZKAFQ4VMqi34pXi",
        "btc_first_address": FIRST})
    assert xprv.status_code == 400
    ok = await client.put(f"/admin/api/opossum/recipients/{r['id']}/chain", headers=ADMIN, json={"btc_xpub": ZPUB, "btc_first_address": FIRST})
    assert ok.status_code == 200 and [x["id"] for x in ok.json()["rails"]] == ["btc"]
    listed = (await client.get("/opossum/api/recipients")).json()
    zorak = next(x for x in listed if x["handle"] == "zorak")
    assert [x["id"] for x in zorak["rails"]] == ["card", "btc"]
    assert "xpub" not in json.dumps(zorak) and ZPUB not in json.dumps(zorak)


async def test_merchant_sets_up_their_own_wallet(client, merchant):
    headers = await merchant_key(client, merchant["id"])
    r = await client.put("/opossum/merchant/api/chain", headers=headers, json={"usdc_address": MERCHANT_EVM.lower()})
    assert r.status_code == 200 and r.json()["usdc_address"] == MERCHANT_EVM
    assert len(r.json()["rails"]) == len(chains.EVM)
    fees = await client.get("/opossum/merchant/api/fees", headers=headers)
    assert fees.json() == {"fees_due_usd": "0.00"}


# ================================================================== bitcoin


async def test_bitcoin_payment_gets_its_own_address_and_settles(app, client, chain, merchant, payer):
    q, tx = await pay_on_chain(payer, "btc", "100.00")
    assert q["processor_fee"] == "0.00" and q["total_cost"] == "100.00" and q["recipient_receives"] == "97.00" and q["network_fee"]
    assert tx["status"] == "awaiting_chain" and tx["rail"] == "btc" and tx["crypto_asset"] == "BTC"
    how = tx["pay_on_chain"]
    assert how["address"] == SECOND and how["amount"] == "0.00200000" and how["rate_usd"] == "50000.00"
    assert how["uri"] == f"bitcoin:{SECOND}?amount=0.002" and how["qr"].startswith("data:image/svg+xml")
    assert how["confirmations_needed"] == 2 and how["expires_at"]

    _, other = await pay_on_chain(payer, "btc", "10.00", confirm_duplicate=True)
    assert other["pay_on_chain"]["address"] == cu.derive_receive_address(ZPUB, 2, "p2wpkh") != SECOND

    assert await watch(app) == 0
    assert (await payment(client, tx["id"]))["status"] == "awaiting_chain"

    chain.send_btc(SECOND, 200_000)  # in the mempool
    assert await watch(app) == 0
    seen = await payment(client, tx["id"])
    assert seen["status"] == "confirming" and Decimal(seen["crypto_received"]) == Decimal("0.002") and seen["confirmations"] == 0

    chain.btc_txs[SECOND][0]["status"] = {"confirmed": True, "block_height": chain.btc_tip - 1}
    assert await watch(app) == 1
    done = await payment(client, tx["id"])
    assert done["status"] == "settled" and done["chain_txid"] == "aa" * 32 and done["confirmations"] == 2
    assert "pay_on_chain" not in done
    proof = present(done["receipt"], ["crypto_txid", "crypto_amount", "chain", "deposit_address", "amount"])
    v = (await client.post("/opossum/api/verify", json={"presentation": proof})).json()
    assert v["valid"] and v["disclosed"]["crypto_txid"] == "aa" * 32 and v["disclosed"]["chain"] == "Bitcoin"
    assert v["disclosed"]["crypto_amount"] == "0.00200000" and v["disclosed"]["deposit_address"] == SECOND

    headers = await merchant_key(client, merchant["id"])
    assert (await client.get("/opossum/merchant/api/fees", headers=headers)).json() == {"fees_due_usd": "3.00"}
    assert await watch(app) == 0  # settled once only


async def test_bitcoin_expiry_underpayment_and_late_arrival(app, client, chain, merchant, payer):
    _, late = await pay_on_chain(payer, "btc", "100.00")
    _, short = await pay_on_chain(payer, "btc", "50.00", confirm_duplicate=True)
    _, idle = await pay_on_chain(payer, "btc", "20.00", confirm_duplicate=True)
    past = utcnow() - timedelta(minutes=1)
    async with app.state.services.db.session() as session, session.begin():
        await session.execute(update(OpTransaction).values(quote_expires_at=past))

    await watch(app)
    assert (await payment(client, idle["id"]))["status"] == "expired"

    chain.send_btc(short["pay_on_chain"]["address"], 50_000, txid="cc" * 32, height=chain.btc_tip - 5)
    chain.send_btc(late["pay_on_chain"]["address"], 200_000, txid="dd" * 32, height=chain.btc_tip - 5)
    await watch(app)
    assert (await payment(client, short["id"]))["status"] == "underpaid"
    assert (await payment(client, late["id"]))["status"] == "received_late"  # the merchant decides


async def test_sanctioned_sender_goes_to_review(app, client, chain, merchant, payer):
    await sanctions.load_addresses(app.state.services, [PAYER_BTC], "test list")
    _, tx = await pay_on_chain(payer, "btc", "100.00")
    chain.send_btc(SECOND, 200_000, height=chain.btc_tip - 10)
    assert await watch(app) == 0
    held = await payment(client, tx["id"])
    assert held["status"] == "review" and not held.get("receipt")
    audit = (await client.get("/admin/api/opossum/audit", headers=ADMIN)).json()
    assert any(e["action"] == "sanctioned_sender" for e in (audit.get("entries") if isinstance(audit, dict) else audit))


# ================================================================== USDC


async def test_usdc_unique_amount_and_settlement(app, client, chain, merchant, payer):
    q, tx = await pay_on_chain(payer, "usdc-base", "25.00")
    how = tx["pay_on_chain"]
    amount = Decimal(how["amount"])
    assert Decimal("25.000001") <= amount <= Decimal("25.009999") and how["address"] == MERCHANT_EVM
    atomic = cu.to_atomic(amount, 6)
    assert how["uri"] == f"ethereum:{chains.EVM['base'].usdc}@8453/transfer?address={MERCHANT_EVM}&uint256={atomic}"
    assert how["confirmations_needed"] == 20

    chain.send_usdc("base", MERCHANT_EVM, atomic - 1, txid="0x" + "01" * 32)  # wrong amount: not ours
    chain.send_usdc("base", MERCHANT_EVM, atomic, txid="0x" + "02" * 32, block=chain.evm_tip)
    assert await watch(app) == 0
    assert (await payment(client, tx["id"]))["status"] == "confirming"

    chain.evm_tip += 19
    assert await watch(app) == 1
    done = await payment(client, tx["id"])
    assert done["status"] == "settled" and done["chain_txid"] == "0x" + "02" * 32 and done["crypto_amount"] == how["amount"]

    # A second payment given the same amount can never be settled by the same transfer.
    _, again = await pay_on_chain(payer, "usdc-base", "25.00", confirm_duplicate=True)
    async with app.state.services.db.session() as session, session.begin():
        await session.execute(update(OpTransaction).where(OpTransaction.id == again["id"]).values(crypto_amount=how["amount"],
                                                                                                    chain_from_block=0))
    assert await watch(app) == 0
    assert (await payment(client, again["id"]))["status"] == "awaiting_chain"


async def test_usdc_needs_a_reachable_network(client, chain, merchant, payer):
    q = await payer.quote("zorak", "10.00", rail="usdc-polygon")  # no RPC configured for polygon in this test
    body = payer.payment_body("zorak", "10.00", rail="usdc-polygon")
    r = await payer.pay(body, expected_total=q["total_cost"])
    assert r.status_code == 503 and r.json()["error"]["code"] == "chain_unavailable"


async def test_rails_are_checked(client, chain, merchant, payer):
    r = await client.post("/opossum/api/quote", json={"recipient": "zorak", "amount": "10.00", "rail": "usdc-solana"})
    assert r.status_code == 400 and r.json()["error"]["code"] == "rail_unavailable"
    r = await client.post("/opossum/api/quote", json={"recipient": "zorak", "amount": "10.00", "currency": "EUR", "rail": "btc"})
    assert r.status_code == 400
    r = await client.post("/opossum/api/quote", json={"recipient": "north-coffee", "amount": "10.00", "rail": "btc"})
    assert r.status_code == 400 and r.json()["error"]["code"] == "rail_unavailable"


# ================================================================== refunds and fees


async def test_chain_refund_needs_the_refund_transaction(app, client, upstream, chain, merchant, payer):
    _, tx = await pay_on_chain(payer, "usdc-base", "40.00")
    atomic = cu.to_atomic(Decimal(tx["pay_on_chain"]["amount"]), 6)
    chain.send_usdc("base", MERCHANT_EVM, atomic)
    chain.evm_tip += 30
    assert await watch(app) == 1
    headers = await merchant_key(client, merchant["id"])
    assert (await client.get("/opossum/merchant/api/fees", headers=headers)).json() == {"fees_due_usd": "1.20"}

    r = await client.post(f"/opossum/merchant/api/payments/{tx['id']}/refund", headers=headers, json={})
    assert r.status_code == 409 and r.json()["error"]["code"] == "refund_on_chain"
    r = await client.post(f"/opossum/merchant/api/payments/{tx['id']}/refund", headers=headers, json={"txid": "0x1234"})
    assert r.status_code == 409
    r = await client.post(f"/opossum/merchant/api/payments/{tx['id']}/refund", headers=headers, json={"txid": "0x" + "ef" * 32})
    assert r.status_code == 200 and r.json()["status"] == "refunded"
    assert (await client.get("/opossum/merchant/api/fees", headers=headers)).json() == {"fees_due_usd": "0.00"}
    assert not [q for q in upstream.requests if q.url.path == "/v1/refunds"]  # the merchant's wallet sent it, not Stripe


async def test_admin_records_fees_paid(app, client, chain, merchant, payer):
    _, tx = await pay_on_chain(payer, "usdc-base", "100.00")
    chain.send_usdc("base", MERCHANT_EVM, cu.to_atomic(Decimal(tx["pay_on_chain"]["amount"]), 6))
    chain.evm_tip += 30
    assert await watch(app) == 1
    r = await client.post(f"/admin/api/opossum/recipients/{merchant['id']}/fees-paid", headers=ADMIN, json={"amount": "5"})
    assert r.status_code == 400
    r = await client.post(f"/admin/api/opossum/recipients/{merchant['id']}/fees-paid", headers=ADMIN, json={"amount": "2.50"})
    assert r.status_code == 200 and r.json() == {"fees_due": "0.50"}


# ================================================================== Stripe stablecoins and the OFAC list


async def test_stripe_stablecoin_payment_is_labelled_on_the_receipt(client, upstream, payer):
    await admin_create_recipient(client, processor="stripe", processor_account="platform")
    upstream.on("/v1/payment_intents/pi_live_1", lambda req: httpx.Response(200, json={"id": "pi_live_1", "latest_charge": {
        "payment_method_details": {"type": "crypto", "crypto": {"network": "base", "token_currency": "usdc",
                                                                "transaction_hash": "0x" + "ab" * 32}}}}))
    tx = await paid_by_stripe(client, upstream, payer)
    done = await payment(client, tx["id"])
    proof = present(done["receipt"], ["payment_method", "chain", "crypto_asset", "crypto_txid"])
    v = (await client.post("/opossum/api/verify", json={"presentation": proof})).json()
    assert v["disclosed"] == {"payment_method": "stablecoin via Stripe", "chain": "base", "crypto_asset": "USDC",
                              "crypto_txid": "0x" + "ab" * 32}


def test_ofac_crypto_addresses_are_parsed():
    remarks = ('123,"SOME ENTITY",-0-,"CYBER2",... "Digital Currency Address - XBT 1AjZPMsnmpdK2Rv9KQNfMurTXinscVro9V; '
               'Digital Currency Address - ETH 0x7F367cC41522cE07553e823bf3be79A889DEbe1B; alt. Digital Currency Address - '
               'USDT TXYZabc1234567890abcdefghijklmnopq."')
    found = sanctions.parse_addresses(remarks)
    assert "1AjZPMsnmpdK2Rv9KQNfMurTXinscVro9V" in found and "0x7F367cC41522cE07553e823bf3be79A889DEbe1B" in found
    assert "TXYZabc1234567890abcdefghijklmnopq" in found
    assert sanctions.address_key("0x7F367cC41522cE07553e823bf3be79A889DEbe1B") == "addr:0x7f367cc41522ce07553e823bf3be79a889debe1b"
    assert sanctions.address_key("1AjZPMsnmpdK2Rv9KQNfMurTXinscVro9V") == "addr:1AjZPMsnmpdK2Rv9KQNfMurTXinscVro9V"


async def test_sender_screening_ignores_case_for_evm(app):
    await sanctions.load_addresses(app.state.services, ["0x7F367cC41522cE07553e823bf3be79A889DEbe1B"], "test")
    async with app.state.services.db.session() as session:
        assert await sanctions.screen_addresses(session, ["0x7f367cc41522ce07553e823bf3be79a889debe1b"])
        assert not await sanctions.screen_addresses(session, [PAYER_EVM])


async def test_ofac_refresh_is_due_until_crypto_addresses_are_loaded(app):
    services = app.state.services
    services.settings.opossum_ofac_enabled = True
    try:
        await sanctions.load_names(services, sanctions.LIST_NAME, ["SMITH, John"], "test")
        assert await sanctions.due(services)  # names are fresh, but no address list yet
        await sanctions.load_addresses(services, ["0x7F367cC41522cE07553e823bf3be79A889DEbe1B"], "test")
        assert not await sanctions.due(services)
    finally:
        services.settings.opossum_ofac_enabled = False


async def test_live_selftest_reads_real_chain_shapes_without_writing(app, client, chain):
    chain.send_btc(SECOND, 150_000, txid="ee" * 32, height=chain.btc_tip - 3)
    chain.send_usdc("base", MERCHANT_EVM, 12_340_000, txid="0x" + "0f" * 32, block=chain.evm_tip - 35)
    r = await client.post("/admin/api/opossum/chains/selftest", headers=ADMIN)
    assert r.status_code == 200, r.text
    out = r.json()
    btc, base = out["btc"], out["usdc-base"]
    assert btc["ok"] and btc["sample_tx"] == "ee" * 32 and btc["amount"] == "0.00150000" and btc["confirmations"] == 4
    assert btc["would_settle"] and btc["receipt_signed_and_verified"] and btc["sender_screened"] == [PAYER_BTC]
    assert base["ok"] and base["sample_tx"] == "0x" + "0f" * 32 and base["amount"] == "12.340000" and base["confirmations"] == 36
    assert base["to"] == MERCHANT_EVM and base["would_settle"]
    assert not out["usdc-polygon"]["ok"] and "polygon" in out["usdc-polygon"]["error"]  # no RPC configured in this test
    async with app.state.services.db.session() as session:
        assert (await session.scalar(select(func.count()).select_from(OpTransaction))) == 0
