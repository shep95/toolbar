"""Direct on-chain payments to a merchant's own wallet (non-custodial).

Opossum never holds coins or private keys. It hands the payer an address and
an exact amount, watches the blockchain, and when the payment has enough
confirmations it settles the relay record and signs a receipt, exactly as for
card payments.

Rails:

* ``btc``: Bitcoin. Each payment gets a fresh address derived from the
  merchant's extended public key (xpub/ypub/zpub), so one merchant's payments
  are not linked by address reuse. Price locked from a public BTC-USD spot
  quote for ``OPOSSUM_CHAIN_QUOTE_MINUTES``.
* ``usdc-<network>``: USDC on Ethereum, Base, Polygon, Arbitrum or Optimism,
  1 USDC = 1 USD. Payments go to the merchant's address; each payment's
  amount carries a unique tail of up to 0.009999 USDC so it can be matched.

What a blockchain makes public cannot be made private here: amounts, the
paying wallet and the receiving address are visible to anyone. Opossum keeps
the payer's identity from the merchant and keeps the payer's ledger private;
it does not mix or obscure funds. Senders are screened against the crypto
addresses on the OFAC SDN list.
"""

from __future__ import annotations

import json
import logging
import secrets
import time
from dataclasses import dataclass
from datetime import timedelta
from decimal import ROUND_CEILING, Decimal

import httpx
from sqlalchemy import and_, func, or_, select

from ..models import utcnow
from ..services import Services
from . import chainutil as cu
from .models import OpChainAddress, OpRecipient, OpTransaction
from .web import OpError

log = logging.getLogger("aiproxy.opossum")

TRANSFER_TOPIC = "0x" + cu.keccak256(b"Transfer(address,address,uint256)").hex()


@dataclass(frozen=True)
class Network:
    key: str
    label: str
    chain_id: int
    usdc: str
    confirmations: int
    explorer: str


EVM = {
    "ethereum": Network("ethereum", "Ethereum", 1, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 12, "https://etherscan.io/tx/"),
    "base": Network("base", "Base", 8453, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", 20, "https://basescan.org/tx/"),
    "polygon": Network("polygon", "Polygon", 137, "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", 64, "https://polygonscan.com/tx/"),
    "arbitrum": Network("arbitrum", "Arbitrum One", 42161, "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", 20, "https://arbiscan.io/tx/"),
    "optimism": Network("optimism", "OP Mainnet", 10, "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", 20, "https://optimistic.etherscan.io/tx/"),
}
USDC_DECIMALS = 6
BTC_DECIMALS = 8
LATE_WATCH_HOURS = 24
# A transaction already seen on chain is followed longer (a low-fee Bitcoin
# transaction can wait days for a block).
CONFIRMING_WATCH_DAYS = 14


def rail_label(rail: str) -> str:
    if rail == "btc":
        return "Bitcoin"
    return "USDC on " + EVM[rail.split("-", 1)[1]].label


def all_rails() -> list[str]:
    return ["btc"] + [f"usdc-{k}" for k in EVM]


# ---------------------------------------------------------------- merchant setup


def configure(xpub: str | None, first_address: str | None, address_type: str | None, evm_address: str | None) -> dict:
    """Validate a merchant's receiving setup. The first derived Bitcoin address
    must match what their wallet shows, so a wrong key type can never send
    customers' coins somewhere the merchant's wallet does not watch."""
    config: dict = {}
    if xpub:
        key = cu.parse_xpub(xpub)
        kind = address_type or cu.default_address_type(key)
        if kind not in ("p2wpkh", "p2sh-p2wpkh", "p2pkh"):
            raise cu.ChainError("address_type must be p2wpkh, p2sh-p2wpkh or p2pkh")
        derived = cu.derive_receive_address(xpub, 0, kind)
        if not first_address or first_address.strip() != derived:
            raise cu.ChainError(f"enter your wallet's first receiving address to confirm; this key with {kind} gives {derived}")
        config["btc"] = {"xpub": xpub.strip(), "type": kind, "first_address": derived}
    if evm_address:
        if not cu.valid_evm_address(evm_address):
            raise cu.ChainError("that is not a valid 0x address (check its capitalisation)")
        config["evm"] = {"address": cu.checksum_address(evm_address.lower())}
    if not config:
        raise cu.ChainError("give a Bitcoin xpub and/or a USDC receiving address")
    return config


def rails_for(config: dict | None) -> list[str]:
    if not config:
        return []
    rails = ["btc"] if "btc" in config else []
    if "evm" in config:
        rails += [f"usdc-{k}" for k in EVM]
    return rails


# ---------------------------------------------------------------- prices

_PRICE_CACHE: dict[str, tuple[float, Decimal]] = {}


async def btc_usd(services: Services) -> Decimal:
    cached = _PRICE_CACHE.get("BTC-USD")
    if cached and time.monotonic() - cached[0] < 60:
        return cached[1]
    url = services.settings.opossum_price_api.format(pair="BTC-USD")
    try:
        resp = await services.http.get(url, timeout=10.0)
        price = Decimal(str(resp.json()["data"]["amount"]))
    except (httpx.HTTPError, KeyError, ValueError, ArithmeticError):
        raise OpError(503, "price_unavailable", "the bitcoin price could not be fetched; try again shortly") from None
    if not price.is_finite() or price <= 0:
        raise OpError(503, "price_unavailable", "the bitcoin price looks wrong; try again shortly")
    _PRICE_CACHE["BTC-USD"] = (time.monotonic(), price)
    return price


# ---------------------------------------------------------------- chain access


async def _rpc(services: Services, network: str, method: str, params: list):
    urls = json.loads(services.settings.opossum_evm_rpc)
    url = urls.get(network)
    if not url:
        raise OpError(503, "chain_unavailable", f"no RPC endpoint configured for {network}")
    resp = await services.http.post(url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=15.0)
    body = resp.json()
    if "error" in body:
        raise httpx.HTTPError(f"rpc error: {body['error']}")
    return body["result"]


async def evm_block(services: Services, network: str) -> int:
    return int(await _rpc(services, network, "eth_blockNumber", []), 16)


async def usdc_transfers(services: Services, network: str, to: str, from_block: int) -> list[dict]:
    net = EVM[network]
    latest = await evm_block(services, network)
    logs = await _rpc(services, network, "eth_getLogs", [{
        "fromBlock": hex(max(0, from_block)), "toBlock": hex(latest), "address": net.usdc,
        "topics": [TRANSFER_TOPIC, None, "0x" + "0" * 24 + to[2:].lower()],
    }])
    out = []
    for entry in logs:
        if entry.get("removed"):
            continue
        out.append({
            "txid": entry["transactionHash"], "value": int(entry["data"], 16),
            "sender": "0x" + entry["topics"][1][-40:], "confirmations": latest - int(entry["blockNumber"], 16) + 1,
        })
    return out


async def btc_payments(services: Services, address: str) -> list[dict]:
    api = services.settings.opossum_btc_api.rstrip("/")
    tip = int((await services.http.get(f"{api}/blocks/tip/height", timeout=15.0)).text.strip())
    txs = (await services.http.get(f"{api}/address/{address}/txs", timeout=15.0)).json()
    out = []
    for tx in txs:
        value = sum(int(v.get("value", 0)) for v in tx.get("vout", []) if v.get("scriptpubkey_address") == address)
        if not value:
            continue
        status = tx.get("status") or {}
        confirmations = tip - int(status["block_height"]) + 1 if status.get("confirmed") else 0
        senders = sorted({(v.get("prevout") or {}).get("scriptpubkey_address") for v in tx.get("vin", [])} - {None})
        out.append({"txid": tx["txid"], "value": value, "confirmations": confirmations, "senders": senders})
    return out


# ---------------------------------------------------------------- quoting a payment


async def prepare(services: Services, session, recipient: OpRecipient, config: dict, rail: str, amount_usd: Decimal, tx_id: str) -> dict:
    """Pick the deposit address and exact crypto amount for a new payment."""
    expires = utcnow() + timedelta(minutes=max(5, services.settings.opossum_chain_quote_minutes))
    if rail == "btc":
        if "btc" not in config:
            raise OpError(400, "rail_unavailable", "this recipient does not accept Bitcoin")
        price = await btc_usd(services)
        btc = (amount_usd / price).quantize(Decimal("0.00000001"), rounding=ROUND_CEILING)
        index = (await session.scalar(select(func.max(OpChainAddress.derivation_index)).where(
            OpChainAddress.recipient_id == recipient.id)))
        index = 1 if index is None else index + 1  # index 0 is the one the merchant confirmed at setup
        address = cu.derive_receive_address(config["btc"]["xpub"], index, config["btc"]["type"])
        session.add(OpChainAddress(address=address, recipient_id=recipient.id, derivation_index=index, tx_id=tx_id))
        return {"rail": rail, "asset": "BTC", "crypto_amount": format(btc, "f"), "deposit_address": address, "rate_usd": str(price),
                "quote_expires_at": expires, "chain_from_block": None,
                "uri": cu.bip21_uri(address, btc, recipient.display_name)}
    network = rail.split("-", 1)[1] if rail.startswith("usdc-") else ""
    if network not in EVM or "evm" not in config:
        raise OpError(400, "rail_unavailable", "this recipient does not accept that payment method")
    to = config["evm"]["address"]
    base = cu.to_atomic(amount_usd, USDC_DECIMALS)
    taken = set((await session.execute(select(OpTransaction.crypto_amount).where(
        OpTransaction.recipient_id == recipient.id, OpTransaction.rail == rail,
        OpTransaction.status.in_(("awaiting_chain", "confirming", "expired"))))).scalars())
    for _ in range(50):
        atomic = base + secrets.randbelow(9999) + 1
        amount = cu.from_atomic(atomic, USDC_DECIMALS)
        if format(amount, "f") not in taken:
            break
    else:
        raise OpError(503, "busy", "too many open payments to this recipient; try again in a minute")
    try:
        start = await evm_block(services, network)
    except (httpx.HTTPError, ValueError, KeyError):
        raise OpError(503, "chain_unavailable", f"{EVM[network].label} could not be reached; try another network") from None
    return {"rail": rail, "asset": "USDC", "crypto_amount": format(amount, "f"), "deposit_address": to, "rate_usd": "1",
            "quote_expires_at": expires, "chain_from_block": start - 5,
            "uri": cu.eip681_token_uri(EVM[network].usdc, EVM[network].chain_id, to, atomic)}


def qr_svg(uri: str) -> str:
    import segno

    return segno.make(uri, error="m").svg_data_uri(scale=5, border=2, dark="#070914", light="#eef0f8")


def required_confirmations(settings, rail: str) -> int:
    if rail == "btc":
        return max(1, settings.opossum_btc_confirmations)
    return EVM[rail.split("-", 1)[1]].confirmations


def payment_uri(tx: OpTransaction) -> str:
    if tx.rail == "btc":
        return cu.bip21_uri(tx.deposit_address, Decimal(tx.crypto_amount))
    net = EVM[tx.rail.split("-", 1)[1]]
    return cu.eip681_token_uri(net.usdc, net.chain_id, tx.deposit_address, cu.to_atomic(Decimal(tx.crypto_amount), USDC_DECIMALS))


def instructions(tx: OpTransaction, settings) -> dict | None:
    """What the payer's wallet needs: address, exact amount, a payment link and a QR code."""
    if not tx.rail or not tx.deposit_address:
        return None
    from .web import aware

    uri = payment_uri(tx)
    explorer = "https://mempool.space/tx/" if tx.rail == "btc" else EVM[tx.rail.split("-", 1)[1]].explorer
    return {
        "rail": tx.rail, "label": rail_label(tx.rail), "asset": tx.asset, "amount": tx.crypto_amount, "address": tx.deposit_address,
        "uri": uri, "qr": qr_svg(uri), "rate_usd": tx.rate_usd, "received": tx.crypto_received,
        "txid": tx.chain_txid, "explorer": explorer + tx.chain_txid if tx.chain_txid else None,
        "confirmations": tx.confirmations or 0, "confirmations_needed": required_confirmations(settings, tx.rail),
        "expires_at": aware(tx.quote_expires_at).isoformat() if tx.quote_expires_at else None,
        "network_fee": "paid by your wallet to the network; not part of the price",
    }


# ---------------------------------------------------------------- watching the chain


async def _observe(services: Services, tx: OpTransaction, claimed: set[str]) -> dict | None:
    """What the chain shows for this payment, or None if nothing yet.

    ``claimed`` holds transfers already matched to other payments, so one
    transfer can never settle two payments."""
    if tx.rail == "btc":
        payments = await btc_payments(services, tx.deposit_address)
        if not payments:
            return None
        total = sum(p["value"] for p in payments)
        return {"received": cu.from_atomic(total, BTC_DECIMALS), "txid": payments[0]["txid"],
                "confirmations": min(p["confirmations"] for p in payments),
                "senders": sorted({s for p in payments for s in p["senders"]}),
                "complete": total >= cu.to_atomic(Decimal(tx.crypto_amount), BTC_DECIMALS)}
    network = tx.rail.split("-", 1)[1]
    expected = cu.to_atomic(Decimal(tx.crypto_amount), USDC_DECIMALS)
    for t in await usdc_transfers(services, network, tx.deposit_address, tx.chain_from_block or 0):
        if t["value"] == expected and t["txid"].lower() not in claimed:
            return {"received": cu.from_atomic(t["value"], USDC_DECIMALS), "txid": t["txid"], "confirmations": t["confirmations"],
                    "senders": [t["sender"]], "complete": True}
    return None


async def watch(services: Services) -> int:
    """Advance open on-chain payments. Returns how many settled."""
    from . import audit, webhooks
    from .relay import recipient_view, settle
    from .sanctions import screen_addresses
    from .web import aware, keys

    k = keys(services)
    now = utcnow()
    async with services.db.session() as session:
        open_rows = (await session.execute(select(OpTransaction.id).where(
            OpTransaction.processor == "chain",
            or_(and_(OpTransaction.status.in_(("awaiting_chain", "expired")), OpTransaction.created_at >= now - timedelta(hours=LATE_WATCH_HOURS)),
                and_(OpTransaction.status == "confirming", OpTransaction.created_at >= now - timedelta(days=CONFIRMING_WATCH_DAYS))),
        ).order_by(OpTransaction.created_at).limit(100))).scalars().all()
    settled = 0
    for tx_id in open_rows:
        async with services.db.session() as session:
            tx = await session.get(OpTransaction, tx_id)
            claimed = set()
            if tx.rail != "btc":
                claimed = {t.lower() for t in (await session.execute(select(OpTransaction.chain_txid).where(
                    OpTransaction.rail == tx.rail, OpTransaction.id != tx.id, OpTransaction.chain_txid.is_not(None)))).scalars()}
        try:
            seen = await _observe(services, tx, claimed)
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            log.warning("chain watch failed for %s", tx_id)
            continue
        async with services.db.session() as session, session.begin():
            tx = await session.get(OpTransaction, tx_id)
            if tx.status not in ("awaiting_chain", "confirming", "expired"):
                continue
            recipient = await session.get(OpRecipient, tx.recipient_id)
            expired = tx.quote_expires_at is not None and now > aware(tx.quote_expires_at)
            if seen is None:
                if expired and tx.status == "awaiting_chain":
                    tx.status = "expired"
                    await audit.append(session, "chain", "payment_expired", tx.id)
                continue
            tx.crypto_received, tx.chain_txid, tx.confirmations = format(seen["received"], "f"), seen["txid"][:100], seen["confirmations"]
            hit = await screen_addresses(session, seen["senders"])
            if hit:
                # Never settled automatically; a compliance officer decides.
                tx.status = "review"
                await audit.append(session, "compliance", "sanctioned_sender", tx.id, list=hit)
                webhooks.enqueue(session, recipient, "payment.review", recipient_view(k, tx))
                continue
            if not seen["complete"]:
                if expired:
                    tx.status = "underpaid"
                    await audit.append(session, "chain", "payment_underpaid", tx.id, received=tx.crypto_received)
                else:
                    tx.status = "confirming"
                continue
            if seen["confirmations"] < required_confirmations(services.settings, tx.rail):
                tx.status = "confirming"
                continue
            if tx.status == "expired" and tx.rail == "btc":
                # The price lock ran out before the coins arrived: the merchant decides.
                tx.status = "received_late"
                await audit.append(session, "chain", "payment_received_late", tx.id)
                continue
            await settle(session, k, tx, extra={
                "payment_method": "crypto", "chain": rail_label(tx.rail), "crypto_asset": tx.asset,
                "crypto_amount": tx.crypto_amount, "crypto_txid": tx.chain_txid, "deposit_address": tx.deposit_address,
                "rate_usd": tx.rate_usd,
            })
            recipient.fees_due = (recipient.fees_due or Decimal("0")) + tx.opossum_fee
            settled += 1
    return settled
