"""The Opossum Relay: turns a signed payment request into a processor payment.

What the relay learns about a payment: the amount, currency, type, the
recipient, the fees, the payer's pseudonym and anything the payer chose to
show the recipient. What it never receives: the payer's category, notes or
budget (a note can be *committed* to as a hash so it can be proven later).

What the recipient learns: the amount, what they receive, the transaction ID,
the payer's pseudonym, and only the identity fields the payer chose to show.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from datetime import timedelta
from decimal import Decimal, InvalidOperation

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ..models import utcnow
from ..services import Services
from . import audit, webhooks
from .compliance import ComplianceBlock, check_payment
from .crypto import RelayKeys, random_id
from .fees import FeeError, Quote, Rule, choose_rule, quote
from .models import OpAccount, OpFeeRule, OpIdempotency, OpIdentity, OpInvoice, OpNonce, OpRecipient, OpTransaction
from .processors import ProcessorError, minor_units, start_payment
from .web import OpError, aware

log = logging.getLogger("aiproxy.opossum")

TX_TYPES = ("purchase", "bill", "subscription", "donation", "transfer", "invoice", "reimbursement", "other")
MODES = ("public", "pseudonymous", "private", "disclosure")
# Identity fields a payer can choose to show a recipient.
RECIPIENT_DISCLOSABLE = ("legal_name", "email")
REQUEST_MAX_AGE_SECONDS = 300
DUPLICATE_WINDOW_SECONDS = 120
IDEMPOTENCY_HOURS = 24
HANDLE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$")


def currencies(services: Services) -> list[str]:
    return [c.strip().upper() for c in services.settings.opossum_currencies.split(",") if c.strip()]


def default_rule(services: Services) -> Rule:
    return Rule(id="default", name="standard", percent=services.settings.opossum_fee_percent)


def rule_from_row(row: OpFeeRule) -> Rule:
    return Rule(
        id=str(row.id), name=row.name, percent=row.percent, flat=row.flat, minimum=row.minimum, maximum=row.maximum,
        recipient_id=str(row.recipient_id) if row.recipient_id else None, tx_type=row.tx_type,
        starts_at=aware(row.starts_at) if row.starts_at else None, ends_at=aware(row.ends_at) if row.ends_at else None,
        priority=row.priority,
    )


def parse_amount(value) -> Decimal:
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise OpError(400, "invalid_amount", "amount must be a number like 12.50") from None
    if not amount.is_finite() or amount <= 0 or amount > Decimal("1000000"):
        raise OpError(400, "invalid_amount", "amount must be above 0 and at most 1,000,000")
    return amount


def recipient_rails(r: OpRecipient) -> list[str]:
    rails = ["card"] if r.processor in ("stripe", "sandbox") else []
    return rails + [x for x in (r.chain_rails or "").split(",") if x]


async def compute_quote(services: Services, session, recipient: OpRecipient, amount, currency: str, tx_type: str, fee_bearer: str,
                        rail: str = "card") -> Quote:
    on_chain = rail != "card"
    if on_chain:
        if not services.settings.opossum_chain_enabled or rail not in recipient_rails(recipient):
            raise OpError(400, "rail_unavailable", "this recipient does not accept that payment method")
        if currency != "USD":
            raise OpError(400, "unsupported_currency", "crypto payments are priced in USD")
        fee_bearer = "recipient"  # on-chain the recipient gets the full amount and is billed Opossum's fee
    if currency not in currencies(services):
        raise OpError(400, "unsupported_currency", f"currency must be one of {', '.join(currencies(services))}")
    if tx_type not in TX_TYPES:
        raise OpError(400, "invalid_type", f"type must be one of {', '.join(TX_TYPES)}")
    rows = (await session.execute(select(OpFeeRule).where(OpFeeRule.active.is_(True)))).scalars().all()
    rule = choose_rule([rule_from_row(r) for r in rows], default_rule(services), str(recipient.id), tx_type, utcnow())
    try:
        return quote(
            parse_amount(amount), currency, rule,
            processor_percent=Decimal("0") if on_chain else services.settings.opossum_processor_fee_percent,
            processor_flat=Decimal("0") if on_chain else services.settings.opossum_processor_fee_flat,
            fee_bearer=fee_bearer,
        )
    except FeeError as exc:
        raise OpError(400, "invalid_amount", str(exc)) from None


async def find_recipient(session, handle: str) -> OpRecipient:
    if not isinstance(handle, str) or not HANDLE_RE.match(handle):
        raise OpError(404, "unknown_recipient", "no recipient with that handle")
    recipient = await session.scalar(select(OpRecipient).where(OpRecipient.handle == handle))
    if recipient is None or recipient.status != "active":
        raise OpError(404, "unknown_recipient", "no recipient with that handle")
    return recipient


# ---------------------------------------------------------------- views


def recipient_public(r: OpRecipient) -> dict:
    from .chains import rail_label

    rails = recipient_rails(r)
    return {"handle": r.handle, "name": r.display_name, "category": r.category, "country": r.country,
            "test_money": r.processor == "sandbox",
            "rails": [{"id": x, "label": ("card or stablecoin (Stripe)" if r.processor == "stripe" else "card (test money)") if x == "card"
                       else rail_label(x)} for x in rails]}


def chain_fields(tx: OpTransaction) -> dict:
    if not tx.rail or tx.rail == "card":
        return {}
    return {"rail": tx.rail, "crypto_asset": tx.asset, "crypto_amount": tx.crypto_amount, "crypto_received": tx.crypto_received,
            "chain_txid": tx.chain_txid, "confirmations": tx.confirmations or 0}


def money(value) -> str:
    """Money as a string with exactly two decimals (the database keeps six)."""
    return str(Decimal(value).quantize(Decimal("0.01")))


def money_fields(tx: OpTransaction) -> dict:
    return {
        "amount": money(tx.amount), "currency": tx.currency, "opossum_fee": money(tx.opossum_fee),
        "processor_fee": money(tx.processor_fee), "total_cost": money(tx.total_cost),
        "recipient_receives": money(tx.recipient_receives), "fee_bearer": tx.fee_bearer,
    }


def owner_view(keys: RelayKeys, tx: OpTransaction, recipient: OpRecipient, settings=None) -> dict:
    view = {
        "id": tx.id, "status": tx.status, "type": tx.tx_type, "mode": tx.mode, "payer_pseudonym": tx.payer_pseudonym,
        "recipient": recipient_public(recipient), "invoice_id": tx.invoice_id, **money_fields(tx),
        "fee_rule": tx.fee_rule, "created_at": aware(tx.created_at).isoformat(),
        "settled_at": aware(tx.settled_at).isoformat() if tx.settled_at else None,
        "refunded_at": aware(tx.refunded_at).isoformat() if tx.refunded_at else None,
        "test_money": tx.processor == "sandbox", "shown_to_recipient": [],
    }
    if tx.disclosed_enc:
        view["shown_to_recipient"] = sorted(keys.open(tx.disclosed_enc, f"op_transactions:{tx.id}:disclosed").keys())
    if tx.status == "settled" and tx.receipt_enc:
        stored = keys.open(tx.receipt_enc, f"op_transactions:{tx.id}:receipt")
        view["receipt"] = {"sd_jwt": stored["sd_jwt"], "disclosures": stored["disclosures"]}
    view.update(chain_fields(tx))
    if settings is not None and tx.rail and tx.rail != "card" and tx.status in ("awaiting_chain", "confirming", "expired", "underpaid"):
        from .chains import instructions

        view["pay_on_chain"] = instructions(tx, settings)
    return view


def recipient_view(keys: RelayKeys, tx: OpTransaction) -> dict:
    """Everything a recipient gets: no account, no device, no payer notes."""
    payer = {"pseudonym": tx.payer_pseudonym}
    if tx.disclosed_enc:
        payer.update(keys.open(tx.disclosed_enc, f"op_transactions:{tx.id}:disclosed"))
    return {
        "id": tx.id, "status": tx.status, "type": tx.tx_type, "invoice_id": tx.invoice_id, "payer": payer,
        "amount": money(tx.amount), "currency": tx.currency, "you_receive": money(tx.recipient_receives),
        "opossum_fee": money(tx.opossum_fee), "processor_fee": money(tx.processor_fee), "fee_bearer": tx.fee_bearer,
        "created_at": aware(tx.created_at).isoformat(), "settled_at": aware(tx.settled_at).isoformat() if tx.settled_at else None,
        "refunded_at": aware(tx.refunded_at).isoformat() if tx.refunded_at else None,
        "test_money": tx.processor == "sandbox", **chain_fields(tx),
    }


# ---------------------------------------------------------------- creating a payment


def _request_hash(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


async def create_payment(services: Services, keys: RelayKeys, account: OpAccount, device_id: str, body: bytes, base_url: str) -> dict:
    try:
        req = json.loads(body)
    except ValueError:
        req = None
    if not isinstance(req, dict):
        raise OpError(400, "invalid_request", "the payment request is not valid JSON")

    # Replay protection: fresh timestamp and a nonce never seen before.
    ts, nonce, idem = req.get("ts"), req.get("nonce"), req.get("idempotency_key")
    if not isinstance(ts, int) or abs(time.time() - ts) > REQUEST_MAX_AGE_SECONDS:
        raise OpError(400, "stale_request", "the request is too old or its clock is wrong; try again")
    if not isinstance(nonce, str) or not 16 <= len(nonce) <= 64:
        raise OpError(400, "invalid_request", "nonce missing")
    if not isinstance(idem, str) or not 16 <= len(idem) <= 64:
        raise OpError(400, "invalid_request", "idempotency_key missing")

    owner_tag = keys.owner_tag(account.id)
    idem_key = hashlib.sha256(f"{owner_tag}|{idem}".encode()).hexdigest()
    now = utcnow()

    async with services.db.session() as session, session.begin():
        try:
            session.add(OpNonce(nonce=hashlib.sha256(nonce.encode()).hexdigest(), expires_at=now + timedelta(seconds=REQUEST_MAX_AGE_SECONDS * 2)))
            await session.flush()
        except IntegrityError:
            raise OpError(409, "replayed_request", "this signed request was already used") from None
        # Idempotency: a retry (new nonce, same key) returns the same payment, never a second one.
        existing = await session.get(OpIdempotency, idem_key)
        if existing is not None:
            tx = await session.get(OpTransaction, existing.tx_id)
            if existing.request_hash != _request_hash_without_replay_fields(req) or tx is None:
                raise OpError(409, "idempotency_conflict", "this idempotency key was already used for a different payment")
            recipient = await session.get(OpRecipient, tx.recipient_id)
            return {**owner_view(keys, tx, recipient), "replayed": True}

    # Fraud control: payments per hour per account.
    allowed, retry = services.opossum_payment_limiter.check(owner_tag, services.settings.opossum_payments_per_hour)
    if not allowed:
        raise OpError(429, "too_many_payments", "too many payments in the last hour; try again later", retry_after=retry)

    mode = req.get("mode", "pseudonymous")
    if mode not in MODES:
        raise OpError(400, "invalid_mode", f"mode must be one of {', '.join(MODES)}")
    fee_bearer = req.get("fee_bearer", "recipient")
    rail = req.get("rail") or "card"
    if not isinstance(rail, str) or len(rail) > 24:
        raise OpError(400, "invalid_request", "rail must be a payment method id")
    currency = str(req.get("currency", "USD")).upper()
    tx_type = req.get("type", "purchase")
    memo_commitment = req.get("memo_commitment")
    if memo_commitment is not None and not (isinstance(memo_commitment, str) and re.fullmatch(r"[0-9a-f]{64}", memo_commitment)):
        raise OpError(400, "invalid_request", "memo_commitment must be a sha-256 hex digest")
    message = req.get("message_to_recipient")
    if message is not None and (not isinstance(message, str) or len(message) > 200):
        raise OpError(400, "invalid_request", "message_to_recipient is limited to 200 characters")
    chosen = req.get("disclose") or []
    if not isinstance(chosen, list) or any(f not in RECIPIENT_DISCLOSABLE for f in chosen):
        raise OpError(400, "invalid_request", f"disclose can list: {', '.join(RECIPIENT_DISCLOSABLE)}")

    async with services.db.session() as session, session.begin():
        recipient = await find_recipient(session, req.get("recipient"))
        invoice = None
        if req.get("invoice"):
            invoice = await session.get(OpInvoice, str(req["invoice"])[:40])
            if invoice is None or invoice.recipient_id != recipient.id:
                raise OpError(404, "unknown_invoice", "no such invoice for this recipient")
            if invoice.status != "open":
                raise OpError(409, "invoice_closed", f"this invoice is {invoice.status}")
            if parse_amount(req.get("amount")) != invoice.amount or currency != invoice.currency:
                raise OpError(400, "invoice_mismatch", f"this invoice is for {invoice.amount} {invoice.currency}")
            tx_type = "invoice"
        q = await compute_quote(services, session, recipient, req.get("amount"), currency, tx_type, fee_bearer, rail)
        if str(req.get("expected_total")) != str(q.total_cost):
            raise OpError(409, "quote_changed", "the total changed since you reviewed it; please review again", quote=q.as_dict())

        if services.settings.opossum_require_mfa and not account.mfa_enabled:
            raise OpError(403, "mfa_required", "turn on an authenticator app in security before making payments")
        real_money = recipient.processor != "sandbox" or rail != "card"
        try:
            limits = await check_payment(
                session, services.settings, account_country=account.jurisdiction, kyc_status=account.kyc_status,
                owner_tag=owner_tag, recipient_country=recipient.country, amount_usd_equivalent=q.total_cost, real_money=real_money,
            )
        except ComplianceBlock as exc:
            await audit.append(session, "relay", "payment_blocked", None, code=exc.code, jurisdiction=account.jurisdiction)
            raise OpError(exc.status, exc.code, exc.message) from None

        # Duplicate guard: same recipient and amount moments ago.
        if not req.get("confirm_duplicate"):
            recent = await session.scalar(select(OpTransaction.id).where(
                OpTransaction.owner_tag == owner_tag, OpTransaction.recipient_id == recipient.id,
                OpTransaction.amount == q.amount, OpTransaction.created_at >= now - timedelta(seconds=DUPLICATE_WINDOW_SECONDS),
                OpTransaction.status.in_(("pending_payment", "settled", "awaiting_chain", "confirming")),
            ).limit(1))
            if recent:
                raise OpError(409, "possible_duplicate", "you just paid this recipient the same amount; confirm to pay again")

        identity = None
        row = await session.get(OpIdentity, account.id)
        if row is not None:
            identity = keys.open(row.ciphertext, f"op_identities:{account.id}:doc")

        pseudonym = keys.pairwise_pseudonym(account.id, recipient.id) if mode in ("pseudonymous", "public", "disclosure") else keys.one_time_pseudonym()
        shown: dict = {}
        fields = RECIPIENT_DISCLOSABLE if mode == "public" else (chosen if mode == "disclosure" else ())
        for field in fields:
            if identity and identity.get(field):
                shown[field] = identity[field]
        if message:
            shown["message"] = message

        tx = OpTransaction(
            id=random_id("otx_"), owner_tag=owner_tag, recipient_id=recipient.id, invoice_id=invoice.id if invoice else None,
            tx_type=tx_type, mode=mode, payer_pseudonym=pseudonym, memo_commitment=memo_commitment,
            amount=q.amount, currency=currency, fee_bearer=q.fee_bearer, opossum_fee=q.opossum_fee, processor_fee=q.processor_fee,
            total_cost=q.total_cost, recipient_receives=q.recipient_receives, fee_rule=q.rule.describe()[:80],
            status="creating", processor="chain" if rail != "card" else recipient.processor, created_at=now, rail=rail,
            retain_until=now + timedelta(days=limits.retention_days), compliance_envelope="",
        )
        tx.compliance_envelope = keys.seal({"account_id": str(account.id), "device_id": device_id}, f"op_transactions:{tx.id}:envelope")
        if shown:
            tx.disclosed_enc = keys.seal(shown, f"op_transactions:{tx.id}:disclosed")
        # Receipt claims are fixed now, so settlement never needs the account.
        claims = receipt_claims(tx, recipient, invoice, identity, account.kyc_status)
        tx.receipt_enc = keys.seal({"pending": claims}, f"op_transactions:{tx.id}:receipt")
        session.add(tx)
        session.add(OpIdempotency(key=idem_key, tx_id=tx.id, request_hash=_request_hash_without_replay_fields(req),
                                  expires_at=now + timedelta(hours=IDEMPOTENCY_HOURS)))
        if rail != "card":
            from .chains import prepare

            config = keys.open(recipient.chain_config_enc, f"op_recipients:{recipient.id}:chain") if recipient.chain_config_enc else {}
            plan = await prepare(services, session, recipient, config, rail, q.total_cost, tx.id)
            for key in ("asset", "crypto_amount", "deposit_address", "rate_usd", "quote_expires_at", "chain_from_block"):
                setattr(tx, key, plan[key])
            tx.status = "awaiting_chain"
        await session.flush()
        await audit.append(session, "relay", "payment_created", tx.id, amount=str(tx.amount), currency=currency, mode=mode,
                           recipient=recipient.handle, processor=tx.processor, rail=rail, fee_rule=tx.fee_rule)
        recipient_id = recipient.id
        if rail != "card":
            return owner_view(keys, tx, recipient, services.settings)

    # The processor call happens outside the database transaction.
    async with services.db.session() as session:
        recipient = await session.get(OpRecipient, recipient_id)
        tx = await session.get(OpTransaction, tx.id)
    try:
        started = await start_payment(services, tx, recipient, base_url)
    except ProcessorError as exc:
        async with services.db.session() as session, session.begin():
            row = await session.get(OpTransaction, tx.id)
            row.status = "failed"
            await audit.append(session, "relay", "payment_failed", tx.id, reason=exc.message)
        raise OpError(502, "processor_error", exc.message) from None

    async with services.db.session() as session, session.begin():
        row = await session.get(OpTransaction, tx.id)
        row.processor_ref = started.reference
        if started.status == "settled":
            await settle(session, keys, row)
        else:
            row.status = "pending_payment"
        recipient = await session.get(OpRecipient, row.recipient_id)
        view = owner_view(keys, row, recipient)
    if started.checkout_url:
        view["checkout_url"] = started.checkout_url
    return view


def _request_hash_without_replay_fields(req: dict) -> str:
    stable = {k: v for k, v in req.items() if k not in ("nonce", "ts")}
    return hashlib.sha256(json.dumps(stable, sort_keys=True).encode()).hexdigest()


# ---------------------------------------------------------------- receipts and settlement


def receipt_claims(tx: OpTransaction, recipient: OpRecipient, invoice: OpInvoice | None, identity: dict | None, kyc_status: str) -> dict:
    claims = {
        "transaction_id": tx.id, "type": tx.tx_type, "privacy_mode": tx.mode, **money_fields(tx),
        "recipient_name": recipient.display_name, "recipient_handle": recipient.handle,
        "recipient_category": recipient.category, "payer_pseudonym": tx.payer_pseudonym, "processor": tx.processor,
    }
    if invoice is not None:
        claims["invoice_id"] = invoice.id
        claims["invoice_reference"] = invoice.reference
    if tx.memo_commitment:
        claims["memo_commitment"] = tx.memo_commitment
    if identity and identity.get("legal_name"):
        # Lets the holder prove the payment was theirs, only if they choose to.
        claims["payer_legal_name"] = identity["legal_name"]
        claims["payer_identity_status"] = kyc_status
    return claims


async def settle(session, keys: RelayKeys, tx: OpTransaction, extra: dict | None = None) -> None:
    if tx.status == "settled":
        return
    stored = keys.open(tx.receipt_enc, f"op_transactions:{tx.id}:receipt")
    claims = stored.get("pending") or {}
    claims.update({k: v for k, v in (extra or {}).items() if v is not None})
    now = utcnow()
    claims.update({
        "status": "settled",
        "date": now.date().isoformat(),
        "time": now.strftime("%H:%M:%SZ"),
    })
    sd_jwt, disclosures = keys.issue_receipt(
        claims, {"iss": "opossum-relay", "iat": int(now.timestamp()), "ver": 1, "test": tx.processor == "sandbox"}
    )
    names = list(claims.keys())
    tx.receipt_enc = keys.seal({"sd_jwt": sd_jwt, "disclosures": dict(zip(names, disclosures))}, f"op_transactions:{tx.id}:receipt")
    tx.status = "settled"
    tx.settled_at = now
    recipient = await session.get(OpRecipient, tx.recipient_id)
    if tx.invoice_id:
        invoice = await session.get(OpInvoice, tx.invoice_id)
        if invoice is not None and invoice.status == "open":
            invoice.status = "paid"
            invoice.paid_tx_id = tx.id
            if recipient is not None:
                webhooks.enqueue(session, recipient, "invoice.paid", {"invoice_id": invoice.id, "reference": invoice.reference,
                                                                      "payment": recipient_view(keys, tx)})
    if recipient is not None:
        webhooks.enqueue(session, recipient, "payment.settled", recipient_view(keys, tx))
    await audit.append(session, "relay", "payment_settled", tx.id, processor=tx.processor, receipt_sha256=hashlib.sha256(sd_jwt.encode()).hexdigest())


async def settle_from_stripe(services: Services, event_type: str, obj: dict) -> dict:
    """Called by the Stripe webhook for Checkout Sessions created by the relay."""
    from .web import keys as get_keys

    keys = get_keys(services)
    tx_id = str((obj.get("metadata") or {}).get("opossum_tx") or "")[:40]
    extra = {}
    if event_type != "checkout.session.expired" and obj.get("payment_status") == "paid" and obj.get("payment_intent"):
        from .stripe_ops import payment_details

        extra = await payment_details(services, str(obj["payment_intent"]))
    async with services.db.session() as session, session.begin():
        tx = await session.get(OpTransaction, tx_id)
        if tx is None or tx.processor != "stripe" or tx.processor_ref != obj.get("id"):
            return {"received": True, "ignored": "unknown opossum payment"}
        if event_type == "checkout.session.expired":
            if tx.status == "pending_payment":
                tx.status = "cancelled"
                await audit.append(session, "relay", "payment_cancelled", tx.id, reason="checkout expired")
            return {"received": True, "cancelled": tx.id}
        if obj.get("payment_status") != "paid":
            return {"received": True, "ignored": "not paid yet"}
        if (obj.get("currency") or "").upper() != tx.currency or int(obj.get("amount_total") or -1) != minor_units(tx.total_cost):
            log.error("opossum payment %s paid an unexpected amount", tx.id)
            await audit.append(session, "relay", "payment_amount_mismatch", tx.id)
            return {"received": True, "ignored": "amount mismatch"}
        if obj.get("payment_intent"):
            tx.processor_payment = str(obj["payment_intent"])[:80]
        await settle(session, keys, tx, extra=extra)
    return {"received": True, "settled": tx_id}


# ---------------------------------------------------------------- refunds


async def refund_payment(services: Services, keys: RelayKeys, tx_id: str, *, actor: str, reason: str,
                         recipient_id=None, chain_refund_txid: str | None = None) -> OpTransaction:
    """Refund a settled payment in full, through the processor that took it.

    ``recipient_id`` limits a merchant to refunding its own payments.
    """
    from .processors import PLATFORM_ACCOUNT
    from .stripe_ops import payment_intent_for, refund

    async with services.db.session() as session:
        tx = await session.get(OpTransaction, tx_id[:40])
        if tx is None or (recipient_id is not None and tx.recipient_id != recipient_id):
            raise OpError(404, "unknown_payment", "no such payment")
        if tx.status == "refunded":
            return tx
        if tx.status != "settled":
            raise OpError(409, "not_refundable", f"only settled payments can be refunded; this one is {tx.status}")
        recipient = await session.get(OpRecipient, tx.recipient_id)
    reference = "sbx_refund_" + tx.id.split("_", 1)[1]
    if tx.processor == "chain":
        # Non-custodial: the merchant sends the refund from its own wallet and records it here.
        if not chain_refund_txid or not re.fullmatch(r"(0x)?[0-9a-fA-F]{64}", chain_refund_txid):
            raise OpError(409, "refund_on_chain", "send the refund from your wallet to the payer, then record its transaction id")
        reference = chain_refund_txid
    elif tx.processor == "stripe":
        try:
            intent = tx.processor_payment or await payment_intent_for(services, tx.processor_ref)
            if not intent:
                raise ProcessorError("Stripe has no payment for this checkout yet")
            reference = await refund(services, payment_intent=intent, direct=recipient.processor_account == PLATFORM_ACCOUNT, tx_id=tx.id)
        except ProcessorError as exc:
            raise OpError(502, "processor_error", exc.message) from None
    return await mark_refunded(services, keys, tx.id, reference=reference, actor=actor, reason=reason)


async def mark_refunded(services: Services, keys: RelayKeys, tx_id: str, *, reference: str, actor: str, reason: str) -> OpTransaction:
    async with services.db.session() as session, session.begin():
        tx = await session.get(OpTransaction, tx_id)
        if tx.status == "refunded":
            return tx
        tx.status, tx.refunded_at, tx.refund_ref = "refunded", utcnow(), reference[:80]
        recipient = await session.get(OpRecipient, tx.recipient_id)
        if tx.processor == "chain" and recipient is not None and recipient.fees_due:
            recipient.fees_due = max(Decimal("0"), recipient.fees_due - tx.opossum_fee)
        if tx.invoice_id:
            invoice = await session.get(OpInvoice, tx.invoice_id)
            if invoice is not None and invoice.paid_tx_id == tx.id:
                invoice.status = "refunded"
        if recipient is not None:
            webhooks.enqueue(session, recipient, "payment.refunded", recipient_view(keys, tx))
        await audit.append(session, actor, "payment_refunded", tx.id, reason=reason[:120], reference=reference[:80])
    return tx


async def refund_from_stripe_charge(services: Services, charge: dict) -> dict:
    """charge.refunded: a refund made directly in Stripe is mirrored here."""
    from .web import keys as get_keys

    intent = charge.get("payment_intent")
    if not intent or not charge.get("refunded"):
        return {"received": True, "ignored": "not a full refund"}
    async with services.db.session() as session:
        tx = await session.scalar(select(OpTransaction).where(OpTransaction.processor_payment == str(intent)[:80]))
    if tx is None:
        return {"received": True, "ignored": "not an opossum payment"}
    refunds = ((charge.get("refunds") or {}).get("data") or [{}])
    await mark_refunded(services, get_keys(services), tx.id, reference=str(refunds[0].get("id") or "stripe"), actor="stripe",
                        reason="refunded in Stripe")
    return {"received": True, "refunded": tx.id}
