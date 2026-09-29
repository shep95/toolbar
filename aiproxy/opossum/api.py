"""User-facing Opossum API (``/opossum/api``).

Passwords never reach the server: the browser runs PBKDF2 and sends a derived
"auth key", keeping a second derived key for the ledger to itself. The same
goes for the recovery code. The server stores only scrypt hashes of the
derived keys.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import and_, func, or_, select
from sqlalchemy.exc import IntegrityError

from ..countries import normalise_country
from ..models import utcnow
from ..services import Services, get_services
from . import audit
from .sanctions import screen as screen_name
from .crypto import (
    ReceiptInvalid,
    b64u_decode,
    check_memo,
    check_secret,
    check_totp,
    hash_secret,
    load_device_key,
    new_totp_secret,
    random_id,
    verify_device_signature,
    verify_presentation,
)
from .datamap import DATA_MAP
from .models import OpAccount, OpBackup, OpCase, OpDevice, OpDisclosure, OpIdentity, OpInvoice, OpRecipient, OpTransaction
from .relay import money, MODES, RECIPIENT_DISCLOSABLE, TX_TYPES, compute_quote, create_payment, currencies, find_recipient, owner_view, recipient_public
from .web import OpError, aware, base_url, client_ip, close_session, current_account, end_all_sessions, keys, open_session, same_origin

router = APIRouter(prefix="/opossum/api")

HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_DEVICES = 10
MAX_PAYMENT_BODY = 16_384
_DUMMY_HASH = hash_secret("0" * 64)


def _hex_key(value: str) -> str:
    if not isinstance(value, str) or not HEX64.match(value):
        raise ValueError("must be 64 lowercase hex characters (a key derived in the browser)")
    return value


class DeviceIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    public_jwk: dict

    @field_validator("public_jwk")
    @classmethod
    def _valid_key(cls, value: dict) -> dict:
        load_device_key(value)
        return {k: value[k] for k in ("kty", "crv", "x", "y")}


class SignUp(BaseModel):
    email: EmailStr
    auth_key: str
    recovery_key: str
    kdf_salt: str = Field(min_length=16, max_length=64)
    kdf_iterations: int
    jurisdiction: str
    device: DeviceIn
    wrapped_keys: dict

    _hex = field_validator("auth_key", "recovery_key")(classmethod(lambda cls, v: _hex_key(v)))

    @field_validator("jurisdiction")
    @classmethod
    def _country(cls, value: str) -> str:
        code = normalise_country(value)
        if code is None:
            raise ValueError("country is required")
        return code

    @field_validator("wrapped_keys")
    @classmethod
    def _small(cls, value: dict) -> dict:
        if len(json.dumps(value)) > 4096:
            raise ValueError("wrapped_keys is too large")
        return value


class SignIn(BaseModel):
    email: EmailStr
    auth_key: str
    totp: str | None = Field(default=None, max_length=8)
    # The browser's existing device, and a fresh key to register if that
    # device is unknown or revoked. The new device is approved by this same
    # sign-in (and its authenticator code, when one is set up).
    device_id: str | None = Field(default=None, max_length=40)
    device: DeviceIn | None = None

    _hex = field_validator("auth_key")(classmethod(lambda cls, v: _hex_key(v)))


class Recover(BaseModel):
    email: EmailStr
    recovery_key: str
    new_auth_key: str
    device: DeviceIn

    _hex = field_validator("recovery_key", "new_auth_key")(classmethod(lambda cls, v: _hex_key(v)))


class Identity(BaseModel):
    legal_name: str = Field(min_length=2, max_length=120)
    address_line1: str = Field(min_length=2, max_length=120)
    address_line2: str | None = Field(default=None, max_length=120)
    city: str = Field(min_length=1, max_length=80)
    postal_code: str | None = Field(default=None, max_length=20)
    country: str
    date_of_birth: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")
    phone: str | None = Field(default=None, max_length=30)

    @field_validator("country")
    @classmethod
    def _country(cls, value: str) -> str:
        code = normalise_country(value)
        if code is None:
            raise ValueError("country is required")
        return code


class QuoteIn(BaseModel):
    recipient: str
    amount: str
    currency: str = "USD"
    type: str = "purchase"
    fee_bearer: str = "recipient"
    invoice: str | None = None


class BackupIn(BaseModel):
    expected_version: int = Field(ge=0)
    ciphertext: str


class CodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=6)


class VerifyIn(BaseModel):
    presentation: str = Field(max_length=200_000)
    memo: str | None = Field(default=None, max_length=2000)
    memo_salt: str | None = Field(default=None, max_length=200)


class CloseIn(BaseModel):
    auth_key: str

    _hex = field_validator("auth_key")(classmethod(lambda cls, v: _hex_key(v)))


# ---------------------------------------------------------------- helpers


def _me(services: Services, account: OpAccount, limits: dict | None = None, **extra) -> dict:
    return {
        "jurisdiction": account.jurisdiction, "kyc_status": account.kyc_status, "mfa_enabled": account.mfa_enabled,
        "created_at": aware(account.created_at).isoformat(), "status": account.status,
        "payments_need_mfa": services.settings.opossum_require_mfa, "limits": limits, **extra,
    }


async def _limits(services: Services, session, account: OpAccount) -> dict:
    from .compliance import limits_for

    return (await limits_for(session, services.settings, account.jurisdiction)).as_dict()


def _signin_blocked(services: Services, ip: str, email_index: str) -> None:
    s = services.settings
    for key, limit in ((f"ip:{ip}", s.opossum_signin_failures_per_minute_per_ip), (f"acct:{email_index}", 20)):
        limited, retry = services.opossum_signin_limiter.is_limited(key, limit)
        if limited:
            raise OpError(429, "too_many_attempts", "too many attempts; wait a minute", retry_after=retry)


def _signin_failed(services: Services, ip: str, email_index: str) -> None:
    services.opossum_signin_limiter.check(f"ip:{ip}", 1_000_000)
    services.opossum_signin_limiter.check(f"acct:{email_index}", 1_000_000)


# ---------------------------------------------------------------- public


@router.get("/config")
async def config(request: Request):
    services = get_services(request)
    s = services.settings
    return {
        "enabled": s.opossum_master_key is not None,
        "currencies": currencies(services),
        "fee_percent": str(s.opossum_fee_percent),
        "processor_fee_percent": str(s.opossum_processor_fee_percent),
        "processor_fee_flat": str(s.opossum_processor_fee_flat),
        "kdf_iterations": s.opossum_kdf_iterations,
        "require_mfa": s.opossum_require_mfa,
        "sandbox_enabled": s.opossum_sandbox_enabled,
        "types": list(TX_TYPES),
        "modes": list(MODES),
        "recipient_disclosable": list(RECIPIENT_DISCLOSABLE),
        "session_idle_minutes": s.opossum_session_idle_minutes,
    }


@router.get("/auth/params")
async def auth_params(request: Request, email: EmailStr = Query(...)):
    """Key-derivation salt for an email. Unknown emails get a stable fake
    salt, so this cannot be used to discover who has an account."""
    services = get_services(request)
    k = keys(services)
    index = k.index("email", email.lower())
    async with services.db.session() as session:
        account = await session.scalar(select(OpAccount).where(OpAccount.email_index == index))
    if account is not None:
        return {"kdf_salt": account.kdf_salt, "kdf_iterations": account.kdf_iterations}
    fake = hashlib.sha256((k.index("fake-salt", email.lower())).encode()).digest()[:16]
    from .crypto import b64u

    return {"kdf_salt": b64u(fake), "kdf_iterations": services.settings.opossum_kdf_iterations}


@router.post("/accounts", status_code=201)
async def sign_up(body: SignUp, request: Request):
    services = get_services(request)
    k = keys(services)
    same_origin(request)
    if body.kdf_iterations < services.settings.opossum_kdf_iterations:
        raise OpError(400, "weak_kdf", f"key derivation must use at least {services.settings.opossum_kdf_iterations} iterations")
    try:
        if len(b64u_decode(body.kdf_salt)) < 16:
            raise ValueError
    except ValueError:
        raise OpError(400, "invalid_request", "kdf_salt must be 16+ random bytes, base64url") from None
    email = body.email.lower()
    account = OpAccount(
        email_index=k.index("email", email), kdf_salt=body.kdf_salt, kdf_iterations=body.kdf_iterations,
        auth_hash=hash_secret(body.auth_key), recovery_hash=hash_secret(body.recovery_key),
        jurisdiction=body.jurisdiction, status="active",
    )
    try:
        async with services.db.session() as session, session.begin():
            session.add(account)
            await session.flush()
            session.add(OpIdentity(account_id=account.id, ciphertext=k.seal({"email": email}, f"op_identities:{account.id}:doc")))
            device = OpDevice(id=random_id("dev_"), account_id=account.id, name=body.device.name,
                              public_jwk=json.dumps(body.device.public_jwk), approved_via="signup")
            session.add(device)
            session.add(OpBackup(account_id=account.id, version=0, wrapped_keys=json.dumps(body.wrapped_keys)))
            await audit.append(session, f"account:{k.owner_tag(account.id)[:12]}", "account_created", None, jurisdiction=account.jurisdiction)
            limits = await _limits(services, session, account)
    except IntegrityError:
        raise OpError(409, "account_exists", "an account with this email already exists; sign in instead") from None
    response = JSONResponse(_me(services, account, limits, device_id=device.id), status_code=201)
    await open_session(services, request, response, account)
    return response


@router.post("/session")
async def sign_in(body: SignIn, request: Request):
    services = get_services(request)
    k = keys(services)
    same_origin(request)
    ip = client_ip(request)
    index = k.index("email", body.email.lower())
    _signin_blocked(services, ip, index)
    async with services.db.session() as session:
        account = await session.scalar(select(OpAccount).where(OpAccount.email_index == index))
    ok = check_secret(body.auth_key, account.auth_hash if account else _DUMMY_HASH)
    if not ok or account is None or account.status != "active":
        _signin_failed(services, ip, index)
        raise OpError(401, "wrong_credentials", "that email and password do not match")
    if account.mfa_enabled:
        if not body.totp:
            raise OpError(401, "mfa_required", "enter the 6-digit code from your authenticator app")
        secret = k.open(account.mfa_secret_enc, f"op_accounts:{account.id}:mfa")
        step = check_totp(secret, body.totp, account.mfa_last_step)
        if step is None:
            _signin_failed(services, ip, index)
            raise OpError(401, "wrong_code", "that code is not right or was already used")
        async with services.db.session() as session, session.begin():
            row = await session.get(OpAccount, account.id)
            row.mfa_last_step = step
    device_id = None
    async with services.db.session() as session, session.begin():
        if body.device_id:
            known = await session.get(OpDevice, body.device_id)
            if known is not None and known.account_id == account.id and known.status == "active":
                device_id = known.id
        if device_id is None and body.device is not None:
            active = await session.scalar(select(func.count()).select_from(OpDevice).where(
                OpDevice.account_id == account.id, OpDevice.status == "active"))
            if active >= MAX_DEVICES:
                raise OpError(409, "too_many_devices", f"remove a device first (limit {MAX_DEVICES})")
            new = OpDevice(id=random_id("dev_"), account_id=account.id, name=body.device.name,
                           public_jwk=json.dumps(body.device.public_jwk), approved_via="mfa" if account.mfa_enabled else "password")
            session.add(new)
            device_id = new.id
            await audit.append(session, f"account:{k.owner_tag(account.id)[:12]}", "device_added", new.id, via=new.approved_via)
        await audit.append(session, f"account:{k.owner_tag(account.id)[:12]}", "signed_in", None)
        limits = await _limits(services, session, account)
    response = JSONResponse(_me(services, account, limits, device_id=device_id))
    await open_session(services, request, response, account)
    return response


@router.post("/recovery")
async def recover(body: Recover, request: Request):
    """Lost device or password: the recovery code proves ownership.

    Sets the new password, switches MFA off (the authenticator may be on the
    lost phone), signs every other browser out and revokes every device, then
    registers this browser. The ledger is unwrapped in the browser with the
    same recovery code.
    """
    services = get_services(request)
    k = keys(services)
    same_origin(request)
    ip = client_ip(request)
    index = k.index("email", body.email.lower())
    _signin_blocked(services, ip, index)
    async with services.db.session() as session:
        account = await session.scalar(select(OpAccount).where(OpAccount.email_index == index))
    if not check_secret(body.recovery_key, account.recovery_hash if account else _DUMMY_HASH) or account is None or account.status != "active":
        _signin_failed(services, ip, index)
        raise OpError(401, "wrong_credentials", "that email and recovery code do not match")
    async with services.db.session() as session, session.begin():
        row = await session.get(OpAccount, account.id)
        row.auth_hash = hash_secret(body.new_auth_key)
        row.mfa_enabled, row.mfa_secret_enc, row.mfa_last_step = False, None, None
        await end_all_sessions(session, row.id)
        for device in (await session.execute(select(OpDevice).where(OpDevice.account_id == row.id))).scalars():
            device.status = "revoked"
        device = OpDevice(id=random_id("dev_"), account_id=row.id, name=body.device.name,
                          public_jwk=json.dumps(body.device.public_jwk), approved_via="recovery")
        session.add(device)
        await audit.append(session, f"account:{k.owner_tag(row.id)[:12]}", "account_recovered", None)
        limits = await _limits(services, session, row)
        session.expunge(row)
    response = JSONResponse(_me(services, row, limits, device_id=device.id))
    await open_session(services, request, response, row)
    return response


@router.get("/recipients")
async def recipients(request: Request, q: str | None = Query(default=None, max_length=40)):
    services = get_services(request)
    keys(services)
    stmt = select(OpRecipient).where(OpRecipient.status == "active").order_by(OpRecipient.display_name).limit(200)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(or_(func.lower(OpRecipient.display_name).like(like), OpRecipient.handle.like(like)))
    async with services.db.session() as session:
        rows = (await session.execute(stmt)).scalars().all()
    return [recipient_public(r) for r in rows if r.processor != "sandbox" or services.settings.opossum_sandbox_enabled]


@router.get("/invoices/{invoice_id}")
async def invoice(invoice_id: str, request: Request):
    services = get_services(request)
    keys(services)
    async with services.db.session() as session:
        inv = await session.get(OpInvoice, invoice_id[:40])
        recipient = await session.get(OpRecipient, inv.recipient_id) if inv else None
    if inv is None or recipient is None:
        raise OpError(404, "unknown_invoice", "no such invoice")
    return {"id": inv.id, "reference": inv.reference, "description": inv.description, "amount": money(inv.amount),
            "currency": inv.currency, "status": inv.status, "recipient": recipient_public(recipient)}


@router.post("/quote")
async def quote_endpoint(body: QuoteIn, request: Request):
    services = get_services(request)
    keys(services)
    async with services.db.session() as session:
        recipient = await find_recipient(session, body.recipient)
        q = await compute_quote(services, session, recipient, body.amount, body.currency.upper(), body.type, body.fee_bearer)
    return {**q.as_dict(), "recipient": recipient_public(recipient)}


@router.post("/verify")
async def verify(body: VerifyIn, request: Request):
    services = get_services(request)
    k = keys(services)
    try:
        result = verify_presentation(body.presentation, k.jwks())
    except ReceiptInvalid as exc:
        return {"valid": False, "reason": str(exc)}
    out: dict[str, Any] = {"valid": True, **result}
    commitment = result["disclosed"].get("memo_commitment")
    if body.memo is not None:
        out["memo_valid"] = bool(commitment) and check_memo(commitment, body.memo, body.memo_salt or "")
    return out


@router.get("/data-map")
async def data_map():
    return DATA_MAP


# ---------------------------------------------------------------- signed in


@router.get("/me")
async def me(ctx=Depends(current_account)):
    services, account = ctx
    async with services.db.session() as session:
        limits = await _limits(services, session, account)
        devices = await session.scalar(select(func.count()).select_from(OpDevice).where(
            OpDevice.account_id == account.id, OpDevice.status == "active"))
    return _me(services, account, limits, active_devices=devices)


@router.delete("/session")
async def sign_out(request: Request):
    services = get_services(request)
    same_origin(request)
    response = JSONResponse({"signed_in": False})
    await close_session(services, request, response)
    return response


@router.post("/mfa/setup")
async def mfa_setup(ctx=Depends(current_account)):
    services, account = ctx
    k = keys(services)
    if account.mfa_enabled:
        raise OpError(409, "mfa_on", "an authenticator is already set up")
    secret = new_totp_secret()
    async with services.db.session() as session, session.begin():
        row = await session.get(OpAccount, account.id)
        row.mfa_secret_enc = k.seal(secret, f"op_accounts:{account.id}:mfa")
    return {"secret": secret, "otpauth_uri": f"otpauth://totp/Opossum?secret={secret}&issuer=Opossum&algorithm=SHA1&digits=6&period=30"}


@router.post("/mfa/confirm")
async def mfa_confirm(body: CodeIn, ctx=Depends(current_account)):
    services, account = ctx
    k = keys(services)
    async with services.db.session() as session, session.begin():
        row = await session.get(OpAccount, account.id)
        if not row.mfa_secret_enc or row.mfa_enabled:
            raise OpError(409, "mfa_state", "start the authenticator setup first")
        step = check_totp(k.open(row.mfa_secret_enc, f"op_accounts:{row.id}:mfa"), body.code, row.mfa_last_step)
        if step is None:
            raise OpError(400, "wrong_code", "that code is not right; check the time on your phone")
        row.mfa_enabled, row.mfa_last_step = True, step
        await audit.append(session, f"account:{k.owner_tag(row.id)[:12]}", "mfa_enabled", None)
    return {"mfa_enabled": True}


@router.post("/mfa/disable")
async def mfa_disable(body: CodeIn, ctx=Depends(current_account)):
    services, account = ctx
    k = keys(services)
    async with services.db.session() as session, session.begin():
        row = await session.get(OpAccount, account.id)
        if not row.mfa_enabled:
            return {"mfa_enabled": False}
        step = check_totp(k.open(row.mfa_secret_enc, f"op_accounts:{row.id}:mfa"), body.code, row.mfa_last_step)
        if step is None:
            raise OpError(400, "wrong_code", "that code is not right")
        row.mfa_enabled, row.mfa_secret_enc, row.mfa_last_step = False, None, step
        await audit.append(session, f"account:{k.owner_tag(row.id)[:12]}", "mfa_disabled", None)
    return {"mfa_enabled": False}


def _device_json(d: OpDevice) -> dict:
    return {"id": d.id, "name": d.name, "status": d.status, "approved_via": d.approved_via,
            "created_at": aware(d.created_at).isoformat(), "last_used_at": aware(d.last_used_at).isoformat() if d.last_used_at else None}


@router.get("/devices")
async def devices(ctx=Depends(current_account)):
    services, account = ctx
    async with services.db.session() as session:
        rows = (await session.execute(select(OpDevice).where(OpDevice.account_id == account.id).order_by(OpDevice.created_at))).scalars().all()
    return [_device_json(d) for d in rows]


class AddDevice(DeviceIn):
    totp: str | None = Field(default=None, max_length=8)


@router.post("/devices", status_code=201)
async def add_device(body: AddDevice, ctx=Depends(current_account)):
    """A new browser. With an authenticator set up, it must confirm a code."""
    services, account = ctx
    k = keys(services)
    async with services.db.session() as session, session.begin():
        row = await session.get(OpAccount, account.id)
        if row.mfa_enabled:
            step = check_totp(k.open(row.mfa_secret_enc, f"op_accounts:{row.id}:mfa"), body.totp or "", row.mfa_last_step)
            if step is None:
                raise OpError(401, "mfa_required", "confirm this new device with a code from your authenticator app")
            row.mfa_last_step = step
        active = await session.scalar(select(func.count()).select_from(OpDevice).where(
            OpDevice.account_id == row.id, OpDevice.status == "active"))
        if active >= MAX_DEVICES:
            raise OpError(409, "too_many_devices", f"remove a device first (limit {MAX_DEVICES})")
        device = OpDevice(id=random_id("dev_"), account_id=row.id, name=body.name, public_jwk=json.dumps(body.public_jwk),
                          approved_via="mfa" if row.mfa_enabled else "password")
        session.add(device)
        await audit.append(session, f"account:{k.owner_tag(row.id)[:12]}", "device_added", device.id, via=device.approved_via)
    return _device_json(device)


@router.delete("/devices/{device_id}")
async def revoke_device(device_id: str, ctx=Depends(current_account)):
    services, account = ctx
    k = keys(services)
    async with services.db.session() as session, session.begin():
        device = await session.get(OpDevice, device_id[:40])
        if device is None or device.account_id != account.id:
            raise OpError(404, "unknown_device", "no such device")
        device.status = "revoked"
        await audit.append(session, f"account:{k.owner_tag(account.id)[:12]}", "device_revoked", device.id)
    return _device_json(device)


@router.get("/identity")
async def get_identity(ctx=Depends(current_account)):
    services, account = ctx
    k = keys(services)
    async with services.db.session() as session:
        row = await session.get(OpIdentity, account.id)
    return {"identity": k.open(row.ciphertext, f"op_identities:{account.id}:doc") if row else {}, "kyc_status": account.kyc_status}


@router.put("/identity")
async def put_identity(body: Identity, ctx=Depends(current_account)):
    services, account = ctx
    k = keys(services)
    async with services.db.session() as session, session.begin():
        row = await session.get(OpIdentity, account.id)
        doc = k.open(row.ciphertext, f"op_identities:{account.id}:doc") if row else {}
        doc.update({key: value for key, value in body.model_dump().items() if value is not None})
        if row is None:
            session.add(OpIdentity(account_id=account.id, ciphertext=k.seal(doc, f"op_identities:{account.id}:doc")))
        else:
            row.ciphertext = k.seal(doc, f"op_identities:{account.id}:doc")
            row.updated_at = utcnow()
        acct = await session.get(OpAccount, account.id)
        hit = await screen_name(session, body.legal_name)
        if hit:
            acct.kyc_status, acct.kyc_note = "review", "screening match"
            await audit.append(session, "compliance", "screening_match", None, list=hit, account_ref=k.owner_tag(acct.id)[:12])
        elif acct.kyc_status in ("none", "self_attested"):
            acct.kyc_status = "self_attested"
        acct.kyc_updated_at = utcnow()
        await audit.append(session, f"account:{k.owner_tag(acct.id)[:12]}", "identity_updated", None)
        status = acct.kyc_status
    return {"identity": doc, "kyc_status": status}


@router.post("/identity/verify")
async def start_identity_check(request: Request, ctx=Depends(current_account)):
    """Start a Stripe Identity document check. Stripe sees the document; the
    relay sends only an opaque reference and records the outcome."""
    from .stripe_ops import identity_session
    from .processors import ProcessorError

    services, account = ctx
    k = keys(services)
    if not (services.settings.opossum_stripe_identity and services.settings.stripe_secret_key):
        raise OpError(503, "identity_checks_off", "automatic identity checks are not switched on here")
    if account.kyc_status == "verified":
        raise OpError(409, "already_verified", "your identity is already verified")
    if account.kyc_status == "none":
        raise OpError(409, "identity_required", "save your legal name and address first")
    reference = random_id("kyc_", 12)
    try:
        session_info = await identity_session(services, reference=reference, return_url=f"{base_url(request)}/opossum#privacy")
    except ProcessorError as exc:
        message = exc.message
        if "identity" in message.lower() and ("activ" in message.lower() or "not enabled" in message.lower()):
            message = "identity checks are not activated for this Stripe account yet"
        raise OpError(502, "identity_provider_error", message) from None
    async with services.db.session() as session, session.begin():
        row = await session.get(OpAccount, account.id)
        row.kyc_ref, row.kyc_provider_ref = reference, session_info["id"]
        await audit.append(session, f"account:{k.owner_tag(row.id)[:12]}", "identity_check_started", None, provider="stripe_identity")
    return {"url": session_info["url"]}


async def identity_result(services: Services, event_type: str, obj: dict) -> dict:
    """Stripe Identity webhook: verified raises limits; anything else leaves a note."""
    reference = str((obj.get("metadata") or {}).get("opossum_ref") or "")[:40]
    if not reference:
        return {"received": True, "ignored": "not an opossum identity check"}
    k = keys(services)
    async with services.db.session() as session, session.begin():
        account = await session.scalar(select(OpAccount).where(OpAccount.kyc_ref == reference))
        if account is None or account.kyc_provider_ref != obj.get("id"):
            return {"received": True, "ignored": "unknown identity check"}
        if event_type == "identity.verification_session.verified" and obj.get("status") == "verified":
            if account.kyc_status != "review":  # a sanctions match still needs a human decision
                account.kyc_status = "verified"
            account.kyc_note = "stripe identity " + str(obj.get("id"))[:60]
            outcome = "verified"
        else:
            error = (obj.get("last_error") or {}).get("code") or obj.get("status") or event_type.rsplit(".", 1)[-1]
            account.kyc_note = f"stripe identity: {error}"[:200]
            outcome = str(error)
        account.kyc_updated_at = utcnow()
        await audit.append(session, "stripe_identity", "identity_check_result", None, outcome=outcome[:60],
                           account_ref=k.owner_tag(account.id)[:12])
    return {"received": True, "identity": outcome}


@router.get("/backup")
async def get_backup(ctx=Depends(current_account)):
    services, account = ctx
    async with services.db.session() as session:
        row = await session.get(OpBackup, account.id)
    if row is None:
        raise OpError(404, "no_backup", "no backup yet")
    return {"version": row.version, "ciphertext": row.ciphertext, "wrapped_keys": json.loads(row.wrapped_keys),
            "updated_at": aware(row.updated_at).isoformat()}


@router.put("/backup")
async def put_backup(body: BackupIn, ctx=Depends(current_account)):
    """Store the encrypted ledger. Optimistic concurrency: send the version you started from."""
    services, account = ctx
    if len(body.ciphertext) > services.settings.opossum_max_backup_bytes:
        raise OpError(413, "backup_too_large", "the encrypted ledger is larger than the backup limit")
    if not body.ciphertext.startswith("v1."):
        raise OpError(400, "not_encrypted", "backups must be encrypted in the browser first")
    async with services.db.session() as session, session.begin():
        row = await session.get(OpBackup, account.id, with_for_update=True)
        if row is None:
            raise OpError(404, "no_backup", "no backup record")
        if row.version != body.expected_version:
            raise OpError(409, "backup_conflict", "another device saved a newer ledger; merge and retry", version=row.version)
        row.ciphertext, row.version, row.updated_at = body.ciphertext, row.version + 1, utcnow()
        version = row.version
    return {"version": version}


@router.put("/backup/keys")
async def put_backup_keys(body: dict, ctx=Depends(current_account)):
    services, account = ctx
    wrapped = body.get("wrapped_keys")
    if not isinstance(wrapped, dict) or len(json.dumps(wrapped)) > 4096:
        raise OpError(400, "invalid_request", "wrapped_keys must be a small object")
    async with services.db.session() as session, session.begin():
        row = await session.get(OpBackup, account.id)
        row.wrapped_keys = json.dumps(wrapped)
    return {"ok": True}


@router.post("/payments")
async def pay(request: Request, ctx=Depends(current_account)):
    """A payment request, signed by one of the account's devices.

    Headers: ``X-Opossum-Device`` (device ID) and ``X-Opossum-Signature``
    (base64url ECDSA P-256 signature over the exact request body).
    """
    services, account = ctx
    k = keys(services)
    body = await request.body()
    if len(body) > MAX_PAYMENT_BODY:
        raise OpError(413, "too_large", "payment request too large")
    device_id = (request.headers.get("x-opossum-device") or "")[:40]
    async with services.db.session() as session, session.begin():
        device = await session.get(OpDevice, device_id)
        if device is None or device.account_id != account.id or device.status != "active":
            raise OpError(403, "unknown_device", "this device is not authorised for payments; add it in security")
        if not verify_device_signature(json.loads(device.public_jwk), body, request.headers.get("x-opossum-signature", "")):
            await audit.append(session, "relay", "bad_device_signature", device.id)
            raise OpError(403, "bad_signature", "the payment request signature is not valid")
        device.last_used_at = utcnow()
    return await create_payment(services, k, account, device_id, body, base_url(request))


@router.get("/payments")
async def my_payments(ctx=Depends(current_account), limit: int = Query(default=100, ge=1, le=500)):
    services, account = ctx
    k = keys(services)
    tag = k.owner_tag(account.id)
    async with services.db.session() as session:
        rows = (await session.execute(select(OpTransaction, OpRecipient).join(OpRecipient, OpRecipient.id == OpTransaction.recipient_id)
                                      .where(OpTransaction.owner_tag == tag).order_by(OpTransaction.created_at.desc()).limit(limit))).all()
    return [owner_view(k, tx, r) for tx, r in rows]


@router.get("/payments/{tx_id}")
async def my_payment(tx_id: str, ctx=Depends(current_account)):
    services, account = ctx
    k = keys(services)
    async with services.db.session() as session:
        tx = await session.get(OpTransaction, tx_id[:40])
        if tx is None or tx.owner_tag != k.owner_tag(account.id):
            raise OpError(404, "unknown_payment", "no such payment")
        recipient = await session.get(OpRecipient, tx.recipient_id)
    return owner_view(k, tx, recipient)


@router.get("/disclosures")
async def disclosures_about_me(ctx=Depends(current_account)):
    """Legal disclosures about this account, unless an order delays or forbids telling the user."""
    services, account = ctx
    k = keys(services)
    now = utcnow()
    async with services.db.session() as session:
        rows = (await session.execute(
            select(OpDisclosure, OpCase).join(OpCase, OpCase.id == OpDisclosure.case_id).where(
                OpDisclosure.owner_tag == k.owner_tag(account.id),
                or_(OpCase.notify == "now", and_(OpCase.notify == "delayed", OpCase.notify_after <= now)),
            ).order_by(OpDisclosure.disclosed_at.desc())
        )).all()
    return [{"disclosed_at": aware(d.disclosed_at).isoformat(), "transaction": d.tx_id, "fields": json.loads(d.fields),
             "legal_basis": c.legal_basis, "authority": c.authority, "reference": c.reference} for d, c in rows]


@router.post("/account/close")
async def close_account(body: CloseIn, request: Request, ctx=Depends(current_account)):
    """Close the account. Identity is kept only while a legal retention period still runs."""
    services, account = ctx
    k = keys(services)
    if not check_secret(body.auth_key, account.auth_hash):
        raise OpError(401, "wrong_credentials", "password is not right")
    tag = k.owner_tag(account.id)
    async with services.db.session() as session, session.begin():
        row = await session.get(OpAccount, account.id)
        keep_until = await session.scalar(select(func.max(OpTransaction.retain_until)).where(OpTransaction.owner_tag == tag))
        row.status, row.closed_at = "closed", utcnow()
        row.identity_retain_until = keep_until
        if keep_until is None:
            identity = await session.get(OpIdentity, row.id)
            if identity is not None:
                await session.delete(identity)
        backup = await session.get(OpBackup, row.id)
        if backup is not None:
            backup.ciphertext = None
        for device in (await session.execute(select(OpDevice).where(OpDevice.account_id == row.id))).scalars():
            device.status = "revoked"
        await end_all_sessions(session, row.id)
        await audit.append(session, f"account:{tag[:12]}", "account_closed", None,
                           identity_kept_until=keep_until.isoformat() if keep_until else "deleted now")
    response = JSONResponse({"closed": True, "identity_kept_until": keep_until.isoformat() if keep_until else None})
    await close_session(services, request, response)
    return response

