"""Cryptography for the relay. Established primitives only, via pyca/cryptography.

* Receipts: SD-JWT style selective disclosure (IETF OAuth WG "Selective
  Disclosure for JWTs"): each claim is a salted SHA-256 digest inside an
  Ed25519-signed JWT; the holder reveals any subset of claims by handing over
  their disclosures.
* Identity vault and other protected fields: AES-256-GCM with the row and
  field bound in as associated data.
* Pseudonyms and lookup indexes: HMAC-SHA256.
* All server keys come from one master secret (OPOSSUM_MASTER_KEY) through
  HKDF-SHA256 with a distinct label per purpose.
* Device requests: ECDSA P-256 / SHA-256 signatures made by a non-extractable
  WebCrypto key.
* MFA: TOTP (RFC 6238, HMAC-SHA1, 30 s, 6 digits).

None of this is novel cryptography; it must still be independently audited
before handling real money (see docs/opossum.md).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import struct
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    if not isinstance(text, str) or len(text) > 1_000_000:
        raise ValueError("bad base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def canonical(obj) -> bytes:
    """Deterministic JSON: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def random_id(prefix: str, nbytes: int = 12) -> str:
    return prefix + b64u(secrets.token_bytes(nbytes))


class KeysMissing(RuntimeError):
    pass


@dataclass(frozen=True)
class RelayKeys:
    signing: Ed25519PrivateKey
    kid: str
    vault: AESGCM
    pseudonym_key: bytes
    index_key: bytes

    @classmethod
    def from_master(cls, master: str) -> "RelayKeys":
        try:
            raw = b64u_decode(master.strip())
        except ValueError:
            raw = b""
        if len(raw) < 32:
            raise KeysMissing("OPOSSUM_MASTER_KEY must be at least 32 random bytes, base64url (python -m aiproxy gen-opossum-key)")

        def derive(label: str) -> bytes:
            return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"opossum-v1", info=label.encode()).derive(raw)

        signing = Ed25519PrivateKey.from_private_bytes(derive("receipt-signing"))
        public = signing.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return cls(
            signing=signing,
            kid=b64u(hashlib.sha256(public).digest()[:12]),
            vault=AESGCM(derive("vault")),
            pseudonym_key=derive("pseudonyms"),
            index_key=derive("lookup-index"),
        )

    # ------------------------------------------------------------ vault

    def seal(self, value, context: str) -> str:
        """Encrypt a JSON-serialisable value, bound to ``context`` (table:row:field)."""
        nonce = secrets.token_bytes(12)
        return "v1." + b64u(nonce + self.vault.encrypt(nonce, canonical(value), context.encode()))

    def open(self, sealed: str, context: str):
        if not sealed.startswith("v1."):
            raise ValueError("unknown vault format")
        blob = b64u_decode(sealed[3:])
        try:
            plain = self.vault.decrypt(blob[:12], blob[12:], context.encode())
        except InvalidTag:
            raise ValueError("vault entry does not match its context or was altered") from None
        return json.loads(plain)

    # ------------------------------------------------------------ pseudonyms and indexes

    def index(self, label: str, value: str) -> str:
        return hmac.new(self.index_key, f"{label}|{value}".encode(), hashlib.sha256).hexdigest()

    def owner_tag(self, account_id) -> str:
        return hmac.new(self.pseudonym_key, f"owner|{account_id}".encode(), hashlib.sha256).hexdigest()

    def pairwise_pseudonym(self, account_id, recipient_id) -> str:
        """Stable per (payer, recipient): a shop can recognise a returning
        customer but two shops cannot match their customers."""
        digest = hmac.new(self.pseudonym_key, f"pairwise|{account_id}|{recipient_id}".encode(), hashlib.sha256).digest()
        return "opp_" + b64u(digest[:12])

    @staticmethod
    def one_time_pseudonym() -> str:
        return random_id("opx_")

    # ------------------------------------------------------------ receipts (SD-JWT)

    def jwks(self) -> dict:
        public = self.signing.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": b64u(public), "kid": self.kid, "alg": "EdDSA", "use": "sig"}]}

    def issue_receipt(self, disclosable: dict, always_visible: dict) -> tuple[str, list[str]]:
        """Sign a receipt. Returns the JWT and one disclosure per disclosable claim."""
        disclosures, digests = [], []
        for name, value in disclosable.items():
            disclosure = b64u(canonical([b64u(secrets.token_bytes(16)), name, value]))
            disclosures.append(disclosure)
            digests.append(b64u(hashlib.sha256(disclosure.encode("ascii")).digest()))
        # Decoys hide how many claims a receipt really carries.
        digests += [b64u(hashlib.sha256(secrets.token_bytes(32)).digest()) for _ in range(3)]
        header = {"alg": "EdDSA", "typ": "opossum-receipt+sd-jwt", "kid": self.kid}
        payload = {**always_visible, "_sd": sorted(digests), "_sd_alg": "sha-256"}
        signing_input = b64u(canonical(header)) + "." + b64u(canonical(payload))
        signature = self.signing.sign(signing_input.encode("ascii"))
        return signing_input + "." + b64u(signature), disclosures


class ReceiptInvalid(ValueError):
    pass


def verify_presentation(presentation: str, jwks: dict) -> dict:
    """Check a receipt presentation ``<jwt>~<disclosure>~...~``.

    Returns ``{"issuer_claims": {...}, "disclosed": {...}, "hidden": n}``.
    Raises ReceiptInvalid with a plain reason otherwise.
    """
    if not isinstance(presentation, str) or len(presentation) > 200_000:
        raise ReceiptInvalid("not a receipt")
    parts = presentation.strip().split("~")
    jwt, disclosures = parts[0], [d for d in parts[1:] if d]
    try:
        header_b64, payload_b64, sig_b64 = jwt.split(".")
        header = json.loads(b64u_decode(header_b64))
        payload = json.loads(b64u_decode(payload_b64))
        signature = b64u_decode(sig_b64)
    except (ValueError, UnicodeDecodeError):
        raise ReceiptInvalid("receipt is malformed") from None
    if header.get("alg") != "EdDSA" or header.get("typ") != "opossum-receipt+sd-jwt":
        raise ReceiptInvalid("not an Opossum receipt")
    key = next((k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid")), None)
    if key is None:
        raise ReceiptInvalid("signed with a key this relay does not publish")
    try:
        Ed25519PublicKey.from_public_bytes(b64u_decode(key["x"])).verify(signature, f"{header_b64}.{payload_b64}".encode("ascii"))
    except (InvalidSignature, ValueError):
        raise ReceiptInvalid("signature does not match: the receipt was altered or not issued by this relay") from None
    if payload.get("_sd_alg") != "sha-256" or not isinstance(payload.get("_sd"), list):
        raise ReceiptInvalid("receipt has no disclosure digests")
    digests = set(payload["_sd"])
    disclosed: dict = {}
    for disclosure in disclosures:
        digest = b64u(hashlib.sha256(disclosure.encode("ascii")).digest())
        if digest not in digests:
            raise ReceiptInvalid("a disclosed field was not part of the signed receipt")
        try:
            salt, name, value = json.loads(b64u_decode(disclosure))
        except (ValueError, TypeError):
            raise ReceiptInvalid("a disclosure is malformed") from None
        if not isinstance(salt, str) or not isinstance(name, str) or name in disclosed or name.startswith("_"):
            raise ReceiptInvalid("a disclosure is malformed or repeated")
        disclosed[name] = value
    visible = {k: v for k, v in payload.items() if not k.startswith("_")}
    return {"issuer_claims": visible, "disclosed": disclosed, "hidden": max(0, len(digests) - 3 - len(disclosed)), "kid": header["kid"]}


def check_memo(commitment: str, memo: str, salt: str) -> bool:
    """A memo commitment is sha256(salt || ":" || memo), made in the browser.

    The relay only ever sees the hash; the user can later reveal the memo and
    salt to prove what they wrote at payment time.
    """
    expected = hashlib.sha256(f"{salt}:{memo}".encode("utf-8")).hexdigest()
    return hmac.compare_digest(expected, commitment or "")


# ---------------------------------------------------------------- device signatures


def load_device_key(jwk: dict) -> ec.EllipticCurvePublicKey:
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("device key must be an EC P-256 JWK")
    x, y = b64u_decode(jwk.get("x", "")), b64u_decode(jwk.get("y", ""))
    if len(x) != 32 or len(y) != 32:
        raise ValueError("device key coordinates are the wrong length")
    numbers = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1())
    return numbers.public_key()  # raises ValueError if the point is not on the curve


def verify_device_signature(jwk: dict, body: bytes, signature_b64u: str) -> bool:
    """WebCrypto ECDSA signatures are raw r||s (64 bytes); convert to DER."""
    try:
        raw = b64u_decode(signature_b64u)
        if len(raw) != 64:
            return False
        der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
        load_device_key(jwk).verify(der, body, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------- password verifiers


def hash_secret(secret: str) -> str:
    """scrypt over the client-derived auth key (or recovery key)."""
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(secret.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt$16384$8$1${b64u(salt)}${b64u(digest)}"


def check_secret(secret: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, digest = stored.split("$")
        actual = hashlib.scrypt(secret.encode("utf-8"), salt=b64u_decode(salt), n=int(n), r=int(r), p=int(p), dklen=32)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, b64u_decode(digest))


# ---------------------------------------------------------------- TOTP


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def totp_code(secret: str, step: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    # RFC 6238 authenticator apps use HMAC-SHA1; its use here is not collision-sensitive.
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def check_totp(secret: str, code: str, last_step: int | None, now: float | None = None) -> int | None:
    """Return the matched time step, or None. A step can be used only once."""
    if not isinstance(code, str) or not code.isdigit() or len(code) != 6:
        return None
    current = int((now or time.time()) // 30)
    for step in (current - 1, current, current + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(totp_code(secret, step), code):
            return step
    return None
