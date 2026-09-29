"""Blockchain address primitives, from the published standards.

* Base58Check (Bitcoin) and BIP32 public-key derivation from an extended
  public key (xpub / ypub / zpub), so a merchant's wallet gets a fresh
  receiving address per payment without Opossum ever holding a private key.
* Addresses: P2WPKH (BIP84, bech32 per BIP173), P2SH-P2WPKH (BIP49), P2PKH.
* Ethereum-family: Keccak-256, EIP-55 checksummed addresses.
* Payment URIs: BIP21 (bitcoin:) and EIP-681 (ethereum: token transfer).

Elliptic-curve arithmetic is done by libsecp256k1 (via coincurve); hashes by
pycryptodome and hashlib. Every function here is checked against the
standards' own test vectors in tests/test_opossum_chain.py.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from decimal import Decimal

from coincurve import PublicKey
# pycryptodome (maintained; shares the "Crypto" namespace with the retired pyCrypto).
# Used only for address encoding: hash160 and Ethereum Keccak, which hashlib lacks.
from Crypto.Hash import RIPEMD160, keccak  # nosec B413

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Extended public key version bytes (mainnet) and the address type each implies.
XPUB_VERSIONS = {
    bytes.fromhex("0488b21e"): "xpub",  # BIP32/BIP44; many wallets also use it for BIP84 accounts
    bytes.fromhex("049d7cb2"): "ypub",  # BIP49 nested segwit
    bytes.fromhex("04b24746"): "zpub",  # BIP84 native segwit
}


class ChainError(ValueError):
    pass


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash160(data: bytes) -> bytes:
    return RIPEMD160.new(sha256(data)).digest()


def keccak256(data: bytes) -> bytes:
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()


# ---------------------------------------------------------------- base58check


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def b58decode(text: str) -> bytes:
    n = 0
    for ch in text:
        i = B58.find(ch)
        if i < 0:
            raise ChainError("not base58")
        n = n * 58 + i
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(text) - len(text.lstrip("1"))) + raw


def b58check_encode(payload: bytes) -> str:
    return b58encode(payload + sha256(sha256(payload))[:4])


def b58check_decode(text: str) -> bytes:
    raw = b58decode(text)
    if len(raw) < 5 or sha256(sha256(raw[:-4]))[:4] != raw[-4:]:
        raise ChainError("checksum does not match")
    return raw[:-4]


# ---------------------------------------------------------------- bech32 (BIP173)

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values) -> int:
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convertbits(data, frombits: int, tobits: int, pad: bool = True) -> list[int]:
    acc, bits, ret, maxv = 0, 0, [], (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    elif not pad and (bits >= frombits or ((acc << (tobits - bits)) & maxv)):
        raise ChainError("invalid padding")
    return ret


def segwit_address(hrp: str, witver: int, program: bytes) -> str:
    """bech32 for witness v0 (BIP173). Taproot's bech32m is not needed here."""
    data = [witver] + _convertbits(program, 8, 5)
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[d] for d in data + checksum)


def decode_segwit(hrp: str, addr: str) -> tuple[int, bytes]:
    addr_l = addr.lower()
    if addr != addr_l and addr != addr.upper():
        raise ChainError("mixed case")
    pos = addr_l.rfind("1")
    if pos < 1 or addr_l[:pos] != hrp or len(addr_l) > 90:
        raise ChainError("wrong network")
    try:
        data = [_CHARSET.index(c) for c in addr_l[pos + 1:]]
    except ValueError:
        raise ChainError("not bech32") from None
    const = _polymod(_hrp_expand(hrp) + data)
    if data[0] == 0 and const != 1:
        raise ChainError("bad checksum")
    if data[0] != 0 and const != 0x2BC830A3:  # bech32m for v1+
        raise ChainError("bad checksum")
    program = bytes(_convertbits(data[1:-6], 5, 8, False))
    return data[0], program


# ---------------------------------------------------------------- BIP32 public derivation


@dataclass(frozen=True)
class ExtendedKey:
    kind: str  # xpub | ypub | zpub
    depth: int
    chain_code: bytes
    key: bytes  # 33-byte compressed public key

    def child(self, index: int) -> "ExtendedKey":
        if index >= 0x80000000:
            raise ChainError("hardened children cannot be derived from a public key")
        digest = hmac.new(self.chain_code, self.key + index.to_bytes(4, "big"), hashlib.sha512).digest()
        tweak = int.from_bytes(digest[:32], "big")
        if tweak >= SECP256K1_N:
            raise ChainError("invalid child; use the next index")
        child = PublicKey(self.key).add(digest[:32])
        return ExtendedKey(self.kind, self.depth + 1, digest[32:], child.format(compressed=True))


def parse_xpub(text: str) -> ExtendedKey:
    try:
        raw = b58check_decode(text.strip())
    except ChainError:
        raise ChainError("that is not a valid extended public key (xpub, ypub or zpub)") from None
    if len(raw) != 78 or raw[:4] not in XPUB_VERSIONS:
        raise ChainError("only mainnet xpub, ypub or zpub keys are supported (never paste a private key)")
    key = raw[45:78]
    if key[0] not in (2, 3):
        raise ChainError("not a public key")
    PublicKey(key)  # raises if not on the curve
    return ExtendedKey(XPUB_VERSIONS[raw[:4]], raw[4], raw[13:45], key)


def btc_address(pubkey: bytes, kind: str) -> str:
    h = hash160(pubkey)
    if kind == "p2wpkh":
        return segwit_address("bc", 0, h)
    if kind == "p2sh-p2wpkh":
        redeem = b"\x00\x14" + h
        return b58check_encode(b"\x05" + hash160(redeem))
    if kind == "p2pkh":
        return b58check_encode(b"\x00" + h)
    raise ChainError("unknown address type")


def default_address_type(xpub: ExtendedKey) -> str:
    return {"zpub": "p2wpkh", "ypub": "p2sh-p2wpkh", "xpub": "p2wpkh"}[xpub.kind]


def derive_receive_address(xpub_text: str, index: int, kind: str) -> str:
    """Address m/<account>/0/index from an account-level extended public key."""
    return btc_address(parse_xpub(xpub_text).child(0).child(index).key, kind)


def is_btc_address(addr: str) -> bool:
    try:
        if addr.lower().startswith("bc1"):
            ver, prog = decode_segwit("bc", addr)
            return (ver == 0 and len(prog) in (20, 32)) or (ver == 1 and len(prog) == 32)
        raw = b58check_decode(addr)
        return len(raw) == 21 and raw[0] in (0x00, 0x05)
    except ChainError:
        return False


# ---------------------------------------------------------------- Ethereum family

EVM_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")


def checksum_address(addr: str) -> str:
    if not EVM_ADDRESS.match(addr):
        raise ChainError("not an 0x address")
    lower = addr[2:].lower()
    digest = keccak256(lower.encode()).hex()
    return "0x" + "".join(c.upper() if int(digest[i], 16) >= 8 else c for i, c in enumerate(lower))


def valid_evm_address(addr: str) -> bool:
    """Accept all-lower or all-upper hex, or a correct EIP-55 checksum."""
    if not EVM_ADDRESS.match(addr):
        return False
    body = addr[2:]
    if body == body.lower() or body == body.upper():
        return True
    return checksum_address(addr) == addr


# ---------------------------------------------------------------- payment URIs


def to_atomic(amount: Decimal, decimals: int) -> int:
    return int((amount * (Decimal(10) ** decimals)).to_integral_value())


def from_atomic(value: int, decimals: int) -> Decimal:
    return (Decimal(value) / (Decimal(10) ** decimals)).quantize(Decimal(1).scaleb(-decimals))


def bip21_uri(address: str, amount_btc: Decimal, label: str | None = None) -> str:
    uri = f"bitcoin:{address}?amount={format(amount_btc.normalize(), 'f')}"
    if label:
        from urllib.parse import quote

        uri += "&label=" + quote(label[:40])
    return uri


def eip681_token_uri(token: str, chain_id: int, to: str, atomic: int) -> str:
    return f"ethereum:{token}@{chain_id}/transfer?address={to}&uint256={atomic}"
