"""Chain primitives against the standards' own published test vectors."""

from __future__ import annotations

from decimal import Decimal

import pytest

from aiproxy.opossum import chainutil as cu

G = bytes.fromhex("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")


def test_bip32_public_derivation_vector_1():
    # BIP32 test vector 1: m/0H -> m/0H/1 is a non-hardened step, derivable from the xpub alone.
    parent = cu.parse_xpub("xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw")
    child = parent.child(1)
    expected = cu.parse_xpub("xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ")
    assert child.key == expected.key and child.chain_code == expected.chain_code
    with pytest.raises(cu.ChainError):
        parent.child(0x80000000)


def test_bip84_vector_first_receive_addresses():
    # BIP84 test vector (mnemonic "abandon ... about"), account 0.
    zpub = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"
    assert cu.derive_receive_address(zpub, 0, "p2wpkh") == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
    assert cu.derive_receive_address(zpub, 1, "p2wpkh") == "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"
    assert cu.default_address_type(cu.parse_xpub(zpub)) == "p2wpkh"


def test_address_encodings():
    assert cu.btc_address(G, "p2wpkh") == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"  # BIP173 example
    assert cu.btc_address(G, "p2pkh") == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
    assert cu.is_btc_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    assert cu.is_btc_address("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4")
    assert not cu.is_btc_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5")
    assert cu.is_btc_address("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
    assert not cu.is_btc_address("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMJ")


def test_private_and_testnet_keys_are_refused():
    xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    with pytest.raises(cu.ChainError, match="private key|mainnet"):
        cu.parse_xpub(xprv)
    with pytest.raises(cu.ChainError):
        cu.parse_xpub("not-a-key")


@pytest.mark.parametrize("addr", [
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
])
def test_eip55_vectors(addr):
    assert cu.checksum_address(addr.lower()) == addr
    assert cu.valid_evm_address(addr) and cu.valid_evm_address(addr.lower())
    broken = addr[:-1] + (addr[-1].lower() if addr[-1].isupper() else addr[-1].upper()) if addr[-1].isalpha() else None
    if broken:
        assert not cu.valid_evm_address(broken)


def test_keccak_and_uris():
    assert cu.keccak256(b"Transfer(address,address,uint256)").hex() == "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    assert cu.to_atomic(Decimal("25.000123"), 6) == 25000123
    assert cu.from_atomic(25000123, 6) == Decimal("25.000123")
    assert cu.bip21_uri("bc1qtest", Decimal("0.00123000")) == "bitcoin:bc1qtest?amount=0.00123"
    assert cu.eip681_token_uri("0xA0b8", 1, "0xabc", 5) == "ethereum:0xA0b8@1/transfer?address=0xabc&uint256=5"
