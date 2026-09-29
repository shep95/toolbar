"""Transaction domains: the kinds of digital business the platform serves.

Each domain (AI APIs, brokerage, crypto, payments...) has its own transaction
types and its own structured ``attributes``, validated on the way in so every
record in a domain has the same shape. A business can be given a key locked to
its domain (a MoonPay-style on-ramp gets a ``crypto`` key, a Robinhood-style
broker a ``brokerage`` key), and admins can price each domain, or each type
within it, separately. Every domain starts at the platform's base fee ($0.03),
adjusted for the account's country.

``general`` accepts any type and no attributes, for anything that does not
fit a specific domain.

Adding a domain is a new entry in ``DOMAINS``; nothing else changes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any

from .countries import normalise_country

# ------------------------------------------------------------------ field kinds


class DomainError(ValueError):
    """An attribute failed validation. Maps to HTTP 400."""


def _text(max_len: int, pattern: str | None = None, upper: bool = False, lower: bool = False):
    compiled = re.compile(pattern) if pattern else None

    def check(name: str, value: Any) -> str:
        if not isinstance(value, str) or not value.strip() or len(value) > max_len:
            raise DomainError(f"'{name}' must be text of 1-{max_len} characters")
        value = value.strip()
        if upper:
            value = value.upper()
        if lower:
            value = value.lower()
        if compiled and not compiled.match(value):
            raise DomainError(f"'{name}' has an invalid format")
        return value

    return check


def _enum(*choices: str):
    allowed = frozenset(choices)

    def check(name: str, value: Any) -> str:
        if not isinstance(value, str) or value.lower() not in allowed:
            raise DomainError(f"'{name}' must be one of: {', '.join(sorted(allowed))}")
        return value.lower()

    return check


def _decimal(positive: bool):
    def check(name: str, value: Any) -> str:
        if isinstance(value, bool) or not isinstance(value, (int, float, str)):
            raise DomainError(f"'{name}' must be a number")
        try:
            number = Decimal(str(value))
        except InvalidOperation:
            raise DomainError(f"'{name}' must be a number") from None
        if not number.is_finite() or number < 0 or (positive and number == 0) or number > Decimal("1e18"):
            raise DomainError(f"'{name}' must be a {'positive' if positive else 'non-negative'} number")
        return format(number.normalize(), "f")

    return check


def _integer(minimum: int):
    def check(name: str, value: Any) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > 10**12:
            raise DomainError(f"'{name}' must be a whole number of at least {minimum}")
        return value

    return check


def _country(name: str, value: Any) -> str:
    try:
        code = normalise_country(value)
    except ValueError as exc:
        raise DomainError(f"'{name}': {exc}") from None
    if code is None:
        raise DomainError(f"'{name}' must be an ISO country code")
    return code


SYMBOL = _text(20, r"^[A-Z0-9][A-Z0-9.\-/]{0,19}$", upper=True)  # AAPL, BRK.B, BTC, USDC
CURRENCY = _text(3, r"^[A-Z]{3}$", upper=True)
LABEL = _text(64, r"^[A-Za-z0-9 ._:/@+\-]+$")
NAME = _text(100)
NETWORK = _text(32, r"^[a-z0-9._\-]+$", lower=True)  # ethereum, solana, bitcoin, base
HASH = _text(128, r"^(0x)?[A-Za-z0-9]{8,128}$")
ADDRESS = _text(128, r"^[A-Za-z0-9:._\-]{8,128}$")
POSITIVE = _decimal(positive=True)
NON_NEGATIVE = _decimal(positive=False)


# ------------------------------------------------------------------ domains


@dataclass(frozen=True)
class Domain:
    name: str
    title: str
    description: str
    examples: str
    # None means any type is accepted (the general domain).
    types: frozenset[str] | None
    fields: dict[str, Any] = field(default_factory=dict)
    # type -> attributes that must be present for that type
    required: dict[str, frozenset[str]] = field(default_factory=dict)

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "examples": self.examples,
            "types": sorted(self.types) if self.types is not None else "any",
            "attributes": sorted(self.fields),
            "required": {t: sorted(r) for t, r in sorted(self.required.items())},
        }

    def validate(self, tx_type: str, attributes: Any) -> dict[str, Any]:
        if self.types is not None and tx_type not in self.types:
            raise DomainError(
                f"'{tx_type}' is not a {self.name} transaction type; use one of: {', '.join(sorted(self.types))}"
            )
        if attributes is None:
            attributes = {}
        if not isinstance(attributes, dict):
            raise DomainError("'attributes' must be an object")
        unknown = set(attributes) - set(self.fields)
        if unknown:
            allowed = ", ".join(sorted(self.fields)) or "none"
            raise DomainError(f"unknown {self.name} attributes: {', '.join(sorted(unknown))} (allowed: {allowed})")
        cleaned = {key: self.fields[key](key, value) for key, value in attributes.items() if value is not None}
        missing = self.required.get(tx_type, frozenset()) - set(cleaned)
        if missing:
            raise DomainError(f"a {self.name} '{tx_type}' needs: {', '.join(sorted(missing))}")
        return cleaned


_TRADES = frozenset({"buy", "sell", "short", "cover", "option_buy", "option_sell"})
_CRYPTO_ASSET = frozenset({"buy", "sell", "onramp", "offramp", "send", "receive", "stake", "unstake"})

DOMAINS: dict[str, Domain] = {
    d.name: d
    for d in (
        Domain(
            "general", "General", "Any transaction that does not fit a specific domain.",
            "bookings, tickets, donations, anything else", types=None,
        ),
        Domain(
            "ai", "AI APIs", "Usage of AI models run by your own service (the built-in AI gateway records its own).",
            "chat completions, embeddings, image or audio generation",
            types=frozenset({"request", "completion", "embedding", "image", "audio", "fine_tune"}),
            fields={
                "provider": LABEL, "model": _text(200, r"^[A-Za-z0-9._:/@+\-]+$"),
                "input_tokens": _integer(0), "output_tokens": _integer(0),
            },
        ),
        Domain(
            "brokerage", "Brokerage and trading", "Stock, ETF, option and other securities activity.",
            "Robinhood-style buys and sells, dividends, account deposits",
            types=_TRADES | {"dividend", "deposit", "withdrawal", "transfer", "fee"},
            fields={
                "symbol": SYMBOL,
                "asset_class": _enum("stock", "etf", "option", "bond", "fund", "crypto", "forex", "futures"),
                "quantity": POSITIVE, "price": NON_NEGATIVE, "exchange": LABEL,
                "order_type": _enum("market", "limit", "stop", "stop_limit", "trailing_stop"),
            },
            required={t: frozenset({"symbol", "quantity"}) for t in _TRADES},
        ),
        Domain(
            "crypto", "Crypto", "Buying, selling, swapping and moving digital assets.",
            "MoonPay-style on-ramps and off-ramps, exchange trades, wallet transfers, staking",
            types=_CRYPTO_ASSET | {"swap"},
            fields={
                "asset": SYMBOL, "to_asset": SYMBOL, "quantity": POSITIVE, "price": NON_NEGATIVE,
                "network": NETWORK, "tx_hash": HASH, "wallet_address": ADDRESS,
            },
            required={**{t: frozenset({"asset"}) for t in _CRYPTO_ASSET}, "swap": frozenset({"asset", "to_asset"})},
        ),
        Domain(
            "payments", "Payments", "Card, bank and wallet payments between people and businesses.",
            "checkout charges, refunds, payouts, peer-to-peer payments, invoices",
            types=frozenset({"charge", "refund", "payout", "p2p", "invoice", "subscription", "chargeback"}),
            fields={
                "method": _enum("card", "bank_transfer", "wallet", "cash", "crypto", "other"),
                "card_brand": LABEL, "counterparty": NAME,
            },
        ),
        Domain(
            "remittance", "Remittance and FX", "Sending money across borders and exchanging currencies.",
            "money transfers home, currency exchange",
            types=frozenset({"send", "receive", "fx"}),
            fields={
                "destination_country": _country, "destination_currency": CURRENCY,
                "fx_rate": POSITIVE, "channel": _enum("bank", "cash_pickup", "mobile_money", "wallet", "card"),
            },
            required={"send": frozenset({"destination_country"}), "fx": frozenset({"destination_currency"})},
        ),
        Domain(
            "commerce", "Commerce and marketplaces", "Orders on online stores and marketplaces.",
            "orders, refunds, fulfilments, cancellations",
            types=frozenset({"order", "refund", "fulfillment", "cancellation"}),
            fields={"items": _integer(1), "merchant": NAME, "sku": LABEL},
        ),
        Domain(
            "digital_goods", "Digital goods and gaming", "In-app purchases, game items, gift cards and downloads.",
            "in-app purchases, game currency, gift cards, subscriptions",
            types=frozenset({"purchase", "redemption", "gift", "subscription", "in_app"}),
            fields={"sku": LABEL, "platform": _enum("ios", "android", "web", "console", "pc", "other"), "title": NAME},
        ),
    )
}

DEFAULT_DOMAIN = "general"


def pricing_key(domain: str) -> str:
    """The pricing-rule provider name for a domain.

    ``general`` keeps the key "transactions" used by earlier pricing rules.
    """
    return "transactions" if domain == DEFAULT_DOMAIN else f"domain:{domain}"
