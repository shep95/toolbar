"""Fee engine. Every figure the payer sees is computed here, before confirmation.

Default: 3% of the transaction value, plus the payment processor's fee.

Rules can set a percentage, a flat part, a minimum and a maximum, and can
apply to one recipient, one transaction type, both, or everything, with an
optional start and end time for promotions. The most specific matching rule
wins; among equally specific rules a time-limited one wins over a permanent
one, then the higher priority.

Who bears the fees:
* ``recipient`` (default): the payer's card is charged the amount; fees come
  out of it and the recipient receives the rest.
* ``payer``: fees are added on top, so the recipient receives the full amount.

The processor fee quoted is fixed at quote time. If the processor's real fee
differs, the platform absorbs the difference, so the quote is what happens.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import ROUND_CEILING, ROUND_HALF_UP, Decimal

CENT = Decimal("0.01")
HUNDRED = Decimal("100")


class FeeError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    percent: Decimal
    flat: Decimal = Decimal("0")
    minimum: Decimal | None = None
    maximum: Decimal | None = None
    recipient_id: str | None = None
    tx_type: str | None = None
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    priority: int = 0

    def applies(self, recipient_id: str, tx_type: str, now: datetime) -> bool:
        if self.recipient_id and self.recipient_id != recipient_id:
            return False
        if self.tx_type and self.tx_type != tx_type:
            return False
        if self.starts_at and now < self.starts_at:
            return False
        if self.ends_at and now >= self.ends_at:
            return False
        return True

    def rank(self) -> tuple:
        specificity = (2 if self.recipient_id else 0) + (1 if self.tx_type else 0)
        promotional = 1 if (self.starts_at or self.ends_at) else 0
        return (specificity, promotional, self.priority)

    def describe(self) -> str:
        parts = [f"{_plain(self.percent)}%"]
        if self.flat:
            parts.append(f"+ {_plain(self.flat)}")
        if self.minimum is not None:
            parts.append(f"min {_plain(self.minimum)}")
        if self.maximum is not None:
            parts.append(f"max {_plain(self.maximum)}")
        return f"{self.name} ({' '.join(parts)})"


def _plain(value: Decimal) -> str:
    text = format(value.normalize(), "f")
    return text


def cents(value: Decimal, rounding=ROUND_HALF_UP) -> Decimal:
    return value.quantize(CENT, rounding=rounding)


def choose_rule(rules: list[Rule], default: Rule, recipient_id: str, tx_type: str, now: datetime) -> Rule:
    matching = [r for r in rules if r.applies(recipient_id, tx_type, now)]
    return max(matching, key=Rule.rank) if matching else default


@dataclass(frozen=True)
class Quote:
    amount: Decimal
    currency: str
    fee_bearer: str
    opossum_fee: Decimal
    processor_fee: Decimal
    total_cost: Decimal
    recipient_receives: Decimal
    rule: Rule

    def as_dict(self) -> dict:
        return {
            "currency": self.currency,
            "amount_sent": str(self.amount),
            "opossum_fee": str(self.opossum_fee),
            "processor_fee": str(self.processor_fee),
            "total_cost": str(self.total_cost),
            "recipient_receives": str(self.recipient_receives),
            "fee_bearer": self.fee_bearer,
            "fee_rule": self.rule.describe(),
            "effective_rate_percent": str(cents((self.opossum_fee + self.processor_fee) / self.amount * HUNDRED)),
        }


def opossum_fee(amount: Decimal, rule: Rule) -> Decimal:
    fee = amount * rule.percent / HUNDRED + rule.flat
    if rule.minimum is not None:
        fee = max(fee, rule.minimum)
    if rule.maximum is not None:
        fee = min(fee, rule.maximum)
    return cents(max(fee, Decimal("0")))


def quote(
    amount: Decimal,
    currency: str,
    rule: Rule,
    *,
    processor_percent: Decimal,
    processor_flat: Decimal,
    fee_bearer: str = "recipient",
) -> Quote:
    if not isinstance(amount, Decimal) or not amount.is_finite() or amount <= 0:
        raise FeeError("amount must be a positive number")
    if amount != cents(amount):
        raise FeeError("amount can have at most 2 decimals")
    if fee_bearer not in ("recipient", "payer"):
        raise FeeError("fee_bearer must be 'recipient' or 'payer'")
    ours = opossum_fee(amount, rule)
    rate = processor_percent / HUNDRED
    if fee_bearer == "recipient":
        charged = amount
        processor = cents(charged * rate + processor_flat)
        receives = amount - ours - processor
        total = amount
    else:
        # Gross up so that after the processor takes its cut of the larger
        # charge, the recipient still gets the full amount.
        charged = cents((amount + ours + processor_flat) / (Decimal(1) - rate), ROUND_CEILING)
        processor = charged - amount - ours
        receives = amount
        total = charged
    if receives <= 0:
        raise FeeError("the fees would take the whole amount; send more or let the payer cover the fees")
    return Quote(amount, currency, fee_bearer, ours, processor, total, receives, rule)
