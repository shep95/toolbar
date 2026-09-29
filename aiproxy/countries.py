"""Country-adjusted fees.

The base fee ($0.03) is set for high-income economies. Elsewhere it is scaled
by the country's World Bank income group, the same idea software companies use
for regional ("purchasing power parity") pricing:

    high income           x 1.00   ->  $0.0300
    upper-middle income   x 0.60   ->  $0.0180
    lower-middle income   x 0.35   ->  $0.0105
    low income            x 0.20   ->  $0.0060

Groups follow the World Bank's FY2025 classification (July 2024). The World
Bank reclassifies a handful of countries every July, so admins can override
any country's multiplier in the dashboard (``country_pricing`` table) without
a code change. A country that is unknown, or not listed here, pays the full
base fee, so a missing entry can never cause undercharging.

Balances and fees are kept in US dollars. Customers can still pay top-ups in
their own currency: with Stripe Adaptive Pricing switched on, Checkout shows
the local price and Stripe settles in USD.
"""

from __future__ import annotations

import re
from decimal import Decimal

HIGH = "high"
UPPER_MIDDLE = "upper_middle"
LOWER_MIDDLE = "lower_middle"
LOW = "low"

DEFAULT_MULTIPLIERS: dict[str, Decimal] = {
    HIGH: Decimal("1.00"),
    UPPER_MIDDLE: Decimal("0.60"),
    LOWER_MIDDLE: Decimal("0.35"),
    LOW: Decimal("0.20"),
}

_LOW = """
AF BF BI CD CF ER ET GM GW KP LR MG ML MW MZ NE RW SD SL SO SS SY TD TG UG YE
"""

_LOWER_MIDDLE = """
AO BD BJ BO BT CI CG CM CV DJ EG FM GH GN HN HT IN JO KE KG KH KI KM LA LB LK LS
MA MM MR NG NI NP PG PH PK PS SB SN ST SZ TJ TL TN TZ UZ VN VU WS ZM ZW
"""

_UPPER_MIDDLE = """
AL AM AR AZ BA BR BW BY BZ CN CO CR CU DM DO DZ EC FJ GA GD GE GQ GT ID IQ IR JM KZ LC
LY MD ME MH MK MN MU MV MX MY NA PE PY RS SR SV TH TM TO TR TV UA VC XK ZA
"""

# Everything else (US, Canada, EU, UK, Japan, Korea, Australia, Gulf states,
# Singapore, Chile, Uruguay, Panama, etc.) is high income, as is any code not
# listed at all.


def _codes(block: str) -> set[str]:
    return set(block.split())


INCOME_GROUP: dict[str, str] = {}
for _group, _block in ((LOW, _LOW), (LOWER_MIDDLE, _LOWER_MIDDLE), (UPPER_MIDDLE, _UPPER_MIDDLE)):
    for _code in _codes(_block):
        INCOME_GROUP[_code] = _group

COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
MIN_MULTIPLIER = Decimal("0.01")
MAX_MULTIPLIER = Decimal("10")


def normalise_country(value: object) -> str | None:
    """Return an upper-case ISO alpha-2 code, or None. Raises ValueError on junk."""
    if value is None or value == "":
        return None
    if not isinstance(value, str) or not COUNTRY_RE.match(value.strip().upper()):
        raise ValueError("country must be an ISO 3166-1 alpha-2 code such as US, IN or DE")
    return value.strip().upper()


def income_group(country: str | None) -> str:
    if not country:
        return HIGH
    return INCOME_GROUP.get(country, HIGH)


def default_multiplier(country: str | None) -> Decimal:
    return DEFAULT_MULTIPLIERS[income_group(country)]


def plain(value) -> str:
    """Decimal as plain text without trailing zeros: 250, 49.9, 0.35 (never 2.5E+2)."""
    text = format(Decimal(value).normalize(), "f")
    return text
