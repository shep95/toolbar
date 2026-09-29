from __future__ import annotations

from decimal import Decimal

from aiproxy.billing import Price
from aiproxy.config import Settings
from aiproxy.connectors.base import SSEParser, usage_from_dict
from aiproxy.ratelimit import RateLimiter
from aiproxy.security import generate_api_key, is_valid_key_format, looks_like_upstream_key


def test_sse_parser_handles_events_split_across_chunks():
    parser = SSEParser()
    assert parser.feed(b"event: message_start\ndata: {\"a\"") == []
    events = parser.feed(b": 1}\n\ndata: [DONE]\r\n\r\n")
    assert [(e.event, e.data) for e in events] == [("message_start", '{"a": 1}'), (None, "[DONE]")]
    assert parser.feed(b": keep-alive comment\n\n") == []
    assert parser.feed(b"data: tail") == []
    assert [e.data for e in parser.flush()] == ["tail"]


def test_rate_limiter_sliding_window():
    now = [0.0]
    limiter = RateLimiter(window_seconds=60, clock=lambda: now[0])
    assert [limiter.check("k", 2)[0] for _ in range(3)] == [True, True, False]
    allowed, retry = limiter.check("k", 2)
    assert not allowed and 1 <= retry <= 61
    assert limiter.check("other", 2)[0]
    now[0] = 60.5
    assert limiter.check("k", 2)[0]


def test_key_format_and_upstream_detection():
    key = generate_api_key()
    assert is_valid_key_format(key)
    assert looks_like_upstream_key(key) is None
    assert not is_valid_key_format(key + "x")
    assert looks_like_upstream_key("sk-ant-api03-xyz") == "anthropic"
    assert looks_like_upstream_key("sk-proj-" + "a" * 40) == "openai"
    assert looks_like_upstream_key("A" * 32) == "mistral"


def test_price_rounding():
    assert Price(Decimal("0.03")).fee_for(None) == Decimal("0.030000")
    assert Price(Decimal("0.01"), Decimal("0.002")).fee_for(1234) == Decimal("0.012468")
    assert Price(Decimal("0"), Decimal("0.0000005")).fee_for(1) == Decimal("0.000000")


def test_usage_shapes():
    assert usage_from_dict({"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}).total == 3
    assert usage_from_dict({"input_tokens": 4, "output_tokens": 5}).total == 9
    assert usage_from_dict(None).total is None


def test_database_url_normalisation():
    s = Settings(_env_file=None, database_url="postgres://u:p@host:5432/db")
    assert s.database_url == "postgresql+asyncpg://u:p@host:5432/db"
