"""API key generation, hashing and format validation."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets

KEY_PREFIX = "apx_"
# "apx_" + 43 url-safe base64 characters = 256 bits of randomness.
_KEY_RE = re.compile(r"^apx_[A-Za-z0-9_-]{43}$")

# Shapes of real provider credentials. If a client sends one of these to us it
# is either a mistake or an attempt to smuggle a provider key through the proxy.
_UPSTREAM_KEY_PATTERNS = (
    ("anthropic", re.compile(r"^sk-ant-")),
    ("openai", re.compile(r"^sk-(proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}")),
    ("mistral", re.compile(r"^[A-Za-z0-9]{32}$")),
)


def generate_api_key() -> str:
    """Return a new raw key. Show it to the user once; store only its hash."""
    return KEY_PREFIX + secrets.token_urlsafe(32)


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def display_prefix(raw_key: str) -> str:
    return raw_key[:12]


def is_valid_key_format(raw_key: str) -> bool:
    return bool(_KEY_RE.match(raw_key))


def looks_like_upstream_key(raw_key: str) -> str | None:
    """Return the provider name if the value looks like a real provider credential."""
    for provider, pattern in _UPSTREAM_KEY_PATTERNS:
        if pattern.match(raw_key):
            return provider
    return None


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
