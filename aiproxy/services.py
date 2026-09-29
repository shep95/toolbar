"""Shared runtime objects, created once at startup and stored on ``app.state``."""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx
from fastapi import Request

from .billing import BillingEngine
from .config import Settings
from .connectors import Connector
from .db import Database
from .keycache import AuthCache, KeyUsageTracker
from .ratelimit import RateLimiter


@dataclass
class Services:
    settings: Settings
    db: Database
    billing: BillingEngine
    connectors: dict[str, Connector]
    http: httpx.AsyncClient
    auth_cache: AuthCache
    key_usage: KeyUsageTracker = field(default_factory=KeyUsageTracker)
    # Per-key request limit.
    limiter: RateLimiter = field(default_factory=RateLimiter)
    # Every request per client IP, checked before authentication.
    ip_limiter: RateLimiter = field(default_factory=RateLimiter)
    # Failed authentications per IP: past the limit the IP gets 429 without a DB lookup.
    auth_failure_limiter: RateLimiter = field(default_factory=RateLimiter)
    # Failed-auth rows written to audit_log per IP.
    audit_failure_limiter: RateLimiter = field(default_factory=RateLimiter)
    # Failed admin-token attempts per IP.
    admin_failure_limiter: RateLimiter = field(default_factory=RateLimiter)
    # provider -> (expires_at, raw /models body, parsed model ids)
    models_cache: dict = field(default_factory=dict)


def get_services(request: Request) -> Services:
    return request.app.state.services
