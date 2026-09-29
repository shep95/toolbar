"""Shared runtime objects, created once at startup and stored on ``app.state``."""

from __future__ import annotations

from dataclasses import dataclass

import httpx
from fastapi import Request

from .billing import BillingEngine
from .config import Settings
from .connectors import Connector
from .db import Database
from .ratelimit import RateLimiter


@dataclass
class Services:
    settings: Settings
    db: Database
    billing: BillingEngine
    limiter: RateLimiter
    auth_failure_limiter: RateLimiter
    connectors: dict[str, Connector]
    http: httpx.AsyncClient


def get_services(request: Request) -> Services:
    return request.app.state.services
