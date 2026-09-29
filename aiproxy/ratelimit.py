"""Per-key sliding-window rate limiter.

This is an in-process limiter, correct for a single app instance. If you run
several instances behind a load balancer, each enforces the limit separately;
swap this class for a Redis-backed one with the same ``check`` signature.
"""

from __future__ import annotations

import time
from collections import deque


class RateLimiter:
    def __init__(self, window_seconds: float = 60.0, clock=time.monotonic):
        self.window = window_seconds
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._last_sweep = clock()

    def check(self, key: str, limit: int) -> tuple[bool, int]:
        """Record a hit for ``key``. Returns (allowed, retry_after_seconds)."""
        now = self._clock()
        self._maybe_sweep(now)
        if limit <= 0:
            return False, int(self.window)
        hits = self._hits.setdefault(key, deque())
        cutoff = now - self.window
        while hits and hits[0] <= cutoff:
            hits.popleft()
        if len(hits) >= limit:
            retry_after = max(1, int(hits[0] + self.window - now) + 1)
            return False, retry_after
        hits.append(now)
        return True, 0

    def _maybe_sweep(self, now: float) -> None:
        # Drop idle keys so memory does not grow without bound.
        if now - self._last_sweep < self.window:
            return
        self._last_sweep = now
        cutoff = now - self.window
        for key in [k for k, v in self._hits.items() if not v or v[-1] <= cutoff]:
            del self._hits[key]
