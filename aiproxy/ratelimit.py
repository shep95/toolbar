"""Sliding-window rate limiter with constant memory per key.

Uses the "sliding window counter" approximation: the count for the current
fixed window plus a weighted share of the previous window. Each key costs
three numbers regardless of its limit, and the number of tracked keys is
capped, so an attacker rotating through many IPs cannot exhaust memory.

This is an in-process limiter, correct for a single app instance. If you run
several instances behind a load balancer, each enforces the limit separately;
swap this class for a Redis-backed one with the same interface.
"""

from __future__ import annotations

import math
import time


class RateLimiter:
    def __init__(self, window_seconds: float = 60.0, clock=time.monotonic, max_keys: int = 200_000):
        self.window = window_seconds
        self._clock = clock
        self.max_keys = max_keys
        # key -> [window_start, count_in_window, count_in_previous_window]
        self._state: dict[str, list[float]] = {}
        self._last_sweep = clock()

    def _estimate(self, key: str, now: float) -> tuple[list[float] | None, float]:
        entry = self._state.get(key)
        if entry is None:
            return None, 0.0
        start = now - (now % self.window)
        if entry[0] != start:
            # Roll forward: the old current window becomes "previous" if adjacent.
            entry[2] = entry[1] if start - entry[0] == self.window else 0.0
            entry[1] = 0.0
            entry[0] = start
        weight = 1.0 - (now - start) / self.window
        return entry, entry[1] + entry[2] * weight

    def check(self, key: str, limit: int) -> tuple[bool, int]:
        """Record a hit for ``key``. Returns (allowed, retry_after_seconds)."""
        now = self._clock()
        self._maybe_sweep(now)
        if limit <= 0:
            return False, int(self.window)
        entry, estimate = self._estimate(key, now)
        if estimate + 1 > limit:
            return False, self._retry_after(now)
        if entry is None:
            if len(self._state) >= self.max_keys:
                self._state.pop(next(iter(self._state)))
            entry = [now - (now % self.window), 0.0, 0.0]
            self._state[key] = entry
        entry[1] += 1
        return True, 0

    def is_limited(self, key: str, limit: int) -> tuple[bool, int]:
        """Like ``check`` but does not record a hit."""
        now = self._clock()
        _, estimate = self._estimate(key, now)
        if estimate >= limit:
            return True, self._retry_after(now)
        return False, 0

    def _retry_after(self, now: float) -> int:
        return max(1, math.ceil(self.window - (now % self.window)))

    def _maybe_sweep(self, now: float) -> None:
        # Drop keys idle for two windows so memory does not grow without bound.
        if now - self._last_sweep < self.window:
            return
        self._last_sweep = now
        cutoff = now - 2 * self.window
        for key in [k for k, v in self._state.items() if v[0] < cutoff]:
            del self._state[key]
