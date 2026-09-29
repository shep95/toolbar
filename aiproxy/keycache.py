"""Hot-path helpers that keep the database off the critical path.

* ``AuthCache`` remembers recently authenticated keys for a few seconds so a
  busy key does not cost a database round trip per request. It is safe:
  every billed request re-checks key and user status atomically inside the
  billing reservation, so a revoked key or suspended user is refused at once
  even while cached.
* ``KeyUsageTracker`` batches ``api_keys.last_used_at`` updates into one write
  every few seconds instead of one write per request.
"""

from __future__ import annotations

import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import bindparam, update

from .db import Database
from .models import ApiKey, utcnow


@dataclass(frozen=True)
class CachedKey:
    api_key_id: uuid.UUID
    user_id: uuid.UUID
    key_prefix: str
    key_provider: str
    rate_limit_per_minute: int | None
    country: str | None = None
    domain: str | None = None


class AuthCache:
    def __init__(self, ttl_seconds: float, max_entries: int = 50_000, clock=time.monotonic):
        self.ttl = ttl_seconds
        self.max_entries = max_entries
        self._clock = clock
        self._entries: OrderedDict[str, tuple[CachedKey, float]] = OrderedDict()

    def get(self, key_hash: str) -> CachedKey | None:
        if self.ttl <= 0:
            return None
        entry = self._entries.get(key_hash)
        if entry is None:
            return None
        if entry[1] < self._clock():
            self._entries.pop(key_hash, None)
            return None
        return entry[0]

    def put(self, key_hash: str, value: CachedKey) -> None:
        if self.ttl <= 0:
            return
        self._entries[key_hash] = (value, self._clock() + self.ttl)
        self._entries.move_to_end(key_hash)
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)

    def clear(self) -> None:
        """Called on every admin change to keys or users."""
        self._entries.clear()


class KeyUsageTracker:
    def __init__(self) -> None:
        self._pending: dict[uuid.UUID, datetime] = {}

    def touch(self, api_key_id: uuid.UUID) -> None:
        self._pending[api_key_id] = utcnow()

    def last_seen(self, api_key_id: uuid.UUID) -> datetime | None:
        return self._pending.get(api_key_id)

    async def flush(self, db: Database) -> int:
        if not self._pending:
            return 0
        batch, self._pending = self._pending, {}
        table = ApiKey.__table__
        stmt = update(table).where(table.c.id == bindparam("kid")).values(last_used_at=bindparam("ts"))
        try:
            async with db.engine.begin() as conn:
                await conn.execute(stmt, [{"kid": k, "ts": ts} for k, ts in batch.items()])
        except BaseException:
            # Put the timestamps back so the next flush retries them.
            for key, ts in batch.items():
                self._pending.setdefault(key, ts)
            raise
        return len(batch)
