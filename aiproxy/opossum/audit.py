"""Hash-chained audit trail.

Every entry stores the hash of the one before it, and its own hash covers
its content plus that link. Changing, removing or reordering any past entry
breaks every hash after it, which ``verify_chain`` reports. The head row is
locked while appending so concurrent writers cannot fork the chain.

Entries describe what happened (a payment settled, a device was added, a
case opened data) using opaque IDs. They never hold names, emails or notes.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .crypto import canonical, sha256_hex
from .models import OpAuditEntry, OpAuditHead

GENESIS = "0" * 64


def _entry_hash(prev_hash: str, at: datetime, actor: str, action: str, subject: str | None, details: str) -> str:
    stamp = (at if at.tzinfo else at.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).isoformat(timespec="microseconds")
    return sha256_hex(prev_hash.encode() + canonical([stamp, actor, action, subject, details]))


async def append(session: AsyncSession, actor: str, action: str, subject: str | None = None, **details) -> OpAuditEntry:
    """Append within the caller's transaction."""
    head = (await session.execute(select(OpAuditHead).where(OpAuditHead.id == 1).with_for_update())).scalar_one_or_none()
    if head is None:
        head = OpAuditHead(id=1, hash=GENESIS, count=0)
        session.add(head)
        await session.flush()
    at = datetime.now(timezone.utc)
    body = json.dumps(details, sort_keys=True, default=str)[:4000]
    entry = OpAuditEntry(
        at=at, actor=actor[:80], action=action[:60], subject=(subject or None) and subject[:80], details=body,
        prev_hash=head.hash, hash=_entry_hash(head.hash, at, actor[:80], action[:60], (subject or None) and subject[:80], body),
    )
    session.add(entry)
    head.hash = entry.hash
    head.count += 1
    await session.flush()
    return entry


async def verify_chain(session: AsyncSession) -> dict:
    """Walk the whole chain. Returns ok, count, and the first broken entry if any."""
    prev, count = GENESIS, 0
    result = await session.stream(select(OpAuditEntry).order_by(OpAuditEntry.id))
    async for (entry,) in result:
        count += 1
        if entry.prev_hash != prev or entry.hash != _entry_hash(prev, entry.at, entry.actor, entry.action, entry.subject, entry.details):
            return {"ok": False, "entries": count, "broken_at": entry.id}
        prev = entry.hash
    head = (await session.execute(select(OpAuditHead).where(OpAuditHead.id == 1))).scalar_one_or_none()
    if head is not None and (head.hash != prev or head.count != count):
        return {"ok": False, "entries": count, "broken_at": "head", "detail": "entries were removed from the end"}
    return {"ok": True, "entries": count, "head": prev}
