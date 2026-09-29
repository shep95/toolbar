"""Housekeeping run by the app's maintenance loop.

Minimum retention in practice: relay records are deleted when their
jurisdiction's retention period ends; a closed account's identity is deleted
once no record needs it; sessions, nonces and idempotency keys expire.
"""

from __future__ import annotations

import logging
from datetime import timedelta

from sqlalchemy import delete, select, update

from ..models import utcnow
from ..services import Services
from . import audit
from .models import OpAccount, OpIdentity, OpRecipient, OpTransaction
from .web import purge

log = logging.getLogger("aiproxy.opossum")

SANDBOX_RECIPIENTS = (
    ("north-coffee", "North Coffee (sandbox)", "dining"),
    ("harbor-books", "Harbor Books (sandbox)", "shopping"),
    ("city-power", "City Power & Light (sandbox)", "bills"),
    ("open-shelter", "Open Shelter Fund (sandbox)", "donations"),
)


async def run(services: Services) -> None:
    if services.settings.opossum_master_key is None:
        return
    await purge(services)
    now = utcnow()
    async with services.db.session() as session, session.begin():
        # A payment stuck before reaching the processor is marked failed.
        await session.execute(update(OpTransaction).where(
            OpTransaction.status == "creating", OpTransaction.created_at < now - timedelta(minutes=15)).values(status="failed"))
        expired = (await session.execute(select(OpTransaction.id).where(OpTransaction.retain_until < now).limit(1000))).scalars().all()
        if expired:
            await session.execute(delete(OpTransaction).where(OpTransaction.id.in_(expired)))
            await audit.append(session, "system", "retention_purge", None, payments=len(expired))
        closed = (await session.execute(select(OpAccount.id).where(
            OpAccount.status == "closed", OpAccount.identity_retain_until.is_not(None), OpAccount.identity_retain_until < now))).scalars().all()
        for account_id in closed:
            await session.execute(delete(OpIdentity).where(OpIdentity.account_id == account_id))
            await session.execute(update(OpAccount).where(OpAccount.id == account_id).values(identity_retain_until=None))
        if closed:
            await audit.append(session, "system", "identity_retention_ended", None, accounts=len(closed))


async def seed_sandbox(services: Services) -> None:
    """Give a fresh install a few clearly labelled test recipients."""
    s = services.settings
    if s.opossum_master_key is None or not (s.opossum_sandbox_enabled and s.opossum_seed_sandbox_recipients):
        return
    async with services.db.session() as session, session.begin():
        if await session.scalar(select(OpRecipient.id).limit(1)):
            return
        for handle, name, category in SANDBOX_RECIPIENTS:
            session.add(OpRecipient(handle=handle, display_name=name, category=category, country="US", processor="sandbox"))
        await audit.append(session, "system", "sandbox_recipients_seeded", None, count=len(SANDBOX_RECIPIENTS))
    log.info("opossum sandbox recipients created")
