"""Housekeeping run by the app's maintenance loop.

Minimum retention in practice: relay records are deleted when their
jurisdiction's retention period ends; a closed account's identity is deleted
once no record needs it; sessions, nonces and idempotency keys expire.
"""

from __future__ import annotations

import logging
import time
from datetime import timedelta

from sqlalchemy import delete, select, update

from ..models import utcnow
from ..services import Services
from . import audit
from .models import OpAccount, OpIdentity, OpRecipient, OpTransaction
from .web import purge

log = logging.getLogger("aiproxy.opossum")

ONBOARDING_POLL_SECONDS = 300
_LAST_ONBOARDING_POLL = [float("-inf")]

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
    await _integrations(services)
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


async def _integrations(services: Services) -> None:
    """Merchant webhooks, the OFAC list, and Stripe Connect onboarding. Each is
    isolated so one failing outside system never stops the others."""
    from . import sanctions, webhooks
    from .processors import PLATFORM_ACCOUNT, ProcessorError
    from .stripe_ops import account_ready
    from .web import keys

    try:
        await webhooks.deliver(services, keys(services))
    except Exception:  # noqa: BLE001 - keep the loop alive
        log.exception("webhook delivery failed")
    if services.settings.opossum_chain_enabled:
        from . import chains

        try:
            await chains.watch(services)
        except Exception:  # noqa: BLE001
            log.exception("chain watch failed")
    try:
        if await sanctions.due(services):
            await sanctions.refresh_ofac(services)
    except Exception:  # noqa: BLE001
        log.exception("OFAC refresh failed")
    if not services.settings.stripe_secret_key or time.monotonic() - _LAST_ONBOARDING_POLL[0] < ONBOARDING_POLL_SECONDS:
        return
    _LAST_ONBOARDING_POLL[0] = time.monotonic()
    async with services.db.session() as session:
        pending = (await session.execute(select(OpRecipient).where(
            OpRecipient.status == "onboarding", OpRecipient.processor == "stripe",
            OpRecipient.processor_account.is_not(None), OpRecipient.processor_account != PLATFORM_ACCOUNT).limit(20))).scalars().all()
    for recipient in pending:
        try:
            ready, _ = await account_ready(services, recipient.processor_account)
        except ProcessorError:
            continue
        if ready:
            async with services.db.session() as session, session.begin():
                row = await session.get(OpRecipient, recipient.id)
                if row.status == "onboarding":
                    row.status = "active"
                    await audit.append(session, "system", "recipient_ready", row.handle)
