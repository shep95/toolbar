"""Operator commands.

    python -m aiproxy init-db            create tables (safe to re-run)
    python -m aiproxy gen-admin-token    print a random ADMIN_API_TOKEN value
    python -m aiproxy gen-opossum-key    print a random OPOSSUM_MASTER_KEY value
    python -m aiproxy reconcile          refund transactions stuck in "pending"
"""

from __future__ import annotations

import argparse
import asyncio
import secrets
import sys
from datetime import timedelta

from .billing import BillingEngine
from .config import get_settings
from .db import DB_UNAVAILABLE_ERRORS, Database


async def _init_db(attempts: int = 30, delay: float = 2.0) -> None:
    """Create missing tables, waiting for the database to come up.

    On Railway (and most platforms) the app container can start a few
    seconds before the database accepts connections.
    """
    db = Database.from_settings(get_settings())
    try:
        for attempt in range(1, attempts + 1):
            try:
                await db.create_all()
                break
            except DB_UNAVAILABLE_ERRORS as exc:
                if attempt == attempts:
                    raise
                print(f"database not reachable yet ({type(exc).__name__}); retry {attempt}/{attempts - 1} in {delay:.0f}s",
                      file=sys.stderr, flush=True)
                await asyncio.sleep(delay)
    finally:
        await db.dispose()
    print("database schema is up to date", flush=True)


async def _reconcile() -> None:
    settings = get_settings()
    db = Database.from_settings(settings)
    try:
        count = await BillingEngine(db, settings.default_fee_per_request).reconcile_stale(
            timedelta(minutes=settings.pending_timeout_minutes)
        )
    finally:
        await db.dispose()
    print(f"reconciled {count} stale transactions")


def main() -> None:
    parser = argparse.ArgumentParser(prog="aiproxy")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-db", help="create database tables")
    sub.add_parser("gen-admin-token", help="print a new random admin token")
    sub.add_parser("gen-opossum-key", help="print a new random Opossum master key")
    sub.add_parser("reconcile", help="refund stale pending transactions")
    args = parser.parse_args()

    if args.command == "init-db":
        asyncio.run(_init_db())
    elif args.command == "gen-admin-token":
        print(secrets.token_urlsafe(48))
    elif args.command == "gen-opossum-key":
        print(secrets.token_urlsafe(32))
    elif args.command == "reconcile":
        asyncio.run(_reconcile())
