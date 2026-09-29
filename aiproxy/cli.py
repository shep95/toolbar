"""Operator commands.

    python -m aiproxy init-db            create tables (safe to re-run)
    python -m aiproxy gen-admin-token    print a random ADMIN_API_TOKEN value
    python -m aiproxy reconcile          refund transactions stuck in "pending"
"""

from __future__ import annotations

import argparse
import asyncio
import secrets
from datetime import timedelta

from .billing import BillingEngine
from .config import get_settings
from .db import Database


async def _init_db() -> None:
    db = Database.from_settings(get_settings())
    try:
        await db.create_all()
    finally:
        await db.dispose()
    print("database schema is up to date")


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
    sub.add_parser("reconcile", help="refund stale pending transactions")
    args = parser.parse_args()

    if args.command == "init-db":
        asyncio.run(_init_db())
    elif args.command == "gen-admin-token":
        print(secrets.token_urlsafe(48))
    elif args.command == "reconcile":
        asyncio.run(_reconcile())
