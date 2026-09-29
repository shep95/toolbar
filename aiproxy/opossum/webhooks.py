"""Signed events to merchants' own systems.

When a payment to a merchant settles or is refunded, an event is written to
an outbox in the same database transaction, then delivered with retries.
Each delivery carries ``Opossum-Signature: t=<unix time>,v1=<hex HMAC-SHA256
of "<t>.<body>">`` using the merchant's webhook secret, the same scheme as
Stripe's, so merchants can verify it with a few lines of code.

Payloads are the recipient's view of the payment: never the payer's account
or identity beyond what the payer chose to show that merchant.

Endpoints must be public https URLs; addresses that resolve to private,
loopback, link-local or reserved ranges are refused so the relay cannot be
pointed at internal services.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import socket
import time
from datetime import timedelta
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select

from ..models import utcnow
from ..services import Services
from .crypto import RelayKeys, random_id
from .models import OpRecipient, OpWebhookDelivery

log = logging.getLogger("aiproxy.opossum")

MAX_ATTEMPTS = 8
BACKOFF_SECONDS = (10, 60, 300, 900, 3600, 3 * 3600, 6 * 3600, 12 * 3600)
EVENT_TYPES = ("payment.settled", "payment.refunded", "payment.review", "invoice.paid", "webhook.test")


class WebhookUrlError(ValueError):
    pass


def sign(secret: str, body: bytes, timestamp: int | None = None) -> str:
    ts = str(timestamp or int(time.time()))
    mac = hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"


def new_secret() -> str:
    return "whsec_op_" + secrets.token_urlsafe(32)


async def check_url(url: str, *, resolve: bool = True) -> str:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        raise WebhookUrlError("webhook URL must be https://host/path without credentials")
    if len(url) > 300:
        raise WebhookUrlError("webhook URL is too long")
    host = parts.hostname
    try:
        literal = ipaddress.ip_address(host)
        addresses = [literal]
    except ValueError:
        if host.endswith((".local", ".internal", ".localhost")) or host == "localhost":
            raise WebhookUrlError("webhook URL must be publicly reachable") from None
        if not resolve:
            return url
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(host, parts.port or 443, type=socket.SOCK_STREAM)
        except OSError:
            raise WebhookUrlError("webhook host does not resolve") from None
        addresses = [ipaddress.ip_address(info[4][0]) for info in infos]
    for address in addresses:
        if not address.is_global or address.is_multicast:
            raise WebhookUrlError("webhook URL must not point at a private or reserved address")
    return url


def enqueue(session, recipient: OpRecipient, event_type: str, data: dict) -> None:
    """Add an event to the outbox inside the caller's transaction."""
    if not recipient.webhook_url:
        return
    event_id = random_id("evt_", 12)
    payload = json.dumps({"id": event_id, "type": event_type, "created": int(time.time()), "data": data}, separators=(",", ":"))
    session.add(OpWebhookDelivery(event_id=event_id, recipient_id=recipient.id, event_type=event_type, payload=payload,
                                  next_attempt_at=utcnow()))


async def deliver(services: Services, keys: RelayKeys, limit: int = 50) -> int:
    """Send due events. Returns how many were delivered."""
    now = utcnow()
    async with services.db.session() as session:
        rows = (await session.execute(
            select(OpWebhookDelivery, OpRecipient).join(OpRecipient, OpRecipient.id == OpWebhookDelivery.recipient_id)
            .where(OpWebhookDelivery.delivered_at.is_(None), OpWebhookDelivery.attempts < MAX_ATTEMPTS,
                   OpWebhookDelivery.next_attempt_at <= now)
            .order_by(OpWebhookDelivery.id).limit(limit)
        )).all()
    delivered = 0
    for delivery, recipient in rows:
        error = None
        try:
            if not recipient.webhook_url or not recipient.webhook_secret_enc:
                raise WebhookUrlError("webhook removed")
            url = await check_url(recipient.webhook_url)
            secret = keys.open(recipient.webhook_secret_enc, f"op_recipients:{recipient.id}:webhook")
            body = delivery.payload.encode()
            resp = await services.http.post(url, content=body, timeout=10.0, headers={
                "Content-Type": "application/json", "User-Agent": "opossum-webhooks/1",
                "Opossum-Signature": sign(secret, body), "Opossum-Event": delivery.event_type,
            })
            if not 200 <= resp.status_code < 300:
                error = f"HTTP {resp.status_code}"
        except WebhookUrlError as exc:
            error = str(exc)
        except httpx.HTTPError as exc:
            error = type(exc).__name__
        async with services.db.session() as session, session.begin():
            row = await session.get(OpWebhookDelivery, delivery.id)
            row.attempts += 1
            if error is None:
                row.delivered_at, row.last_error = utcnow(), None
                delivered += 1
            else:
                row.last_error = error[:300]
                row.next_attempt_at = utcnow() + timedelta(seconds=BACKOFF_SECONDS[min(row.attempts - 1, len(BACKOFF_SECONDS) - 1)])
    return delivered
