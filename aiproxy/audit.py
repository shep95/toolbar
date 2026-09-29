"""Audit trail for rejected requests.

Writes go to the ``audit_log`` table and to the application log. If the
database is down the row is lost but the log line is still written, so a
rejection is never silent.
"""

from __future__ import annotations

import logging
import uuid

from .db import DB_UNAVAILABLE_ERRORS, Database
from .models import AuditLog

log = logging.getLogger("aiproxy.audit")


async def record_rejection(
    db: Database,
    *,
    status_code: int,
    outcome: str,
    request_id: str,
    method: str,
    path: str,
    client_ip: str | None,
    detail: str | None = None,
    user_id: uuid.UUID | None = None,
    api_key_id: uuid.UUID | None = None,
    key_prefix: str | None = None,
    write_db: bool = True,
) -> None:
    log.info(
        "rejected",
        extra={
            "event": "request_rejected",
            "request_id": request_id,
            "status_code": status_code,
            "outcome": outcome,
            "path": path,
            "user_id": str(user_id) if user_id else None,
            "api_key_id": str(api_key_id) if api_key_id else None,
            "client_ip": client_ip,
            "detail": detail,
        },
    )
    if not write_db:
        return
    try:
        async with db.session() as session, session.begin():
            session.add(
                AuditLog(
                    request_id=request_id,
                    user_id=user_id,
                    api_key_id=api_key_id,
                    key_prefix=key_prefix,
                    client_ip=client_ip,
                    method=method,
                    path=path[:300],
                    status_code=status_code,
                    outcome=outcome,
                    detail=(detail or None) and detail[:2000],
                )
            )
    except DB_UNAVAILABLE_ERRORS:
        log.exception("could not write audit row", extra={"request_id": request_id})
