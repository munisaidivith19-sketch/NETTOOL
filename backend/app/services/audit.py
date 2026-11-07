"""Append-only audit log (CLAUDE.md 7.10).

The app only ever inserts into audit_log; nothing in the code updates or deletes entries.
Never pass passwords, tokens, keys or cookies in `details`.
"""

import logging
from typing import Any

from fastapi import Request
from pymongo.asynchronous.database import AsyncDatabase

from app.security.sessions import utcnow

logger = logging.getLogger("netmap.audit")


def client_ip(request: Request) -> str:
    # Phase 9 adds trusted-proxy handling so this is the real client IP behind Render's proxy.
    return request.client.host if request.client else "unknown"


def user_actor(user: Any) -> dict:
    return {"type": "user", "id": str(user.id), "username": user.username}


async def record(
    db: AsyncDatabase,
    request: Request,
    *,
    action: str,
    result: str,
    actor: dict | None = None,
    target: dict | None = None,
    details: dict | None = None,
) -> None:
    entry = {
        "at": utcnow(),
        "action": action,  # e.g. "auth.login"
        "result": result,  # "success" | "failure" | "denied"
        "actor": actor,
        "target": target,
        "ip": client_ip(request),
        "request_id": getattr(request.state, "request_id", None),
        "details": details or {},
    }
    try:
        await db.audit_log.insert_one(entry)
    except Exception:
        # A failed audit write is logged loudly but doesn't break the user's request.
        logger.exception("Could not write audit entry for action %s", action)
