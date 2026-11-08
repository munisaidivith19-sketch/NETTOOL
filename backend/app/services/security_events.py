"""Repeated security failures: bounded audit entries and security alerts (CLAUDE.md 7.10).

Problem: requests that fail authentication come from people we can't identify, and each one
used to write an audit entry. Anyone on the internet could send bad agent signatures in a loop
and grow audit_log until the database (Atlas M0: 512 MB) was full.

So failures are counted per (kind, source IP, 10-minute window) in `security_events`:
- the first AUDIT_LIMIT failures in a window are audited in full, as before;
- the next one writes a single "further entries suppressed" audit entry;
- the rest only increase the counter, which is still visible in the alert.
Once a source reaches the alert threshold, a `security` alert opens, and it is notified like
any other alert. The counters expire after a day (TTL index).
"""

import asyncio
import logging
from datetime import timedelta

from fastapi import Request
from pymongo import ReturnDocument
from pymongo.asynchronous.database import AsyncDatabase
from pymongo.errors import DuplicateKeyError

from app.security.sessions import utcnow
from app.services import audit, notify
from app.services.alerts import upsert_alert

logger = logging.getLogger("netmap.security")

WINDOW = timedelta(minutes=10)
AUDIT_LIMIT = 20

# kind -> (failures in one window that open an alert, alert text)
KINDS = {
    "agent_auth": (5, "Repeated agent authentication failures from {ip}"),
    "login_limited": (1, "Sign-in attempts from {ip} hit the rate limit"),
}

# Background notification tasks are kept here so they aren't garbage-collected mid-run.
_tasks: set[asyncio.Task] = set()


def _window(now) -> int:
    return int(now.timestamp()) // int(WINDOW.total_seconds())


async def _count(db: AsyncDatabase, kind: str, ip: str, now) -> int:
    query = {"kind": kind, "ip": ip, "window": _window(now)}
    for _ in range(2):  # two first failures at once: the unique index lets one insert
        try:
            doc = await db.security_events.find_one_and_update(
                query, {"$inc": {"count": 1}, "$setOnInsert": {"at": now}},
                upsert=True, return_document=ReturnDocument.AFTER)
            return doc["count"]
        except DuplicateKeyError:
            continue
    return AUDIT_LIMIT + 2  # still racing: count it, but don't audit or alert again


def _notify_soon(request: Request) -> None:
    """Send pending alert notifications without delaying (or depending on) this response."""
    task = asyncio.get_running_loop().create_task(
        notify.dispatch_pending(request.app.state.db, request.app.state.settings))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)


async def open_alert(request: Request, *, key: str, message: str, target: dict,
                     details: dict) -> None:
    await upsert_alert(request.app.state.db, key=key, type_="security", severity="warning",
                       message=message, target=target, details=details, now=utcnow())
    _notify_soon(request)


async def failure(db: AsyncDatabase, request: Request, kind: str, *, action: str, result: str,
                  actor: dict | None, details: dict) -> None:
    """Record one failed attempt of `kind` from this request's source address."""
    ip = audit.client_ip(request)
    now = utcnow()
    count = await _count(db, kind, ip, now)
    if count <= AUDIT_LIMIT:
        await audit.record(db, request, action=action, result=result, actor=actor,
                           details=details)
    elif count == AUDIT_LIMIT + 1:
        await audit.record(db, request, action=action, result=result, actor=None, details={
            "reason": "suppressed",
            "note": f"More than {AUDIT_LIMIT} failures from this address within "
                    f"{int(WINDOW.total_seconds() // 60)} minutes; further ones are counted "
                    "in the security alert instead of being logged one by one."})
    threshold, text = KINDS[kind]
    if count == threshold or count == AUDIT_LIMIT + 1:
        minutes = int(WINDOW.total_seconds() // 60)
        await open_alert(
            request, key=f"security:{kind}:{ip}",
            message=text.format(ip=ip) + f" ({count}+ in {minutes} minutes).",
            target={"type": "address", "ip": ip},
            details={"kind": kind, "ip": ip, "count": count, "window_minutes": minutes})
