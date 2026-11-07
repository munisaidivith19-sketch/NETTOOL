"""Brute-force protection for login (CLAUDE.md 7.1).

Two independent limits:
- per IP address: many failed logins from one address in a short window → HTTP 429
- per account: 5 failed logins in a row lock that account for 15 minutes
Both are stored in MongoDB, so they survive a restart of the backend.
"""

from datetime import timedelta

from pymongo import ReturnDocument
from pymongo.asynchronous.database import AsyncDatabase

from app.security.sessions import utcnow

IP_WINDOW = timedelta(minutes=5)
IP_MAX_FAILURES = 10
LOCK_AFTER_FAILURES = 5
LOCK_DURATION = timedelta(minutes=15)


async def ip_is_limited(db: AsyncDatabase, ip: str) -> bool:
    since = utcnow() - IP_WINDOW
    count = await db.login_attempts.count_documents(
        {"ip": ip, "at": {"$gte": since}}, limit=IP_MAX_FAILURES
    )
    return count >= IP_MAX_FAILURES


async def record_ip_failure(db: AsyncDatabase, ip: str) -> None:
    await db.login_attempts.insert_one({"ip": ip, "at": utcnow()})


def is_locked(user: dict) -> bool:
    locked_until = user.get("locked_until")
    return locked_until is not None and locked_until > utcnow()


async def record_user_failure(db: AsyncDatabase, user_id) -> bool:
    """Count a failed login for this account. Returns True if this failure locked it."""
    updated = await db.users.find_one_and_update(
        {"_id": user_id},
        {"$inc": {"failed_logins": 1}},
        return_document=ReturnDocument.AFTER,
    )
    if updated and updated.get("failed_logins", 0) >= LOCK_AFTER_FAILURES:
        await db.users.update_one(
            {"_id": user_id},
            {"$set": {"locked_until": utcnow() + LOCK_DURATION, "failed_logins": 0}},
        )
        return True
    return False


async def reset_user_failures(db: AsyncDatabase, user_id) -> None:
    await db.users.update_one(
        {"_id": user_id}, {"$set": {"failed_logins": 0, "locked_until": None}}
    )
