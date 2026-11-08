"""Server-side sessions kept in MongoDB, referenced by an httpOnly cookie (CLAUDE.md 7.1).

The cookie holds a random token. The database stores only the token's SHA-256 hash, so someone
who reads the sessions collection still can't log in as anyone.
"""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Response
from pymongo.asynchronous.database import AsyncDatabase

COOKIE_NAME = "netmap_session"
ABSOLUTE_LIFETIME = timedelta(hours=8)
IDLE_TIMEOUT = timedelta(minutes=30)
# last_seen is refreshed at most this often, to avoid one database write per request.
TOUCH_INTERVAL = timedelta(seconds=60)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def create_session(
    db: AsyncDatabase, user_id: Any, ip: str | None, user_agent: str | None,
    mfa: str | None = None,
) -> tuple[str, dict]:
    token = secrets.token_urlsafe(32)
    now = utcnow()
    session = {
        "token_hash": hash_token(token),
        "user_id": user_id,
        "csrf_token": secrets.token_urlsafe(32),
        "created_at": now,
        "last_seen": now,
        # The TTL index deletes the document after this time: the 8-hour absolute limit.
        "expires_at": now + ABSOLUTE_LIFETIME,
        "ip": ip,
        "user_agent": (user_agent or "")[:200],
        # How the second step was passed ("totp", "recovery_code"), or None without MFA.
        "mfa": mfa,
    }
    await db.sessions.insert_one(session)
    return token, session


async def load_session(db: AsyncDatabase, token: str | None) -> dict | None:
    """Return the live session for this cookie value, or None. Expired sessions are deleted."""
    if not token or len(token) > 128:
        return None
    session = await db.sessions.find_one({"token_hash": hash_token(token)})
    if session is None:
        return None
    now = utcnow()
    # The TTL monitor runs only once a minute, so expiry is also checked here exactly.
    if session["expires_at"] <= now or session["last_seen"] + IDLE_TIMEOUT <= now:
        await db.sessions.delete_one({"_id": session["_id"]})
        return None
    if now - session["last_seen"] >= TOUCH_INTERVAL:
        await db.sessions.update_one({"_id": session["_id"]}, {"$set": {"last_seen": now}})
        session["last_seen"] = now
    return session


async def revoke_session(db: AsyncDatabase, token: str | None) -> None:
    if token and len(token) <= 128:
        await db.sessions.delete_one({"token_hash": hash_token(token)})


async def revoke_user_sessions(db: AsyncDatabase, user_id: Any) -> int:
    result = await db.sessions.delete_many({"user_id": user_id})
    return result.deleted_count


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=int(ABSOLUTE_LIFETIME.total_seconds()),
        httponly=True,  # JavaScript can't read it, so an XSS bug can't steal it
        secure=True,  # only sent over HTTPS (browsers treat http://localhost as secure too)
        samesite="strict",  # never sent on requests started by another site
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(COOKIE_NAME, path="/", httponly=True, secure=True, samesite="strict")
