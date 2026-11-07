"""User records. Route handlers call these; they never build MongoDB filters from raw input."""

from fastapi import HTTPException, status
from pymongo.asynchronous.database import AsyncDatabase
from pymongo.errors import DuplicateKeyError

from app.security.passwords import hash_password, policy_problems
from app.security.sessions import utcnow


def ensure_password_ok(password: str, username: str | None) -> None:
    problems = policy_problems(password, username)
    if problems:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, {"field": "password", "problems": problems}
        )


async def create_user(
    db: AsyncDatabase,
    *,
    username: str,
    password: str,
    role: str,
    rounds: int,
    created_by: str | None,
) -> dict:
    ensure_password_ok(password, username)
    doc = {
        "username": username,
        "password_hash": hash_password(password, rounds),
        "role": role,
        "disabled": False,
        # Whoever set this password isn't the user, so the user must pick their own.
        "must_change_password": True,  # nosec B105 - boolean flag
        "failed_logins": 0,
        "locked_until": None,
        "created_at": utcnow(),
        "created_by": created_by,
        "last_login_at": None,
    }
    try:
        result = await db.users.insert_one(doc)
    except DuplicateKeyError:
        raise HTTPException(status.HTTP_409_CONFLICT, "That username is already taken") from None
    doc["_id"] = result.inserted_id
    return doc


async def count_active_admins(db: AsyncDatabase, excluding=None) -> int:
    query: dict = {"role": "admin", "disabled": False}
    if excluding is not None:
        query["_id"] = {"$ne": excluding}
    return await db.users.count_documents(query)
