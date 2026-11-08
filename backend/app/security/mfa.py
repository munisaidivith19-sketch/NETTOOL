"""Two-step sign-in with TOTP codes (CLAUDE.md 7.1, Phase 8). Required for admins.

How a TOTP code works: the server and the phone share a random secret. Every 30 seconds both
compute HMAC-SHA1(secret, number of 30-second steps since 1970) and shorten it to 6 digits
(RFC 6238). Knowing the password is no longer enough: the attacker also needs the phone.

Storage, on the user document (`users.mfa`):
- secret_ct    the shared secret, Fernet-encrypted under MFA_ENCRYPTION_KEY. It can't be
               hashed like a password, because the server must compute codes from it.
- last_step    the time step of the last accepted code. A code is accepted only for a later
               step, so a code seen over someone's shoulder (or replayed) can't be used again.
- recovery     SHA-256 hashes of 10 single-use recovery codes. They are 50-bit random values,
               like session tokens, so a fast hash is enough (no dictionary to guess from).

Sign-in with MFA is two requests. The password step creates a short-lived *challenge*, not a
session: the browser gets the challenge token in a cookie that only /api/auth/mfa receives.
The code step turns the challenge into a normal session.
"""

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
from typing import Any

import pyotp
import segno
from fastapi import HTTPException, Request, Response, status
from pymongo import ReturnDocument
from pymongo.asynchronous.database import AsyncDatabase

from app.security.rbac import mark_access
from app.security.sessions import hash_token, utcnow

ISSUER = "NetMap"
STEP_SECONDS = 30
# One step either side: phones whose clock is up to ~30 s off still work.
VALID_WINDOW = 1

CHALLENGE_COOKIE = "netmap_mfa"
CHALLENGE_PATH = "/api/auth/mfa"
CHALLENGE_LIFETIME = timedelta(minutes=5)
CHALLENGE_MAX_ATTEMPTS = 5
SETUP_LIFETIME = timedelta(minutes=10)

RECOVERY_CODE_COUNT = 10
# Crockford-style base32: no 0/O or 1/I to misread. 10 characters = 50 random bits.
RECOVERY_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
RECOVERY_WARN_AT = 2

INVALID_CODE = "Invalid or expired code"


# ---- codes ------------------------------------------------------------------------------

def new_secret() -> str:
    return pyotp.random_base32()  # 32 base32 characters = 160 bits, the RFC 4226 recommendation


def provisioning_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER)


def qr_rows(uri: str) -> list[str]:
    """The QR code as rows of '0'/'1'. React draws each '1' as an SVG square, so no image or
    data: URL is needed and the strict Content-Security-Policy stays as it is."""
    qr = segno.make(uri, error="m", micro=False)
    return ["".join("1" if dark else "0" for dark in row)
            for row in qr.matrix_iter(scale=1, border=0)]


def matching_step(secret: str, code: str, now: datetime) -> int | None:
    """The time step this code belongs to (current one or one either side), else None."""
    current = int(now.timestamp()) // STEP_SECONDS
    found = None
    for step in range(current - VALID_WINDOW, current + VALID_WINDOW + 1):
        # Compare every candidate in constant time; don't stop early.
        if hmac.compare_digest(pyotp.TOTP(secret).at(step * STEP_SECONDS), code):
            found = step
    return found


async def use_step(db: AsyncDatabase, user_id: Any, step: int) -> bool:
    """Record `step` as used. False if this or a later step was already used (a replay).
    One conditional update, so two requests with the same code can't both win."""
    result = await db.users.update_one(
        {"_id": user_id, "mfa.enabled": True,
         "$or": [{"mfa.last_step": {"$lt": step}}, {"mfa.last_step": None}]},
        {"$set": {"mfa.last_step": step}},
    )
    return result.modified_count == 1


def normalize_recovery_code(code: str) -> str:
    return "".join(c for c in code.upper() if c not in "- ")


def hash_recovery_code(code: str) -> str:
    return hashlib.sha256(normalize_recovery_code(code).encode()).hexdigest()


def new_recovery_codes() -> list[str]:
    codes = []
    for _ in range(RECOVERY_CODE_COUNT):
        raw = "".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


async def use_recovery_code(db: AsyncDatabase, user_id: Any, code: str) -> int | None:
    """Spend one recovery code. Returns how many are left, or None if it wasn't valid."""
    digest = hash_recovery_code(code)
    updated = await db.users.find_one_and_update(
        {"_id": user_id, "mfa.enabled": True, "mfa.recovery": digest},
        {"$pull": {"mfa.recovery": digest}},
        projection={"mfa.recovery": 1},
        return_document=ReturnDocument.AFTER,
    )
    if updated is None:
        return None
    return len(updated["mfa"].get("recovery", []))


def user_status(doc: dict) -> dict:
    mfa = doc.get("mfa") or {}
    enabled = bool(mfa.get("enabled"))
    return {"enabled": enabled,
            "required": doc.get("role") == "admin",
            "recovery_codes_left": len(mfa.get("recovery", [])) if enabled else 0}


# ---- the sign-in challenge ----------------------------------------------------------------

async def create_challenge(db: AsyncDatabase, user_id: Any, ip: str) -> str:
    token = secrets.token_urlsafe(32)
    now = utcnow()
    await db.mfa_challenges.insert_one({
        "token_hash": hash_token(token), "user_id": user_id, "ip": ip, "attempts": 0,
        "created_at": now,
        "expires_at": now + CHALLENGE_LIFETIME,  # TTL index removes it afterwards
    })
    return token


def set_challenge_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        CHALLENGE_COOKIE, token, max_age=int(CHALLENGE_LIFETIME.total_seconds()),
        httponly=True, secure=True, samesite="strict",
        path=CHALLENGE_PATH,  # sent only to the MFA routes, never usable as a session
    )


def clear_challenge_cookie(response: Response) -> None:
    response.delete_cookie(CHALLENGE_COOKIE, path=CHALLENGE_PATH, httponly=True, secure=True,
                           samesite="strict")


async def require_challenge(request: Request) -> dict:
    """Access rule for POST /api/auth/mfa/verify: a live challenge from the password step."""
    token = request.cookies.get(CHALLENGE_COOKIE)
    challenge = None
    if token and len(token) <= 128:
        challenge = await request.app.state.db.mfa_challenges.find_one(
            {"token_hash": hash_token(token)})
    if challenge is None or challenge["expires_at"] <= utcnow():
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, INVALID_CODE)
    return challenge


mark_access(require_challenge, "mfa_challenge")


async def take_attempt(db: AsyncDatabase, challenge: dict) -> bool:
    """Use up one of the challenge's attempts. False once they are all used."""
    updated = await db.mfa_challenges.find_one_and_update(
        {"_id": challenge["_id"], "attempts": {"$lt": CHALLENGE_MAX_ATTEMPTS}},
        {"$inc": {"attempts": 1}},
    )
    return updated is not None
