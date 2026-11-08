"""Login, logout, current user and password change.

With two-step sign-in (Phase 8) the login route stops after the password for users who have
MFA: it hands out a short-lived challenge instead of a session, and app/api/mfa.py finishes
the sign-in once the code is right.
"""

import hmac

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from app.models.auth import (
    ChangePasswordRequest,
    LoginRequest,
    MfaChallengeOut,
    SessionOut,
    user_out,
)
from app.security import mfa, rate_limit
from app.security.passwords import dummy_hash, hash_password, verify_password
from app.security.rbac import CurrentUser, public, require_session
from app.security.sessions import (
    COOKIE_NAME,
    clear_session_cookie,
    create_session,
    revoke_session,
    revoke_user_sessions,
    set_session_cookie,
    utcnow,
)
from app.services import audit, security_events
from app.services.users import ensure_password_ok

router = APIRouter(prefix="/api/auth", tags=["auth"])

INVALID_LOGIN = "Invalid username or password"


async def ip_limit(request: Request, username: str = "") -> None:
    """429 when this address has too many recent failures (passwords or MFA codes)."""
    db = request.app.state.db
    if await rate_limit.ip_is_limited(db, audit.client_ip(request)):
        # Counted, and audited only up to a limit: a script hammering the login page can't
        # fill the audit log, and it opens a security alert.
        await security_events.failure(
            db, request, "login_limited", action="auth.login", result="denied", actor=None,
            details={"username": username[:64], "reason": "ip_rate_limited"})
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            "Too many failed sign-in attempts. Try again in a few minutes.")


async def count_user_failure(request: Request, user: dict) -> None:
    """One more failure for this account (a wrong password or a wrong MFA code)."""
    db = request.app.state.db
    if await rate_limit.record_user_failure(db, user["_id"]):
        minutes = int(rate_limit.LOCK_DURATION.total_seconds() // 60)
        await audit.record(db, request, action="auth.lockout", result="success",
                           actor=user_actor(user), details={"minutes": minutes})
        await security_events.open_alert(
            request, key=f"security:lockout:{user['_id']}",
            message=f"Account {user['username']} was locked for {minutes} minutes after "
                    f"{rate_limit.LOCK_AFTER_FAILURES} failed sign-in attempts.",
            target={"type": "user", "id": str(user["_id"]), "username": user["username"]},
            details={"ip": audit.client_ip(request), "minutes": minutes})


def user_actor(user: dict) -> dict:
    return {"type": "user", "id": str(user["_id"]), "username": user["username"]}


async def start_session(request: Request, response: Response, user: dict,
                        mfa_method: str | None = None) -> SessionOut:
    """The sign-in succeeded: create the session and set its cookie."""
    db = request.app.state.db
    await rate_limit.reset_user_failures(db, user["_id"])
    await db.users.update_one({"_id": user["_id"]}, {"$set": {"last_login_at": utcnow()}})
    # A session id presented before login is thrown away (session fixation defence).
    await revoke_session(db, request.cookies.get(COOKIE_NAME))
    token, session = await create_session(db, user["_id"], audit.client_ip(request),
                                          request.headers.get("user-agent"), mfa=mfa_method)
    set_session_cookie(response, token)
    await audit.record(db, request, action="auth.login", result="success",
                       actor=user_actor(user), details={"mfa": mfa_method} if mfa_method else {})
    return SessionOut(user=user_out(user), csrf_token=session["csrf_token"])


@router.post("/login", response_model=SessionOut | MfaChallengeOut,
             dependencies=[Depends(public)])
async def login(body: LoginRequest, request: Request,
                response: Response) -> SessionOut | MfaChallengeOut:
    db = request.app.state.db
    settings = request.app.state.settings
    ip = audit.client_ip(request)
    username = body.username.strip().lower()

    await ip_limit(request, username)

    user = await db.users.find_one({"username": username})
    # Always run bcrypt once, even for unknown users, so response time doesn't reveal which
    # usernames exist.
    password_ok = verify_password(
        body.password, user["password_hash"] if user else dummy_hash(settings.bcrypt_rounds)
    )

    reason = None
    if user is None:
        reason = "unknown_user"
    elif user.get("disabled"):
        reason = "disabled"
    elif rate_limit.is_locked(user):
        reason = "locked"
    elif not password_ok:
        reason = "bad_password"

    if reason:
        await rate_limit.record_ip_failure(db, ip)
        if reason == "bad_password":
            await count_user_failure(request, user)
        await audit.record(db, request, action="auth.login", result="failure",
                           actor=user_actor(user) if user else None,
                           details={"username": username[:64], "reason": reason})
        # One message for every case: the attacker can't tell which check failed.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, INVALID_LOGIN)

    if (user.get("mfa") or {}).get("enabled"):
        # The password is right, but there is no session yet: the code step comes next. The
        # failure counter is reset only when the whole sign-in succeeds.
        token = await mfa.create_challenge(db, user["_id"], ip)
        mfa.set_challenge_cookie(response, token)
        await audit.record(db, request, action="auth.mfa_challenge", result="success",
                           actor=user_actor(user))
        return MfaChallengeOut()
    return await start_session(request, response, user)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request, response: Response, user: CurrentUser = Depends(require_session)
) -> Response:
    db = request.app.state.db
    await revoke_session(db, request.cookies.get(COOKIE_NAME))
    await audit.record(db, request, action="auth.logout", result="success",
                       actor=audit.user_actor(user))
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    clear_session_cookie(response)
    return response


@router.get("/me", response_model=SessionOut)
async def me(request: Request, user: CurrentUser = Depends(require_session)) -> SessionOut:
    doc = await request.app.state.db.users.find_one({"_id": user.id})
    return SessionOut(user=user_out(doc), csrf_token=user.csrf_token)


@router.post("/change-password", response_model=SessionOut)
async def change_password(
    body: ChangePasswordRequest,
    request: Request,
    response: Response,
    user: CurrentUser = Depends(require_session),
) -> SessionOut:
    db = request.app.state.db
    settings = request.app.state.settings
    doc = await db.users.find_one({"_id": user.id})
    if not verify_password(body.current_password, doc["password_hash"]):
        # Counts toward the lockout like a failed sign-in: otherwise someone holding a stolen
        # session could guess the password here without limit.
        await count_user_failure(request, doc)
        await audit.record(db, request, action="auth.password_change", result="failure",
                           actor=audit.user_actor(user), details={"reason": "bad_current"})
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")
    if hmac.compare_digest(body.current_password.encode(), body.new_password.encode()):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            {"field": "new_password",
                             "problems": ["Choose a password different from the current one."]})
    ensure_password_ok(body.new_password, user.username)

    await db.users.update_one(
        {"_id": user.id},
        {"$set": {
            "password_hash": hash_password(body.new_password, settings.bcrypt_rounds),
            "must_change_password": False,  # nosec B105 - boolean flag
            "password_changed_at": utcnow(),
        }},
    )
    # Sign out every other device and give this one a fresh session id.
    await revoke_user_sessions(db, user.id)
    token, session = await create_session(db, user.id, audit.client_ip(request),
                                          request.headers.get("user-agent"),
                                          mfa=user.session.get("mfa"))
    set_session_cookie(response, token)
    await audit.record(db, request, action="auth.password_change", result="success",
                       actor=audit.user_actor(user))
    doc = await db.users.find_one({"_id": user.id})
    return SessionOut(user=user_out(doc), csrf_token=session["csrf_token"])
