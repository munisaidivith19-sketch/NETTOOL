"""Login, logout, current user and password change."""

import hmac

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from app.models.auth import ChangePasswordRequest, LoginRequest, SessionOut, user_out
from app.security import rate_limit
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
from app.services import audit
from app.services.users import ensure_password_ok

router = APIRouter(prefix="/api/auth", tags=["auth"])

INVALID_LOGIN = "Invalid username or password"


@router.post("/login", response_model=SessionOut, dependencies=[Depends(public)])
async def login(body: LoginRequest, request: Request, response: Response) -> SessionOut:
    db = request.app.state.db
    settings = request.app.state.settings
    ip = audit.client_ip(request)
    username = body.username.strip().lower()

    if await rate_limit.ip_is_limited(db, ip):
        await audit.record(db, request, action="auth.login", result="denied",
                           details={"username": username[:64], "reason": "ip_rate_limited"})
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            "Too many failed sign-in attempts. Try again in a few minutes.")

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
        actor = {"type": "user", "id": str(user["_id"]), "username": username} if user else None
        if reason == "bad_password" and await rate_limit.record_user_failure(db, user["_id"]):
            await audit.record(db, request, action="auth.lockout", result="success", actor=actor,
                               details={"minutes": int(rate_limit.LOCK_DURATION.seconds / 60)})
        await audit.record(db, request, action="auth.login", result="failure", actor=actor,
                           details={"username": username[:64], "reason": reason})
        # One message for every case: the attacker can't tell which check failed.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, INVALID_LOGIN)

    await rate_limit.reset_user_failures(db, user["_id"])
    await db.users.update_one({"_id": user["_id"]}, {"$set": {"last_login_at": utcnow()}})
    # A session id presented before login is thrown away (session fixation defence).
    await revoke_session(db, request.cookies.get(COOKIE_NAME))
    token, session = await create_session(db, user["_id"], ip, request.headers.get("user-agent"))
    set_session_cookie(response, token)
    await audit.record(db, request, action="auth.login", result="success",
                       actor={"type": "user", "id": str(user["_id"]), "username": username})
    return SessionOut(user=user_out(user), csrf_token=session["csrf_token"])


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
                                          request.headers.get("user-agent"))
    set_session_cookie(response, token)
    await audit.record(db, request, action="auth.password_change", result="success",
                       actor=audit.user_actor(user))
    doc = await db.users.find_one({"_id": user.id})
    return SessionOut(user=user_out(doc), csrf_token=session["csrf_token"])
