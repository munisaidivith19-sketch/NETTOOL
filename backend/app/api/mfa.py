"""Two-step sign-in (TOTP) routes, Phase 8. See app/security/mfa.py for how it works.

- POST /api/auth/mfa/verify          the code step of sign-in (needs the challenge cookie)
- GET  /api/auth/mfa                 my MFA status
- POST /api/auth/mfa/setup           start setup: a new secret and its QR code
- POST /api/auth/mfa/enable          finish setup with a code → 10 recovery codes, shown once
- POST /api/auth/mfa/recovery-codes  replace my recovery codes (needs a current code)
- POST /api/auth/mfa/disable         turn MFA off (needs password + code; not for admins)
Setup works with an ordinary session, because an admin without MFA must be able to reach it.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from app.api.auth import count_user_failure, ip_limit, start_session, user_actor
from app.models.auth import (
    MfaCodeRequest,
    MfaDisableRequest,
    MfaEnabledOut,
    MfaSetupOut,
    MfaStatusOut,
    MfaVerifyRequest,
    RecoveryCodesOut,
    SessionOut,
    user_out,
)
from app.security import mfa, rate_limit
from app.security.passwords import verify_password
from app.security.rbac import CurrentUser, require_session, require_user
from app.security.sessions import create_session, revoke_user_sessions, set_session_cookie, utcnow
from app.services import audit

router = APIRouter(prefix="/api/auth/mfa", tags=["auth"])


def _vault(request: Request):
    return request.app.state.mfa_vault


@router.post("/verify", response_model=SessionOut)
async def verify(body: MfaVerifyRequest, request: Request, response: Response,
                 challenge: dict = Depends(mfa.require_challenge)) -> SessionOut:
    db = request.app.state.db
    await ip_limit(request)
    user = await db.users.find_one({"_id": challenge["user_id"]})

    async def fail(reason: str, *, count: bool = True) -> HTTPException:
        await rate_limit.record_ip_failure(db, audit.client_ip(request))
        if count and user is not None:
            await count_user_failure(request, user)
        await audit.record(db, request, action="auth.mfa_failure", result="failure",
                           actor=user_actor(user) if user else None, details={"reason": reason})
        # Same answer for every reason, like the password step.
        return HTTPException(status.HTTP_401_UNAUTHORIZED, mfa.INVALID_CODE)

    if not await mfa.take_attempt(db, challenge):
        await db.mfa_challenges.delete_one({"_id": challenge["_id"]})
        raise await fail("too_many_attempts", count=False)
    if user is None or user.get("disabled") or not (user.get("mfa") or {}).get("enabled"):
        raise await fail("user_unavailable", count=False)
    if rate_limit.is_locked(user):
        raise await fail("locked", count=False)

    left = None
    if body.code is not None:
        secret = _vault(request).decrypt(user["mfa"]["secret_ct"])
        step = mfa.matching_step(secret, body.code, utcnow())
        if step is None:
            raise await fail("bad_code")
        if not await mfa.use_step(db, user["_id"], step):
            raise await fail("code_reused")
        method = "totp"
    else:
        left = await mfa.use_recovery_code(db, user["_id"], body.recovery_code)
        if left is None:
            raise await fail("bad_recovery_code")
        method = "recovery_code"
        await audit.record(db, request, action="auth.mfa_recovery_used", result="success",
                           actor=user_actor(user), details={"left": left})

    await db.mfa_challenges.delete_one({"_id": challenge["_id"]})
    mfa.clear_challenge_cookie(response)
    session = await start_session(request, response, user, mfa_method=method)
    session.recovery_codes_left = left
    return session


@router.get("", response_model=MfaStatusOut, dependencies=[Depends(require_session)])
async def mfa_status(request: Request) -> MfaStatusOut:
    doc = await request.app.state.db.users.find_one({"_id": request.state.user.id})
    return MfaStatusOut(**mfa.user_status(doc))


@router.post("/setup", response_model=MfaSetupOut)
async def setup(request: Request, user: CurrentUser = Depends(require_session)) -> MfaSetupOut:
    if user.must_change_password:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "password_change_required")
    db = request.app.state.db
    doc = await db.users.find_one({"_id": user.id})
    if (doc.get("mfa") or {}).get("enabled"):
        raise HTTPException(status.HTTP_409_CONFLICT, "Two-step sign-in is already on")
    secret = mfa.new_secret()
    await db.users.update_one({"_id": user.id}, {"$set": {
        "mfa.pending_ct": _vault(request).encrypt(secret), "mfa.pending_at": utcnow()}})
    uri = mfa.provisioning_uri(secret, user.username)
    return MfaSetupOut(secret=secret, otpauth_uri=uri, qr=mfa.qr_rows(uri),
                       expires_in_seconds=int(mfa.SETUP_LIFETIME.total_seconds()))


@router.post("/enable", response_model=MfaEnabledOut)
async def enable(body: MfaCodeRequest, request: Request, response: Response,
                 user: CurrentUser = Depends(require_session)) -> MfaEnabledOut:
    if user.must_change_password:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "password_change_required")
    db = request.app.state.db
    doc = await db.users.find_one({"_id": user.id})
    state = doc.get("mfa") or {}
    if state.get("enabled"):
        raise HTTPException(status.HTTP_409_CONFLICT, "Two-step sign-in is already on")
    if not state.get("pending_ct") or state["pending_at"] + mfa.SETUP_LIFETIME <= utcnow():
        raise HTTPException(status.HTTP_409_CONFLICT, "Setup expired. Start again.")
    step = mfa.matching_step(_vault(request).decrypt(state["pending_ct"]), body.code, utcnow())
    if step is None:
        await audit.record(db, request, action="auth.mfa_enable", result="failure",
                           actor=audit.user_actor(user), details={"reason": "bad_code"})
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "That code didn't match. Check that your phone's clock is right "
                            "and enter the newest code.")
    codes = mfa.new_recovery_codes()
    await db.users.update_one({"_id": user.id}, {"$set": {"mfa": {
        "enabled": True, "secret_ct": state["pending_ct"], "last_step": step,
        "recovery": [mfa.hash_recovery_code(c) for c in codes], "enabled_at": utcnow()}}})
    # Other sessions were signed in without the second step: end them, and rotate this one.
    await revoke_user_sessions(db, user.id)
    token, session = await create_session(db, user.id, audit.client_ip(request),
                                          request.headers.get("user-agent"), mfa="totp")
    set_session_cookie(response, token)
    await audit.record(db, request, action="auth.mfa_enable", result="success",
                       actor=audit.user_actor(user))
    doc = await db.users.find_one({"_id": user.id})
    return MfaEnabledOut(recovery_codes=codes,
                         session=SessionOut(user=user_out(doc),
                                            csrf_token=session["csrf_token"]))


async def _check_current_code(request: Request, user: CurrentUser, code: str) -> dict:
    """For changes to MFA itself: a fresh code from the app, with the same lockout as sign-in,
    so a stolen session alone can't guess its way to new recovery codes."""
    db = request.app.state.db
    doc = await db.users.find_one({"_id": user.id})
    if not (doc.get("mfa") or {}).get("enabled"):
        raise HTTPException(status.HTTP_409_CONFLICT, "Two-step sign-in is off")
    if rate_limit.is_locked(doc):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            "Too many wrong codes. Try again later.")
    step = mfa.matching_step(_vault(request).decrypt(doc["mfa"]["secret_ct"]), code, utcnow())
    if step is None or not await mfa.use_step(db, user.id, step):
        await count_user_failure(request, doc)
        await audit.record(db, request, action="auth.mfa_failure", result="failure",
                           actor=audit.user_actor(user),
                           details={"reason": "bad_code", "path": request.url.path})
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Wrong or already used code")
    return doc


@router.post("/recovery-codes", response_model=RecoveryCodesOut)
async def new_recovery_codes(body: MfaCodeRequest, request: Request,
                             user: CurrentUser = Depends(require_user)) -> RecoveryCodesOut:
    await _check_current_code(request, user, body.code)
    codes = mfa.new_recovery_codes()
    await request.app.state.db.users.update_one(
        {"_id": user.id}, {"$set": {"mfa.recovery": [mfa.hash_recovery_code(c) for c in codes]}})
    await audit.record(request.app.state.db, request, action="auth.mfa_recovery_regenerate",
                       result="success", actor=audit.user_actor(user))
    return RecoveryCodesOut(recovery_codes=codes)


@router.post("/disable", status_code=status.HTTP_204_NO_CONTENT)
async def disable(body: MfaDisableRequest, request: Request,
                  user: CurrentUser = Depends(require_user)) -> Response:
    db = request.app.state.db
    if user.role == "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Two-step sign-in is required for admins")
    doc = await db.users.find_one({"_id": user.id})
    if not verify_password(body.password, doc["password_hash"]):
        await count_user_failure(request, doc)
        await audit.record(db, request, action="auth.mfa_disable", result="failure",
                           actor=audit.user_actor(user), details={"reason": "bad_password"})
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Password is incorrect")
    await _check_current_code(request, user, body.code)
    await db.users.update_one({"_id": user.id}, {"$unset": {"mfa": ""}})
    await audit.record(db, request, action="auth.mfa_disable", result="success",
                       actor=audit.user_actor(user))
    return Response(status_code=status.HTTP_204_NO_CONTENT)
