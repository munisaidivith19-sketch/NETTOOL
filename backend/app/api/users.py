"""User management, admin only (CLAUDE.md 7.2)."""

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.models.auth import UserOut, user_out
from app.models.common import UserIdPath
from app.models.users import CreateUserRequest, ResetPasswordRequest, UpdateUserRequest
from app.security.passwords import hash_password
from app.security.rbac import CurrentUser, require_admin
from app.security.sessions import revoke_user_sessions
from app.services import audit
from app.services.users import count_active_admins, create_user, ensure_password_ok

router = APIRouter(prefix="/api/users", tags=["users"], dependencies=[Depends(require_admin)])

MAX_USERS_LISTED = 500


async def _get_user(request: Request, user_id: str) -> dict:
    doc = await request.app.state.db.users.find_one({"_id": ObjectId(user_id)})
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return doc


def _target(doc: dict) -> dict:
    return {"type": "user", "id": str(doc["_id"]), "username": doc["username"]}


@router.get("", response_model=list[UserOut])
async def list_users(request: Request) -> list[UserOut]:
    cursor = request.app.state.db.users.find({}).sort("username", 1).limit(MAX_USERS_LISTED)
    return [user_out(doc) async for doc in cursor]


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def add_user(
    body: CreateUserRequest, request: Request, admin: CurrentUser = Depends(require_admin)
) -> UserOut:
    db = request.app.state.db
    doc = await create_user(
        db,
        username=body.username,
        password=body.password,
        role=body.role,
        rounds=request.app.state.settings.bcrypt_rounds,
        created_by=admin.username,
    )
    await audit.record(db, request, action="user.create", result="success",
                       actor=audit.user_actor(admin), target=_target(doc),
                       details={"role": body.role})
    return user_out(doc)


@router.patch("/{user_id}", response_model=UserOut)
async def update_user(
    body: UpdateUserRequest,
    request: Request,
    user_id: UserIdPath,
    admin: CurrentUser = Depends(require_admin),
) -> UserOut:
    db = request.app.state.db
    doc = await _get_user(request, user_id)
    changes: dict = {}
    if body.role is not None and body.role != doc["role"]:
        changes["role"] = body.role
    if body.disabled is not None and body.disabled != bool(doc.get("disabled")):
        changes["disabled"] = body.disabled
    if not changes:
        return user_out(doc)

    if doc["_id"] == admin.id:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "You can't change your own role or disable yourself")
    removes_admin = doc["role"] == "admin" and (
        changes.get("role", "admin") != "admin" or changes.get("disabled") is True
    )
    if removes_admin and await count_active_admins(db, excluding=doc["_id"]) == 0:
        raise HTTPException(status.HTTP_409_CONFLICT, "At least one active admin must remain")

    await db.users.update_one({"_id": doc["_id"]}, {"$set": changes})
    # New permissions apply immediately: the user must sign in again.
    await revoke_user_sessions(db, doc["_id"])
    for field, value in changes.items():
        action = "user.role_change" if field == "role" else (
            "user.disable" if value else "user.enable")
        await audit.record(db, request, action=action, result="success",
                           actor=audit.user_actor(admin), target=_target(doc),
                           details={"from": doc.get(field), "to": value})
    doc.update(changes)
    return user_out(doc)


@router.post("/{user_id}/reset-password", response_model=UserOut)
async def reset_password(
    body: ResetPasswordRequest,
    request: Request,
    user_id: UserIdPath,
    admin: CurrentUser = Depends(require_admin),
) -> UserOut:
    db = request.app.state.db
    doc = await _get_user(request, user_id)
    ensure_password_ok(body.new_password, doc["username"])
    changes = {
        "password_hash": hash_password(body.new_password, request.app.state.settings.bcrypt_rounds),
        "must_change_password": True,  # nosec B105 - boolean flag
        "failed_logins": 0,
        "locked_until": None,
    }
    await db.users.update_one({"_id": doc["_id"]}, {"$set": changes})
    await revoke_user_sessions(db, doc["_id"])
    await audit.record(db, request, action="user.password_reset", result="success",
                       actor=audit.user_actor(admin), target=_target(doc))
    doc.update(changes)
    return user_out(doc)


@router.post("/{user_id}/mfa/reset", response_model=UserOut)
async def reset_mfa(
    request: Request, user_id: UserIdPath, admin: CurrentUser = Depends(require_admin)
) -> UserOut:
    """For a user who lost their phone and their recovery codes. They must set MFA up again
    (admins at their next sign-in). Not allowed on yourself: otherwise a stolen admin session
    could remove the second factor of the account it is using."""
    db = request.app.state.db
    doc = await _get_user(request, user_id)
    if doc["_id"] == admin.id:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "Ask another admin to reset your two-step sign-in")
    had = bool((doc.get("mfa") or {}).get("enabled"))
    await db.users.update_one({"_id": doc["_id"]}, {"$unset": {"mfa": ""}})
    await revoke_user_sessions(db, doc["_id"])
    await audit.record(db, request, action="user.mfa_reset", result="success",
                       actor=audit.user_actor(admin), target=_target(doc),
                       details={"was_enabled": had})
    doc.pop("mfa", None)
    return user_out(doc)
