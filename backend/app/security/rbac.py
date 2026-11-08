"""Authentication and role checks for user routes (CLAUDE.md 7.2).

Every /api route must declare exactly how it is protected, through one of:
  require_role(...)         a logged-in user with one of these roles
  require_user              any logged-in user (all three roles)
  require_session           any logged-in user, even one who must still change their password
                            or set up two-step sign-in
  require_agent             a signed agent request (app/security/agent_auth.py)
  require_challenge         the half-finished sign-in of the MFA code step (app/security/mfa.py)
  public                    deliberately open (only login)
tests/test_rbac.py fails if any /api route has none of them: that is "deny by default".
"""

from dataclasses import dataclass, field
from typing import Any

from fastapi import Depends, HTTPException, Request, status

from app.security import csrf
from app.security.sessions import COOKIE_NAME, load_session, revoke_user_sessions
from app.services import audit

ROLES = ("admin", "engineer", "viewer")
ACCESS_MARKER = "__netmap_access__"


@dataclass
class CurrentUser:
    id: Any
    username: str
    role: str
    must_change_password: bool
    session: dict = field(repr=False)
    # Admins must use two-step sign-in (CLAUDE.md 7.1); until they set it up, only the
    # require_session routes (me, logout, change password, MFA setup) work.
    mfa_setup_required: bool = False

    @property
    def csrf_token(self) -> str:
        return self.session["csrf_token"]


def mark_access(dependency, label: str):
    setattr(dependency, ACCESS_MARKER, label)
    return dependency


def mfa_setup_required(user: dict) -> bool:
    return user.get("role") == "admin" and not (user.get("mfa") or {}).get("enabled")


def _unauthorized() -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, "Not signed in or session expired")


async def _authenticate(request: Request) -> CurrentUser:
    db = request.app.state.db
    session = await load_session(db, request.cookies.get(COOKIE_NAME))
    if session is None:
        raise _unauthorized()
    user = await db.users.find_one({"_id": session["user_id"]})
    if user is None or user.get("disabled"):
        await revoke_user_sessions(db, session["user_id"])
        raise _unauthorized()
    current = CurrentUser(
        id=user["_id"],
        username=user["username"],
        role=user["role"],
        must_change_password=bool(user.get("must_change_password")),
        session=session,
        mfa_setup_required=mfa_setup_required(user),
    )
    request.state.user = current
    # CSRF is checked for every state-changing request made with the session cookie.
    csrf.check_token(request, current.csrf_token)
    return current


async def require_session(user: CurrentUser = Depends(_authenticate)) -> CurrentUser:
    return user


mark_access(require_session, "session")


def require_role(*roles: str):
    unknown = set(roles) - set(ROLES)
    if unknown or not roles:
        raise ValueError(f"Unknown roles: {unknown}")

    async def dependency(
        request: Request, user: CurrentUser = Depends(_authenticate)
    ) -> CurrentUser:
        if user.must_change_password:
            await audit.record(
                request.app.state.db,
                request,
                action="auth.password_change_required",
                result="denied",
                actor=audit.user_actor(user),
                details={"path": request.url.path},
            )
            raise HTTPException(status.HTTP_403_FORBIDDEN, "password_change_required")
        if user.mfa_setup_required:
            # Checked on every request, so a user promoted to admin is stopped at once.
            await audit.record(
                request.app.state.db,
                request,
                action="auth.mfa_setup_required",
                result="denied",
                actor=audit.user_actor(user),
                details={"path": request.url.path},
            )
            raise HTTPException(status.HTTP_403_FORBIDDEN, "mfa_setup_required")
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "You don't have permission to do this")
        return user

    return mark_access(dependency, "roles:" + ",".join(roles))


require_user = require_role(*ROLES)
require_admin = require_role("admin")


async def public() -> None:
    """Marker for routes that are deliberately reachable without logging in."""


mark_access(public, "public")
