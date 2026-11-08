from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, Field, StringConstraints, model_validator

from app.models.common import PasswordInput, Role, StrictModel
from app.security.rbac import mfa_setup_required

MfaCode = Annotated[str, StringConstraints(pattern=r"^[0-9]{6}$")]
# XXXXX-XXXXX; lower case, spaces and a missing dash are accepted and normalised.
RecoveryCodeInput = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9 -]{10,14}$")]


class LoginRequest(StrictModel):
    # Deliberately loose (no username pattern): every bad login gets the same 401 answer.
    username: str = Field(min_length=1, max_length=64)
    password: PasswordInput


class ChangePasswordRequest(StrictModel):
    current_password: PasswordInput
    new_password: PasswordInput


class MfaVerifyRequest(StrictModel):
    """The second sign-in step: a code from the app, or one recovery code."""
    code: MfaCode | None = None
    recovery_code: RecoveryCodeInput | None = None

    @model_validator(mode="after")
    def exactly_one(self) -> "MfaVerifyRequest":
        if (self.code is None) == (self.recovery_code is None):
            raise ValueError("Send either code or recovery_code")
        return self


class MfaCodeRequest(StrictModel):
    code: MfaCode


class MfaDisableRequest(StrictModel):
    password: PasswordInput
    code: MfaCode


class UserOut(BaseModel):
    id: str
    username: str
    role: Role
    disabled: bool = False
    must_change_password: bool = False
    mfa_enabled: bool = False
    # An admin without two-step sign-in can only reach the MFA setup screen.
    mfa_setup_required: bool = False
    created_at: datetime | None = None
    last_login_at: datetime | None = None


class SessionOut(BaseModel):
    user: UserOut
    # Kept in memory by the frontend and sent back as X-CSRF-Token. Never put it in localStorage.
    csrf_token: str
    # Set when the sign-in used a recovery code, so the UI can warn when few are left.
    recovery_codes_left: int | None = None


class MfaChallengeOut(BaseModel):
    """Password accepted; the code step comes next. No session exists yet."""
    mfa_required: Literal[True] = True


class MfaStatusOut(BaseModel):
    enabled: bool
    required: bool
    recovery_codes_left: int


class MfaSetupOut(BaseModel):
    secret: str
    otpauth_uri: str
    qr: list[str]  # rows of "0"/"1"
    expires_in_seconds: int


class MfaEnabledOut(BaseModel):
    recovery_codes: list[str]
    session: SessionOut


class RecoveryCodesOut(BaseModel):
    recovery_codes: list[str]


def user_out(doc: dict) -> UserOut:
    return UserOut(
        id=str(doc["_id"]),
        username=doc["username"],
        role=doc["role"],
        disabled=bool(doc.get("disabled")),
        must_change_password=bool(doc.get("must_change_password")),
        mfa_enabled=bool((doc.get("mfa") or {}).get("enabled")),
        mfa_setup_required=mfa_setup_required(doc),
        created_at=doc.get("created_at"),
        last_login_at=doc.get("last_login_at"),
    )
