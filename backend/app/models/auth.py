from datetime import datetime

from pydantic import BaseModel, Field

from app.models.common import PasswordInput, Role, StrictModel


class LoginRequest(StrictModel):
    # Deliberately loose (no username pattern): every bad login gets the same 401 answer.
    username: str = Field(min_length=1, max_length=64)
    password: PasswordInput


class ChangePasswordRequest(StrictModel):
    current_password: PasswordInput
    new_password: PasswordInput


class UserOut(BaseModel):
    id: str
    username: str
    role: Role
    disabled: bool = False
    must_change_password: bool = False
    created_at: datetime | None = None
    last_login_at: datetime | None = None


class SessionOut(BaseModel):
    user: UserOut
    # Kept in memory by the frontend and sent back as X-CSRF-Token. Never put it in localStorage.
    csrf_token: str


def user_out(doc: dict) -> UserOut:
    return UserOut(
        id=str(doc["_id"]),
        username=doc["username"],
        role=doc["role"],
        disabled=bool(doc.get("disabled")),
        must_change_password=bool(doc.get("must_change_password")),
        created_at=doc.get("created_at"),
        last_login_at=doc.get("last_login_at"),
    )
