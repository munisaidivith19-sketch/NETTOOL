from app.models.common import PasswordInput, Role, StrictModel, Username


class CreateUserRequest(StrictModel):
    username: Username
    # A temporary password: the new user must change it at first login.
    password: PasswordInput
    role: Role


class UpdateUserRequest(StrictModel):
    role: Role | None = None
    disabled: bool | None = None


class ResetPasswordRequest(StrictModel):
    new_password: PasswordInput
