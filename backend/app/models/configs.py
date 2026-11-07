"""Request models for config backups (from agents) and change requests (from users)."""

from typing import Annotated, Literal

from pydantic import Field, StringConstraints, model_validator

from app.models.common import StrictModel

Vendor = Literal["cisco_ios", "mikrotik_routeros"]
ObjectIdStr = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{24}$")]
Sha256Hex = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
# Short, fixed codes from the agent (connection.py / push.py): never free text from a device.
ErrorCode = Annotated[str, StringConstraints(pattern=r"^[a-z_]{2,40}$")]
MAX_CONFIG_CHARS = 1_000_000
MAX_COMMANDS_CHARS = 20_000


class ConfigFacts(StrictModel):
    snmp_default_community: bool = False


class ConfigUpload(StrictModel):
    """One backup result. `text` is present only when the fingerprint changed."""

    device_id: ObjectIdStr
    source: Literal["scheduled", "manual", "post_change"]
    change_id: ObjectIdStr | None = None
    vendor: Vendor | None = None
    hash: Sha256Hex | None = None
    facts: ConfigFacts = Field(default_factory=ConfigFacts)
    text: Annotated[str, StringConstraints(max_length=MAX_CONFIG_CHARS)] | None = None
    error: ErrorCode | None = None

    @model_validator(mode="after")
    def complete(self) -> "ConfigUpload":
        if self.error is None and (self.vendor is None or self.hash is None):
            raise ValueError("vendor and hash are required unless error is set")
        return self


class JobStatus(StrictModel):
    status: Literal["verifying", "done", "rolled_back", "failed"]
    error: ErrorCode | None = None
    before_hash: Sha256Hex | None = None
    after_hash: Sha256Hex | None = None
    log: Annotated[str, StringConstraints(max_length=10_000)] | None = None


TemplateId = Annotated[str, StringConstraints(pattern=r"^[a-z_]{2,40}/[a-z_]{2,40}$")]
Commands = Annotated[str, StringConstraints(min_length=1, max_length=MAX_COMMANDS_CHARS)]
Title = Annotated[str, StringConstraints(min_length=3, max_length=120,
                                         pattern=r"^[^\x00-\x1f\x7f<>]+$")]
Note = Annotated[str, StringConstraints(max_length=500, pattern=r"^[^\x00-\x08\x0b-\x1f\x7f]*$")]


class ChangeSource(StrictModel):
    """Either a template with variables, or raw commands typed by an engineer."""

    device_id: ObjectIdStr
    template: TemplateId | None = None
    # Values are validated by the template's own model (app/config_mgmt/templates.py).
    variables: dict[Annotated[str, StringConstraints(pattern=r"^[a-z_]{1,40}$")],
                    str | int | bool | list[str] | None] = Field(default_factory=dict,
                                                                 max_length=40)
    commands: Commands | None = None

    @model_validator(mode="after")
    def one_source(self) -> "ChangeSource":
        if (self.template is None) == (self.commands is None):
            raise ValueError("give either a template or commands, not both")
        if self.commands is not None and self.variables:
            raise ValueError("variables are only used with a template")
        return self


class ChangeCreate(ChangeSource):
    title: Title


class ApproveBody(StrictModel):
    comment: Note | None = None
    # Only for an admin approving their own change (four-eyes override): why it can't wait.
    override_reason: Annotated[str, StringConstraints(min_length=10, max_length=500,
                                                      pattern=r"^[^\x00-\x1f\x7f]+$")] | None = None


class RejectBody(StrictModel):
    reason: Annotated[str, StringConstraints(min_length=3, max_length=500,
                                             pattern=r"^[^\x00-\x1f\x7f]+$")]
