from typing import Annotated, Literal

from fastapi import Path
from pydantic import BaseModel, ConfigDict, StringConstraints


class StrictModel(BaseModel):
    """Base for every request body: unknown fields are an error (CLAUDE.md 7.4).

    Typed fields are also the NoSQL-injection defence: a field declared as `str` can never
    arrive as an object like {"$ne": null}, so it can't change the meaning of a query.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


Role = Literal["admin", "engineer", "viewer"]
Username = Annotated[str, StringConstraints(pattern=r"^[a-z0-9._-]{3,32}$")]
# Long enough for any real password; the policy check gives the precise limit and message.
PasswordInput = Annotated[str, StringConstraints(min_length=1, max_length=256)]
# Path parameters carry their pattern inside Path(): FastAPI ignores StringConstraints on an
# Annotated alias when a separate `= Path()` default is given, which once let unvalidated ids
# through (caught by tests/test_users.py::test_bad_user_id_rejected).
UserIdPath = Annotated[str, Path(pattern=r"^[a-f0-9]{24}$")]
AgentIdPath = Annotated[str, Path(pattern=r"^agt_[a-f0-9]{16}$")]
ObjectIdPath = Annotated[str, Path(pattern=r"^[a-f0-9]{24}$")]
# Characters of an IPv4 or IPv6 address only; ipaddress does the real check afterwards.
IpPath = Annotated[str, Path(pattern=r"^[0-9A-Fa-f.:]{2,45}$")]
