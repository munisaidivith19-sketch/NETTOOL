from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, StringConstraints

from app.models.common import StrictModel

AgentName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9 ._-]{1,64}$")]


class CreateAgentRequest(StrictModel):
    name: AgentName


class AgentOut(BaseModel):
    id: str
    name: str
    key_fingerprint: str
    created_at: datetime
    created_by: str
    last_seen_at: datetime | None = None
    revoked_at: datetime | None = None


class AgentCreated(AgentOut):
    # Returned exactly once, when the agent is created. The server can't show it again.
    key: str


AgentVersion = Annotated[str, StringConstraints(pattern=r"^[0-9A-Za-z.+-]{1,32}$")]


class HeartbeatRequest(StrictModel):
    agent_version: AgentVersion | None = None


def agent_out(doc: dict) -> AgentOut:
    return AgentOut(
        id=doc["_id"],
        name=doc["name"],
        key_fingerprint=doc["key_fingerprint"],
        created_at=doc["created_at"],
        created_by=doc["created_by"],
        last_seen_at=doc.get("last_seen_at"),
        revoked_at=doc.get("revoked_at"),
    )
