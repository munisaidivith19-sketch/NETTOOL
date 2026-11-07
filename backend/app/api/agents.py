"""Agent registration and revocation, admin only (CLAUDE.md 7.3)."""

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.models.agents import AgentCreated, AgentOut, CreateAgentRequest, agent_out
from app.models.common import AgentIdPath
from app.security.agent_auth import fingerprint, new_agent_id, new_agent_key
from app.security.rbac import CurrentUser, require_admin
from app.security.sessions import utcnow
from app.services import audit

router = APIRouter(prefix="/api/agents", tags=["agents"], dependencies=[Depends(require_admin)])


@router.get("", response_model=list[AgentOut])
async def list_agents(request: Request) -> list[AgentOut]:
    cursor = request.app.state.db.agents.find({}).sort("created_at", -1).limit(200)
    return [agent_out(doc) async for doc in cursor]


@router.post("", response_model=AgentCreated, status_code=status.HTTP_201_CREATED)
async def create_agent(
    body: CreateAgentRequest, request: Request, admin: CurrentUser = Depends(require_admin)
) -> AgentCreated:
    db = request.app.state.db
    key = new_agent_key()
    doc = {
        "_id": new_agent_id(),
        "name": body.name,
        "key_ciphertext": request.app.state.vault.encrypt(key),
        "key_fingerprint": fingerprint(key),
        "created_at": utcnow(),
        "created_by": admin.username,
        "last_seen_at": None,
        "revoked_at": None,
    }
    await db.agents.insert_one(doc)
    await audit.record(db, request, action="agent.create", result="success",
                       actor=audit.user_actor(admin),
                       target={"type": "agent", "id": doc["_id"], "name": body.name},
                       details={"key_fingerprint": doc["key_fingerprint"]})
    return AgentCreated(**agent_out(doc).model_dump(), key=key)


@router.post("/{agent_id}/revoke", response_model=AgentOut)
async def revoke_agent(
    request: Request,
    agent_id: AgentIdPath,
    admin: CurrentUser = Depends(require_admin),
) -> AgentOut:
    db = request.app.state.db
    doc = await db.agents.find_one({"_id": agent_id})
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent not found")
    if doc.get("revoked_at") is None:
        now = utcnow()
        await db.agents.update_one({"_id": agent_id},
                                   {"$set": {"revoked_at": now, "revoked_by": admin.username}})
        doc["revoked_at"] = now
        await audit.record(db, request, action="agent.revoke", result="success",
                           actor=audit.user_actor(admin),
                           target={"type": "agent", "id": agent_id, "name": doc["name"]})
    return agent_out(doc)
