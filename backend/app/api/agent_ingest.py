"""Routes called by agents, authenticated by HMAC signature only (never by session cookie).

Phase 1 has only the heartbeat; Phase 2 adds /report and /known-devices.
"""

from fastapi import APIRouter, Depends, Request

from app.models.agents import HeartbeatRequest
from app.security.agent_auth import CurrentAgent, require_agent
from app.security.sessions import utcnow
from app.services import audit

router = APIRouter(prefix="/api/agent", tags=["agent"], dependencies=[Depends(require_agent)])


@router.post("/heartbeat")
async def heartbeat(
    body: HeartbeatRequest, request: Request, agent: CurrentAgent = Depends(require_agent)
) -> dict:
    now = utcnow()
    await request.app.state.db.agents.update_one(
        {"_id": agent.id},
        {"$set": {"last_seen_at": now, "last_seen_ip": audit.client_ip(request),
                  "agent_version": body.agent_version}},
    )
    return {"status": "ok", "server_time": now.isoformat()}
