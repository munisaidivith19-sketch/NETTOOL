"""Routes called by agents, authenticated by HMAC signature only (never by session cookie).

The report body is large (up to 10 MB, see LARGE_BODY_PATHS) and fully untrusted; it is
validated by app/models/report.py before anything touches the database.
"""

from fastapi import APIRouter, Depends, Request

from app.models.agents import HeartbeatRequest
from app.models.report import MAX_DEVICES, DiscoveryReport, KnownDevice
from app.security.agent_auth import CurrentAgent, require_agent
from app.security.sessions import utcnow
from app.services import audit
from app.services.ingest import ingest_report

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


@router.post("/report")
async def report(
    body: DiscoveryReport, request: Request, agent: CurrentAgent = Depends(require_agent)
) -> dict:
    db = request.app.state.db
    now = utcnow()
    summary = await ingest_report(db, agent.id, body, now)
    await db.agents.update_one(
        {"_id": agent.id},
        {"$set": {"last_seen_at": now, "last_seen_ip": audit.client_ip(request),
                  "last_report_at": now, "agent_version": body.agent_version}},
    )
    # Counts only: the audit log records that a report arrived, not the network's contents.
    await audit.record(db, request, action="agent.report", result="success",
                       actor={"type": "agent", "id": agent.id, "name": agent.name},
                       details=summary)
    return {"status": "ok", "summary": summary}


@router.get("/known-devices")
async def known_devices(
    request: Request, agent: CurrentAgent = Depends(require_agent)
) -> dict:
    cursor = request.app.state.db.devices.find(
        {"agent_id": agent.id}, {"_id": 0, "mgmt_ip": 1, "snmp_port": 1, "status": 1}
    ).sort("mgmt_ip_key", 1).limit(MAX_DEVICES)
    devices = [KnownDevice(mgmt_ip=d["mgmt_ip"], snmp_port=d.get("snmp_port", 161),
                           status=d.get("status", "unknown")) async for d in cursor]
    return {"devices": [d.model_dump() for d in devices]}
