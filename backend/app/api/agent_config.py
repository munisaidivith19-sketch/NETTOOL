"""Agent routes for config backups and approved change jobs (HMAC-signed requests only).

An agent can only touch devices it reported itself (devices.agent_id) and only change
requests for those devices.
"""

from bson import ObjectId
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pymongo import ReturnDocument

from app.models.common import ObjectIdPath
from app.models.configs import ConfigUpload, JobStatus
from app.models.report import MAX_DEVICES
from app.security.agent_auth import CurrentAgent, require_agent
from app.security.sessions import utcnow
from app.services import audit, changes, configs, notify

router = APIRouter(prefix="/api/agent", tags=["agent"], dependencies=[Depends(require_agent)])


def _agent_actor(agent: CurrentAgent) -> dict:
    return {"type": "agent", "id": agent.id, "name": agent.name}


@router.get("/backup-targets")
async def backup_targets(request: Request, agent: CurrentAgent = Depends(require_agent)) -> dict:
    """Devices to back up, with the fingerprint of the last stored version."""
    cursor = request.app.state.db.devices.find(
        {"agent_id": agent.id},
        {"mgmt_ip": 1, "config_backup.hash": 1, "backup_requested_at": 1},
    ).sort("mgmt_ip_key", 1).limit(MAX_DEVICES)
    return {"devices": [
        {"device_id": str(d["_id"]), "mgmt_ip": d["mgmt_ip"],
         "last_hash": (d.get("config_backup") or {}).get("hash"),
         "requested": d.get("backup_requested_at") is not None}
        async for d in cursor]}


@router.post("/configs")
async def upload_config(body: ConfigUpload, request: Request, background: BackgroundTasks,
                        agent: CurrentAgent = Depends(require_agent)) -> dict:
    db = request.app.state.db
    device = await db.devices.find_one({"_id": ObjectId(body.device_id), "agent_id": agent.id})
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown device")
    if body.change_id is not None and await db.change_requests.count_documents(
            {"_id": ObjectId(body.change_id), "device_id": device["_id"]}) == 0:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Unknown change request")
    now = utcnow()
    summary = await configs.ingest_upload(db, device, body, now)
    if body.change_id is not None and summary.get("version"):
        await db.change_requests.update_one({"_id": ObjectId(body.change_id)},
                                            {"$set": {"after_version": summary["version"]}})
    background.add_task(notify.dispatch_pending, db, request.app.state.settings)
    if summary.get("stored") or body.error:
        await audit.record(db, request, action="config.backup",
                           result="failure" if body.error else "success",
                           actor=_agent_actor(agent),
                           target={"type": "device", "id": body.device_id,
                                   "mgmt_ip": device["mgmt_ip"]},
                           details={"source": body.source, "error": body.error,
                                    "version": summary.get("version"), "hash": body.hash})
    return {"status": "ok", **summary}


@router.post("/jobs/claim")
async def claim_job(request: Request, agent: CurrentAgent = Depends(require_agent)) -> dict:
    """Hand the oldest approved, unexpired change for this agent's devices to the agent."""
    db = request.app.state.db
    now = utcnow()
    await changes.expire_and_time_out(db, agent.id, now)
    doc = await db.change_requests.find_one_and_update(
        {"agent_id": agent.id, "status": "approved", "expires_at": {"$gt": now}},
        {"$set": {"status": "pushing", "claimed_at": now, "updated_at": now},
         "$push": {"timeline": changes.timeline_entry(
             "pushing", now, {"id": agent.id, "username": f"agent {agent.name}"})}},
        sort=[("approved_at", 1)], return_document=ReturnDocument.AFTER,
    )
    if doc is None:
        return {"job": None}
    await audit.record(db, request, action="change.push_start", result="success",
                       actor=_agent_actor(agent),
                       target={"type": "change", "id": str(doc["_id"]),
                               "mgmt_ip": doc["mgmt_ip"]})
    # Exactly the fields the backend signed at approval (agent checks the signature).
    return {"job": doc["job"]}


@router.post("/jobs/{change_id}/status")
async def job_status(change_id: ObjectIdPath, body: JobStatus, request: Request,
                     background: BackgroundTasks,
                     agent: CurrentAgent = Depends(require_agent)) -> dict:
    db = request.app.state.db
    now = utcnow()
    by = {"id": agent.id, "username": f"agent {agent.name}"}
    if body.status == "verifying":
        updated = await changes.transition(db, ObjectId(change_id), ("pushing",), "verifying",
                                           now, by, match={"agent_id": agent.id})
    else:
        # The agent reports a final result; keep only the agent's masked, capped log.
        result = body.model_dump()
        updated = await db.change_requests.find_one_and_update(
            {"_id": ObjectId(change_id), "agent_id": agent.id,
             "status": {"$in": ["pushing", "verifying"]}},
            {"$set": {"status": body.status, "result": result, "finished_at": now,
                      "updated_at": now, "job": None},
             "$push": {"timeline": changes.timeline_entry(body.status, now, by, body.error)}},
            return_document=ReturnDocument.AFTER)
    if updated is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "This change is not being pushed by you")
    if body.status in ("rolled_back", "failed"):
        await changes.change_failed_alert(db, updated, now)
        background.add_task(notify.dispatch_pending, db, request.app.state.settings)
    if body.status != "verifying":
        await audit.record(
            db, request, action="change.push", result="success" if body.status == "done"
            else "failure", actor=_agent_actor(agent),
            target={"type": "change", "id": change_id, "mgmt_ip": updated["mgmt_ip"]},
            details={"status": body.status, "error": body.error,
                     "before_hash": body.before_hash, "after_hash": body.after_hash})
    return {"status": "ok"}
