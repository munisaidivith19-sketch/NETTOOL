"""Alerts: list (any role), acknowledge and resolve (engineer or admin).

Alerts are created and auto-resolved by services/alerts.py. A person can acknowledge one
("I'm on it", it stays open) or resolve it by hand. If the problem is still there, the next
check reopens the same alert, so resolving can't hide a real problem.
"""

from typing import Literal

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.models.common import ObjectIdPath
from app.models.ipam import AlertOut
from app.security.rbac import CurrentUser, require_role, require_user
from app.security.sessions import utcnow
from app.services import audit

router = APIRouter(prefix="/api/alerts", tags=["alerts"], dependencies=[Depends(require_user)])
require_engineer = require_role("admin", "engineer")

AlertType = Literal["duplicate_ip", "subnet_usage", "device_down", "interface_down",
                    "new_mac", "traffic_anomaly", "compliance", "config_changed", "change_failed",
                    "security"]


def alert_out(doc: dict) -> AlertOut:
    return AlertOut(id=str(doc["_id"]),
                    **{k: doc.get(k) for k in AlertOut.model_fields if k != "id"})


@router.get("", response_model=list[AlertOut])
async def list_alerts(
    request: Request,
    status: Literal["open", "resolved", "all"] = "open",
    type: AlertType | None = None,  # noqa: A002 - matches the query parameter name
    limit: int = Query(100, ge=1, le=500),
) -> list[AlertOut]:
    query: dict = {}
    if status != "all":
        query["status"] = status
    if type is not None:
        query["type"] = type
    cursor = request.app.state.db.alerts.find(query).sort("last_seen", -1).limit(limit)
    return [alert_out(d) async for d in cursor]


async def _act(request: Request, alert_id: str, user: CurrentUser, action: str,
               changes: dict) -> AlertOut:
    db = request.app.state.db
    # Only open alerts can be acknowledged or resolved; the filter makes that atomic.
    doc = await db.alerts.find_one_and_update(
        {"_id": ObjectId(alert_id), "status": "open"}, {"$set": changes},
        return_document=True)
    if doc is None:
        exists = await db.alerts.count_documents({"_id": ObjectId(alert_id)}, limit=1)
        if not exists:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
        raise HTTPException(status.HTTP_409_CONFLICT, "Alert is already resolved")
    await audit.record(db, request, action=action, result="success",
                       actor=audit.user_actor(user),
                       target={"type": "alert", "id": alert_id, "key": doc["key"]},
                       details={"alert_type": doc["type"]})
    return alert_out(doc)


@router.post("/{alert_id}/acknowledge", response_model=AlertOut)
async def acknowledge(
    request: Request, alert_id: ObjectIdPath, user: CurrentUser = Depends(require_engineer)
) -> AlertOut:
    return await _act(request, alert_id, user, "alert.acknowledge",
                      {"acknowledged_by": user.username, "acknowledged_at": utcnow()})


@router.post("/{alert_id}/resolve", response_model=AlertOut)
async def resolve(
    request: Request, alert_id: ObjectIdPath, user: CurrentUser = Depends(require_engineer)
) -> AlertOut:
    now = utcnow()
    alert = await _act(request, alert_id, user, "alert.resolve",
                       {"status": "resolved", "resolved_at": now, "resolved_by": user.username})
    if alert.type == "new_mac" and alert.target.get("mac"):
        # Resolving a new-device alert means "I know this device": record who approved it.
        await request.app.state.db.mac_addresses.update_one(
            {"mac": alert.target["mac"]},
            {"$set": {"known_by": user.username, "known_at": now}})
    return alert
