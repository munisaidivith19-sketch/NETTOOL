"""Read-only alert list (any role). Alerts are created and resolved by services/alerts.py."""

from typing import Literal

from fastapi import APIRouter, Depends, Query, Request

from app.models.ipam import AlertOut
from app.security.rbac import require_user

router = APIRouter(prefix="/api/alerts", tags=["alerts"], dependencies=[Depends(require_user)])

AlertType = Literal["duplicate_ip", "subnet_usage", "device_down", "interface_down",
                    "new_mac", "anomaly", "compliance"]


@router.get("", response_model=list[AlertOut])
async def list_alerts(
    request: Request,
    status: Literal["open", "resolved"] | None = "open",
    type: AlertType | None = None,  # noqa: A002 - matches the query parameter name
    limit: int = Query(100, ge=1, le=500),
) -> list[AlertOut]:
    query: dict = {}
    if status is not None:
        query["status"] = status
    if type is not None:
        query["type"] = type
    cursor = request.app.state.db.alerts.find(query).sort("last_seen", -1).limit(limit)
    return [AlertOut(id=str(d["_id"]), **{k: d.get(k) for k in AlertOut.model_fields
                                          if k != "id"}) async for d in cursor]
