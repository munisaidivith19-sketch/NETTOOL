"""Forecasts and device types (Phase 7).

- GET  /api/predictions                     any role: latest forecasts, without the series
- GET  /api/subnets/{id}/forecast           any role: usage history + exhaustion forecast
- GET  /api/devices/{id}/forecast           any role: traffic history + bandwidth forecast
- PUT  /api/macs/{mac}/classification       engineer/admin: correct an endpoint's type
- DELETE /api/macs/{mac}/classification     engineer/admin: back to the automatic type
A correction always wins: the agent's next run never overwrites a manual type.
"""

import ipaddress
from datetime import timedelta, timezone
from typing import Annotated, Literal

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status

from app.models.ai import TypeCorrection
from app.models.common import ObjectIdPath
from app.security.rbac import CurrentUser, require_role, require_user
from app.security.sessions import utcnow
from app.services import audit, ipam

router = APIRouter(tags=["predictions"])
require_engineer = require_role("admin", "engineer")
MacPath = Annotated[str, Path(pattern=r"^[0-9A-Fa-f:.-]{12,17}$")]
SUMMARY_FIELDS = {"series": 0, "_id": 0, "agent_id": 0}
HISTORY_DAYS = 90
TRAFFIC_HOURS = 72


def _out(doc: dict) -> dict:
    out = {k: v for k, v in doc.items() if k not in ("_id", "agent_id")}
    for key in ("subnet_id", "device_id"):
        if isinstance(out.get(key), ObjectId):
            out[key] = str(out[key])
    return out


@router.get("/api/predictions", dependencies=[Depends(require_user)])
async def list_predictions(
    request: Request,
    kind: Literal["subnet_exhaustion", "uplink_bandwidth"] | None = None,
    limit: int = Query(200, ge=1, le=1000),
) -> list[dict]:
    query = {"kind": kind} if kind else {}
    cursor = request.app.state.db.predictions.find(query, SUMMARY_FIELDS).sort(
        [("kind", 1), ("days_until_full", 1), ("label", 1)]).limit(limit)
    rows = [_out(d) async for d in cursor]
    # Soonest-to-fill first; "never" (None) last.
    rows.sort(key=lambda r: (r["kind"], r.get("days_until_full") is None,
                             r.get("days_until_full") or 0, -(r.get("percent") or 0)))
    return rows


@router.get("/api/subnets/{subnet_id}/forecast", dependencies=[Depends(require_user)])
async def subnet_forecast(request: Request, subnet_id: ObjectIdPath) -> dict:
    db = request.app.state.db
    subnet = await db.subnets.find_one({"_id": ObjectId(subnet_id)}, {"network": 1})
    if subnet is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Subnet not found")
    usable = ipam.usable_count(ipaddress.ip_network(subnet["network"]))
    since = (utcnow() - timedelta(days=HISTORY_DAYS)).date().isoformat()
    history = [{"day": h["day"], "used": h["used"]} async for h in db.subnet_usage.find(
        {"subnet_id": subnet["_id"], "day": {"$gte": since}}, {"day": 1, "used": 1})
        .sort("day", 1).limit(HISTORY_DAYS + 1)]
    prediction = await db.predictions.find_one(
        {"kind": "subnet_exhaustion", "target_key": subnet_id})
    return {"usable": str(usable), "history": history,
            "prediction": _out(prediction) if prediction else None}


@router.get("/api/devices/{device_id}/forecast", dependencies=[Depends(require_user)])
async def device_forecast(request: Request, device_id: ObjectIdPath,
                          if_index: int | None = Query(None, ge=0, le=2**31 - 1)) -> dict:
    """Bandwidth forecasts for a device's interfaces; with if_index, also hourly history."""
    db = request.app.state.db
    oid = ObjectId(device_id)
    if await db.devices.find_one({"_id": oid}, {"_id": 1}) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")
    query: dict = {"kind": "uplink_bandwidth", "device_id": oid}
    if if_index is not None:
        query["if_index"] = if_index
    forecasts = [_out(d) async for d in db.predictions.find(
        query, None if if_index is not None else SUMMARY_FIELDS).sort("if_index", 1).limit(100)]
    history = []
    if if_index is not None:
        since = utcnow() - timedelta(hours=TRAFFIC_HOURS)
        buckets: dict = {}
        async for m in db.metrics.find(
                {"device_id": oid, "if_index": if_index, "ts": {"$gte": since}},
                {"ts": 1, "in_bps": 1, "out_bps": 1}).sort("ts", 1).limit(TRAFFIC_HOURS * 12 + 50):
            ts = m["ts"] if m["ts"].tzinfo else m["ts"].replace(tzinfo=timezone.utc)
            hour = ts.replace(minute=0, second=0, microsecond=0)
            buckets.setdefault(hour, []).append(max(m.get("in_bps") or 0, m.get("out_bps") or 0))
        history = [{"ts": h.isoformat(), "bps": round(sum(v) / len(v))}
                   for h, v in sorted(buckets.items())]
    return {"forecasts": forecasts, "history": history}


def _mac(value: str) -> str:
    mac = ipam.normalize_mac(value)
    if mac is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Not a valid MAC address")
    return mac


@router.put("/api/macs/{mac}/classification")
async def correct_type(request: Request, mac: MacPath, body: TypeCorrection,
                       user: CurrentUser = Depends(require_engineer)) -> dict:
    db = request.app.state.db
    mac = _mac(mac)
    before = await db.mac_addresses.find_one({"mac": mac}, {"classification": 1})
    if before is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "MAC address not seen on the network")
    value = {"type": body.type, "confidence": 1.0,
             "reasons": [f"Set by {user.username}"], "source": "manual",
             "by": user.username, "at": utcnow()}
    await db.mac_addresses.update_one({"mac": mac}, {"$set": {"classification": value}})
    await audit.record(db, request, action="endpoint.classify", result="success",
                       actor=audit.user_actor(user), target={"type": "mac", "mac": mac},
                       details={"before": (before.get("classification") or {}).get("type"),
                                "after": body.type})
    return {"mac": mac, "classification": value}


@router.delete("/api/macs/{mac}/classification", status_code=status.HTTP_204_NO_CONTENT)
async def reset_type(request: Request, mac: MacPath,
                     user: CurrentUser = Depends(require_engineer)) -> None:
    db = request.app.state.db
    mac = _mac(mac)
    result = await db.mac_addresses.update_one(
        {"mac": mac, "classification.source": "manual"}, {"$unset": {"classification": ""}})
    if result.matched_count == 0:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No manual type set for this MAC")
    await audit.record(db, request, action="endpoint.classify_reset", result="success",
                       actor=audit.user_actor(user), target={"type": "mac", "mac": mac})
