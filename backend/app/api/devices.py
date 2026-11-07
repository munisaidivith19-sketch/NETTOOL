"""Devices: searchable list and a detail view with interfaces and addresses (any role).

Devices are created only by agent reports (services/ingest.py); the UI can't add or edit them.
"""

import re
from datetime import timedelta
from typing import Annotated, Literal

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.api.subnets import ip_rows
from app.models.common import ObjectIdPath
from app.models.devices import DeviceDetail, DeviceOut, InterfaceOut, LinkOut, MetricPoint
from app.security.rbac import require_user
from app.security.sessions import utcnow
from app.services import ipam
from app.services.ipaddr import network_key_range

router = APIRouter(prefix="/api/devices", tags=["devices"], dependencies=[Depends(require_user)])

MAX_ADDRESSES = 500
MAX_LINKS = 500
# 7 days of 5-minute samples (the metrics TTL) is 2016 points.
MAX_POINTS = 2100
# Same allowlist as /api/ips/search: no quotes, braces, "$" or regex characters.
SearchText = Annotated[str, Query(min_length=1, max_length=100,
                                  pattern=r"^[A-Za-z0-9.:_\- /]+$")]


def _out(doc: dict, model=DeviceOut, **extra):
    fields = {k: doc.get(k) for k in model.model_fields if k not in ("id", *extra)}
    fields["snmp_v2c"] = bool(doc.get("snmp_v2c"))
    return model(id=str(doc["_id"]), **fields, **extra)


@router.get("", response_model=list[DeviceOut])
async def list_devices(
    request: Request,
    q: SearchText | None = None,
    status_: Literal["up", "snmp_error", "down"] | None = Query(None, alias="status"),
    limit: int = Query(200, ge=1, le=1000),
) -> list[DeviceOut]:
    query: dict = {}
    if status_ is not None:
        query["status"] = status_
    if q is not None:
        # The filter is built from the parsed value, never from the raw text.
        kind, value = ipam.classify_query(q)
        if kind == "ip":
            query["mgmt_ip"] = str(value)
        elif kind == "network":
            start_key, end_key = network_key_range(value)
            query["mgmt_ip_key"] = {"$gte": start_key, "$lte": end_key}
        else:
            pattern = {"$regex": re.escape(q.strip()), "$options": "i"}
            query["$or"] = [{"sys_name": pattern}, {"sys_location": pattern},
                            {"vendor": pattern}]
    cursor = request.app.state.db.devices.find(query).sort(
        [("sys_name", 1), ("mgmt_ip_key", 1)]).limit(limit)
    return [_out(doc) async for doc in cursor]


@router.get("/{device_id}", response_model=DeviceDetail)
async def get_device(request: Request, device_id: ObjectIdPath) -> DeviceDetail:
    db = request.app.state.db
    doc = await db.devices.find_one({"_id": ObjectId(device_id)})
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")
    interfaces = [InterfaceOut(**{k: i.get(k) for k in InterfaceOut.model_fields})
                  async for i in db.interfaces.find({"device_id": doc["_id"]}).sort("if_index", 1)]
    addresses = [a async for a in db.ip_addresses.find({"device_id": doc["_id"]})
                 .sort("ip_key", 1).limit(MAX_ADDRESSES)]
    links = [LinkOut(**{k: link.get(k) for k in LinkOut.model_fields if k != "remote_device_id"},
                     remote_device_id=str(link["remote_device_id"])
                     if link.get("remote_device_id") else None)
             async for link in db.links.find({"device_id": doc["_id"]})
             .sort([("if_index", 1), ("protocol", 1)]).limit(MAX_LINKS)]
    return _out(doc, DeviceDetail, interfaces=interfaces,
                addresses=await ip_rows(request, addresses), links=links)


@router.get("/{device_id}/metrics", response_model=list[MetricPoint])
async def device_metrics(
    request: Request,
    device_id: ObjectIdPath,
    if_index: int = Query(ge=1, le=2**31 - 1),
    hours: int = Query(24, ge=1, le=7 * 24),
) -> list[MetricPoint]:
    """Traffic history of one interface (kept for uplinks and IP interfaces, 7 days)."""
    db = request.app.state.db
    if await db.devices.find_one({"_id": ObjectId(device_id)}, {"_id": 1}) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")
    since = utcnow() - timedelta(hours=hours)
    cursor = db.metrics.find(
        {"device_id": ObjectId(device_id), "if_index": if_index, "ts": {"$gte": since}},
        {"_id": 0, "ts": 1, "in_bps": 1, "out_bps": 1, "in_errors": 1, "out_errors": 1},
    ).sort("ts", -1).limit(MAX_POINTS)
    points = [MetricPoint(**m) async for m in cursor]
    return points[::-1]  # oldest first, for charts
