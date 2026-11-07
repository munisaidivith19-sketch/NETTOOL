"""Config backups, versions, diffs and compliance (user routes).

- Every role sees the overview: last backup, compliance score, unconfigured flag.
- Config text - even masked - is for engineers and admins only: it still describes the
  network's defences in detail.
"""

from typing import Annotated

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status

from app.models.common import ObjectIdPath
from app.security.rbac import CurrentUser, require_role, require_user
from app.security.sessions import utcnow
from app.services import audit
from app.services.configs import diff_rows

router = APIRouter(tags=["configs"])
require_engineer = require_role("admin", "engineer")
VersionPath = Annotated[int, Path(ge=1, le=10_000_000)]
MAX_DEVICES = 2000


def _summary(device: dict) -> dict:
    backup = device.get("config_backup") or {}
    report = device.get("compliance") or {}
    unconfigured = device.get("unconfigured") or {}
    return {
        "id": str(device["_id"]), "sys_name": device.get("sys_name"),
        "mgmt_ip": device["mgmt_ip"], "vendor": device.get("vendor"),
        "status": device.get("status"), "config_vendor": device.get("config_vendor"),
        "backup": {k: backup.get(k) for k in ("status", "error", "checked_at", "changed_at",
                                               "version", "source")},
        "backup_requested": device.get("backup_requested_at") is not None,
        "compliance": {k: report.get(k) for k in ("score", "previous_score", "checked_at",
                                                  "version", "rules_checked")}
        | {"findings": len(report.get("findings") or [])} if report else None,
        "unconfigured": {"flag": bool(unconfigured.get("flag")),
                         "reasons": unconfigured.get("reasons") or []},
    }


async def _device(request: Request, device_id: str) -> dict:
    device = await request.app.state.db.devices.find_one({"_id": ObjectId(device_id)})
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")
    return device


@router.get("/api/configs", dependencies=[Depends(require_user)])
async def overview(request: Request) -> list[dict]:
    cursor = request.app.state.db.devices.find(
        {}, {"sys_name": 1, "mgmt_ip": 1, "vendor": 1, "status": 1, "config_vendor": 1,
             "config_backup": 1, "backup_requested_at": 1, "compliance": 1, "unconfigured": 1},
    ).sort([("sys_name", 1), ("mgmt_ip_key", 1)]).limit(MAX_DEVICES)
    return [_summary(d) async for d in cursor]


@router.get("/api/devices/{device_id}/compliance", dependencies=[Depends(require_user)])
async def device_compliance(request: Request, device_id: ObjectIdPath) -> dict:
    device = await _device(request, device_id)
    return _summary(device) | {"report": device.get("compliance")}


@router.get("/api/devices/{device_id}/configs", dependencies=[Depends(require_engineer)])
async def list_versions(request: Request, device_id: ObjectIdPath) -> list[dict]:
    cursor = request.app.state.db.configs.find(
        {"device_id": ObjectId(device_id)},
        {"version": 1, "taken_at": 1, "source": 1, "size": 1, "lines": 1, "change_id": 1},
    ).sort("version", -1).limit(100)
    return [{"version": c["version"], "taken_at": c["taken_at"], "source": c["source"],
             "size": c["size"], "lines": c["lines"],
             "change_id": str(c["change_id"]) if c.get("change_id") else None}
            async for c in cursor]


@router.get("/api/devices/{device_id}/configs/diff", dependencies=[Depends(require_engineer)])
async def diff(
    request: Request, device_id: ObjectIdPath,
    from_: int = Query(..., alias="from", ge=1, le=10_000_000),
    to: int = Query(..., ge=1, le=10_000_000),
    context: int = Query(3, ge=0, le=50),
) -> dict:
    db = request.app.state.db
    docs = {c["version"]: c async for c in db.configs.find(
        {"device_id": ObjectId(device_id), "version": {"$in": [from_, to]}},
        {"version": 1, "text": 1, "taken_at": 1})}
    if from_ not in docs or to not in docs:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Version not found")
    rows = diff_rows(docs[from_]["text"], docs[to]["text"], context)
    changed = sum(1 for r in rows if r["kind"] in ("added", "removed", "changed"))
    return {"from": {"version": from_, "taken_at": docs[from_]["taken_at"]},
            "to": {"version": to, "taken_at": docs[to]["taken_at"]},
            "changed_lines": changed, "rows": rows}


@router.get("/api/devices/{device_id}/configs/{version}",
            dependencies=[Depends(require_engineer)])
async def get_version(request: Request, device_id: ObjectIdPath, version: VersionPath) -> dict:
    doc = await request.app.state.db.configs.find_one(
        {"device_id": ObjectId(device_id), "version": version})
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Version not found")
    return {"version": doc["version"], "taken_at": doc["taken_at"], "source": doc["source"],
            "vendor": doc["vendor"], "text": doc["text"],
            "change_id": str(doc["change_id"]) if doc.get("change_id") else None}


@router.post("/api/devices/{device_id}/configs/backup-now", status_code=status.HTTP_202_ACCEPTED)
async def backup_now(request: Request, device_id: ObjectIdPath,
                     user: CurrentUser = Depends(require_engineer)) -> dict:
    db = request.app.state.db
    device = await _device(request, device_id)
    await db.devices.update_one({"_id": device["_id"]},
                                {"$set": {"backup_requested_at": utcnow()}})
    await audit.record(db, request, action="config.backup_request", result="success",
                       actor=audit.user_actor(user),
                       target={"type": "device", "id": device_id, "mgmt_ip": device["mgmt_ip"]})
    # The agent checks for requests every JOB_POLL_INTERVAL_SECONDS (default one minute).
    return {"status": "requested"}
