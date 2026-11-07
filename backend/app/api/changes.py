"""Change requests and templates (CLAUDE.md 7.5). The flow is in services/changes.py.

Roles: everyone can read; engineers and admins create, submit and approve; an approver can
never approve their own change, except an admin who gives a written reason (audit-logged).
"""

from typing import Literal

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.config_mgmt import templates
from app.models.common import ObjectIdPath
from app.models.configs import ApproveBody, ChangeCreate, ChangeSource, RejectBody
from app.security.rbac import CurrentUser, require_role, require_user
from app.security.sessions import utcnow
from app.services import audit, changes
from app.services.changes import ChangeError
from app.services.configs import latest_version

router = APIRouter(tags=["changes"])
require_engineer = require_role("admin", "engineer")
STATUSES = Literal["draft", "pending_approval", "approved", "rejected", "pushing", "verifying",
                   "done", "rolled_back", "failed", "cancelled", "expired"]


def _error(exc: ChangeError) -> JSONResponse:
    return JSONResponse({"detail": str(exc), "violations": exc.violations},
                        status_code=exc.status_code)


def _out(doc: dict) -> dict:
    def who(value: dict | None) -> dict | None:
        return {"id": value.get("id"), "username": value.get("username")} if value else None

    result = doc.get("result") or {}
    return {
        "id": str(doc["_id"]), "title": doc["title"], "status": doc["status"],
        "device_id": str(doc["device_id"]), "device_name": doc.get("device_name"),
        "mgmt_ip": doc["mgmt_ip"], "vendor": doc["vendor"], "source": doc["source"],
        "commands": doc["commands"], "violations": doc.get("violations", []),
        "protected_interfaces": doc.get("protected_interfaces", []),
        "before_version": doc.get("before_version"),
        "created_by": who(doc.get("created_by")), "created_at": doc["created_at"],
        "updated_at": doc.get("updated_at"), "approved_by": who(doc.get("approved_by")),
        "override_reason": doc.get("override_reason"), "expires_at": doc.get("expires_at"),
        "result": {k: result.get(k) for k in ("status", "error", "before_hash", "after_hash",
                                              "log")} if result else None,
        "after_version": doc.get("after_version"),
        "timeline": [{"at": t["at"], "status": t["status"], "by": who(t.get("by")),
                      "note": t.get("note")} for t in doc.get("timeline", [])],
    }


async def _render(request: Request, body: ChangeSource) -> tuple[dict, dict, str, dict]:
    """Device, its vendor, the rendered commands and the safety check result."""
    db = request.app.state.db
    device = await db.devices.find_one({"_id": ObjectId(body.device_id)})
    if device is None:
        raise ChangeError(404, "Device not found")
    vendor = device.get("config_vendor")
    if vendor is None:
        raise ChangeError(409, "NetMap has no config backup of this device yet, so it can't "
                               "be changed safely. Add SSH credentials on the agent first.")
    if body.template is not None:
        template = templates.TEMPLATES.get(body.template)
        if template is None or template.vendor != vendor:
            raise ChangeError(422, f"Template not available for {vendor} devices")
        try:
            commands, _ = templates.render(body.template, body.variables,
                                           request.app.state.settings.templates_path)
        except ValidationError as exc:
            raise ChangeError(422, "Template variables are not valid", [
                {"line": 0, "text": ".".join(map(str, e["loc"])), "reason": e["msg"]}
                for e in exc.errors()]) from None
        except templates.TemplateError as exc:
            raise ChangeError(422, str(exc)) from None
        source = {"kind": "template", "template": body.template, "variables": body.variables}
    else:
        commands = "\n".join(line.rstrip() for line in body.commands.strip("\n").splitlines()) \
            + "\n"
        source = {"kind": "raw"}
    checked = await changes.check(db, device, vendor, commands)
    return device, source | {"vendor": vendor}, commands, checked


def _refuse_secrets(commands: str, vendor: str) -> None:
    """Never store a change that contains a password: refuse it instead of saving a draft."""
    found = changes.secret_lines(commands, vendor)
    if found:
        raise ChangeError(422, "Secrets can't be part of a change request",
                          [v.as_dict() for v in found])


async def _load(request: Request, change_id: str) -> dict:
    doc = await request.app.state.db.change_requests.find_one({"_id": ObjectId(change_id)})
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Change request not found")
    return doc


def _actor(user: CurrentUser) -> dict:
    return {"id": str(user.id), "username": user.username}


def _target(doc: dict) -> dict:
    return {"type": "change", "id": str(doc["_id"]), "device_id": str(doc["device_id"]),
            "mgmt_ip": doc["mgmt_ip"]}


@router.get("/api/templates", dependencies=[Depends(require_user)])
async def list_templates() -> list[dict]:
    return templates.catalogue()


@router.post("/api/changes/preview", dependencies=[Depends(require_engineer)])
async def preview(body: ChangeSource, request: Request):
    """Dry run: render and check, store nothing."""
    try:
        device, source, commands, checked = await _render(request, body)
    except ChangeError as exc:
        return _error(exc)
    return {"commands": commands, "vendor": source["vendor"],
            "device_name": device.get("sys_name"), **checked}


@router.post("/api/changes", status_code=status.HTTP_201_CREATED)
async def create(body: ChangeCreate, request: Request,
                 user: CurrentUser = Depends(require_engineer)):
    db = request.app.state.db
    try:
        device, source, commands, checked = await _render(request, body)
        _refuse_secrets(commands, source["vendor"])
    except ChangeError as exc:
        return _error(exc)
    now = utcnow()
    doc = {
        "title": body.title, "status": "draft", "device_id": device["_id"],
        "device_name": device.get("sys_name"), "mgmt_ip": device["mgmt_ip"],
        "agent_id": device.get("agent_id"), "vendor": source.pop("vendor"), "source": source,
        "commands": commands, **checked, "created_by": _actor(user), "created_at": now,
        "updated_at": now, "timeline": [changes.timeline_entry("draft", now, _actor(user))],
    }
    doc["_id"] = (await db.change_requests.insert_one(doc)).inserted_id
    await audit.record(db, request, action="change.create", result="success",
                       actor=audit.user_actor(user), target=_target(doc),
                       details={"source": source.get("kind"), "lines": commands.count("\n"),
                                "violations": len(checked["violations"])})
    return _out(doc)


@router.put("/api/changes/{change_id}")
async def update(change_id: ObjectIdPath, body: ChangeCreate, request: Request,
                 user: CurrentUser = Depends(require_engineer)):
    """Edit a draft or rejected change. It goes back to draft and needs a new approval."""
    db = request.app.state.db
    doc = await _load(request, change_id)
    if doc["created_by"]["id"] != str(user.id) and user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only the creator can edit this change")
    if str(doc["device_id"]) != body.device_id:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "The device can't be changed")
    try:
        _, source, commands, checked = await _render(request, body)
        _refuse_secrets(commands, source["vendor"])
    except ChangeError as exc:
        return _error(exc)
    now = utcnow()
    updated = await changes.transition(
        db, doc["_id"], changes.EDITABLE, "draft", now, _actor(user), "Edited",
        extra={"title": body.title,
               "source": {k: v for k, v in source.items() if k != "vendor"},
               "commands": commands, **checked})
    if updated is None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "Only draft or rejected changes can be edited")
    await audit.record(db, request, action="change.update", result="success",
                       actor=audit.user_actor(user), target=_target(doc))
    return _out(updated)


@router.post("/api/changes/{change_id}/submit")
async def submit(change_id: ObjectIdPath, request: Request,
                 user: CurrentUser = Depends(require_engineer)):
    db = request.app.state.db
    doc = await _load(request, change_id)
    if doc["created_by"]["id"] != str(user.id) and user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only the creator can submit this change")
    device = await db.devices.find_one({"_id": doc["device_id"]})
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")
    checked = await changes.check(db, device, doc["vendor"], doc["commands"])
    if checked["violations"]:
        await audit.record(db, request, action="change.submit", result="denied",
                           actor=audit.user_actor(user), target=_target(doc),
                           details={"violations": len(checked["violations"])})
        return _error(ChangeError(422, "The change contains blocked commands",
                                  checked["violations"]))
    latest = await latest_version(db, doc["device_id"])
    if latest is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "No config backup of this device yet")
    updated = await changes.transition(
        db, doc["_id"], ("draft",), "pending_approval", utcnow(), _actor(user),
        extra={"before_hash": latest["hash"], "before_version": latest["version"], **checked})
    if updated is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Only a draft can be submitted")
    await audit.record(db, request, action="change.submit", result="success",
                       actor=audit.user_actor(user), target=_target(doc),
                       details={"before_version": latest["version"]})
    return _out(updated)


@router.post("/api/changes/{change_id}/approve")
async def approve(change_id: ObjectIdPath, body: ApproveBody, request: Request,
                  user: CurrentUser = Depends(require_engineer)):
    db = request.app.state.db
    doc = await _load(request, change_id)
    own = doc["created_by"]["id"] == str(user.id)
    if own and not (user.role == "admin" and body.override_reason):
        # Four-eyes rule: nobody approves their own change.
        await audit.record(db, request, action="change.approve", result="denied",
                           actor=audit.user_actor(user), target=_target(doc),
                           details={"reason": "four_eyes"})
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "You can't approve your own change: another engineer must review it")
    if doc["status"] != "pending_approval":
        raise HTTPException(status.HTTP_409_CONFLICT, "Only a change waiting for approval can "
                                                      "be approved")
    device = await db.devices.find_one({"_id": doc["device_id"]})
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")
    try:
        checked = await changes.check(db, device, doc["vendor"], doc["commands"])
        if checked["violations"]:
            raise ChangeError(422, "The change contains blocked commands", checked["violations"])
        await changes.ensure_current_backup(db, doc)
        now = utcnow()
        job = await changes.build_job(db, request.app.state.vault, doc, device,
                                      checked["protected_interfaces"], now)
    except ChangeError as exc:
        await audit.record(db, request, action="change.approve", result="failure",
                           actor=audit.user_actor(user), target=_target(doc),
                           details={"reason": str(exc)[:200]})
        return _error(exc)
    updated = await changes.transition(
        db, doc["_id"], ("pending_approval",), "approved", now, _actor(user), body.comment,
        extra={"approved_by": _actor(user), "approved_at": now, "job": job,
               "expires_at": now + changes.JOB_LIFETIME,
               "override_reason": body.override_reason if own else None, **checked})
    if updated is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "The change was modified meanwhile")
    await audit.record(db, request, action="change.approve_override" if own else "change.approve",
                       result="success", actor=audit.user_actor(user), target=_target(doc),
                       details={"before_hash": doc["before_hash"],
                                "commands_sha256": job["commands_sha256"],
                                **({"override_reason": body.override_reason} if own else {})})
    return _out(updated)


@router.post("/api/changes/{change_id}/reject")
async def reject(change_id: ObjectIdPath, body: RejectBody, request: Request,
                 user: CurrentUser = Depends(require_engineer)):
    db = request.app.state.db
    doc = await _load(request, change_id)
    updated = await changes.transition(db, doc["_id"], ("pending_approval",), "rejected",
                                       utcnow(), _actor(user), body.reason)
    if updated is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Only a change waiting for approval can "
                                                      "be rejected")
    await audit.record(db, request, action="change.reject", result="success",
                       actor=audit.user_actor(user), target=_target(doc))
    return _out(updated)


@router.post("/api/changes/{change_id}/cancel")
async def cancel(change_id: ObjectIdPath, request: Request,
                 user: CurrentUser = Depends(require_engineer)):
    db = request.app.state.db
    doc = await _load(request, change_id)
    if doc["created_by"]["id"] != str(user.id) and user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only the creator or an admin can cancel")
    updated = await changes.transition(db, doc["_id"], changes.CANCELLABLE, "cancelled",
                                       utcnow(), _actor(user), extra={"job": None})
    if updated is None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "This change can no longer be cancelled (the agent has it)")
    await audit.record(db, request, action="change.cancel", result="success",
                       actor=audit.user_actor(user), target=_target(doc))
    return _out(updated)


@router.get("/api/changes", dependencies=[Depends(require_user)])
async def list_changes(
    request: Request,
    status_: STATUSES | None = Query(None, alias="status"),
    device_id: str | None = Query(None, pattern=r"^[a-f0-9]{24}$"),
    limit: int = Query(100, ge=1, le=500),
) -> list[dict]:
    query: dict = {}
    if status_ is not None:
        query["status"] = status_
    if device_id is not None:
        query["device_id"] = ObjectId(device_id)
    cursor = request.app.state.db.change_requests.find(query, {"job": 0}).sort(
        "created_at", -1).limit(limit)
    return [_out(doc) async for doc in cursor]


@router.get("/api/changes/{change_id}", dependencies=[Depends(require_user)])
async def get_change(change_id: ObjectIdPath, request: Request) -> dict:
    return _out(await _load(request, change_id))
