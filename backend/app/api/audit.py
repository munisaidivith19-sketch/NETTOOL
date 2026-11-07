"""Read-only view of the audit log, admin only."""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, StringConstraints

from app.security.rbac import require_admin

router = APIRouter(prefix="/api/audit", tags=["audit"], dependencies=[Depends(require_admin)])

ActionFilter = Annotated[str, StringConstraints(pattern=r"^[a-z_]{2,32}(\.[a-z_]{2,32})?$")]
UsernameFilter = Annotated[str, StringConstraints(pattern=r"^[a-z0-9._-]{3,32}$")]


class AuditEntry(BaseModel):
    id: str
    at: datetime
    action: str
    result: str
    actor: dict | None
    target: dict | None
    ip: str | None
    request_id: str | None
    details: dict


class AuditPage(BaseModel):
    items: list[AuditEntry]
    # Pass as `before` to get the next (older) page.
    next_before: datetime | None


@router.get("", response_model=AuditPage)
async def list_audit(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    before: datetime | None = None,
    action: ActionFilter | None = None,
    actor: UsernameFilter | None = None,
) -> AuditPage:
    # The filter is assembled from validated, typed values only (no raw user JSON).
    query: dict = {}
    if before is not None:
        query["at"] = {"$lt": before}
    if action is not None:
        # "auth" matches every auth.* action; "auth.login" matches exactly. The pattern above
        # allows only letters, "_" and one ".", so the value can't carry regex or operators.
        query["action"] = action if "." in action else {"$regex": rf"^{action}\."}
    if actor is not None:
        query["actor.username"] = actor
    cursor = request.app.state.db.audit_log.find(query).sort("at", -1).limit(limit)
    items = [
        AuditEntry(
            id=str(doc["_id"]),
            at=doc["at"],
            action=doc["action"],
            result=doc["result"],
            actor=doc.get("actor"),
            target=doc.get("target"),
            ip=doc.get("ip"),
            request_id=doc.get("request_id"),
            details=doc.get("details") or {},
        )
        async for doc in cursor
    ]
    next_before = items[-1].at if len(items) == limit else None
    return AuditPage(items=items, next_before=next_before)

