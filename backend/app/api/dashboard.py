"""One request for the dashboard and the top bar's alert counter (any role).

The agents list is admin-only, so only the latest check-in (name and time) is shown here.
"""

import heapq
import ipaddress

from fastapi import APIRouter, Depends, Request

from app.models.devices import AgentCheckIn, DashboardSummary, SubnetSummary
from app.security.rbac import require_user
from app.security.sessions import utcnow
from app.services import ipam
from app.services.alerts import MIN_USABLE_FOR_USAGE_ALERT

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"],
                   dependencies=[Depends(require_user)])

TOP_SUBNETS = 5
MAX_SUBNETS_SCANNED = 1000


async def _counts(collection, match: dict, field: str) -> dict[str, int]:
    pipeline = [{"$match": match}, {"$group": {"_id": f"${field}", "n": {"$sum": 1}}}]
    return {str(g["_id"]): g["n"] async for g in await collection.aggregate(pipeline)}


@router.get("/summary", response_model=DashboardSummary)
async def summary(request: Request) -> DashboardSummary:
    db = request.app.state.db
    cutoff = ipam.stale_cutoff(utcnow(), request.app.state.settings.ip_stale_days)

    by_status = await _counts(db.devices, {}, "status")
    devices = {"total": sum(by_status.values()),
               **{s: by_status.get(s, 0) for s in ("up", "snmp_error", "down")}}

    subnets = []
    async for doc in db.subnets.find({}, {"network": 1, "name": 1}).limit(MAX_SUBNETS_SCANNED):
        net = ipaddress.ip_network(doc["network"])
        if ipam.usable_count(net) < MIN_USABLE_FOR_USAGE_ALERT:  # full by design
            continue
        usage = ipam.usage(net, await ipam.count_used(db, net, cutoff))
        subnets.append(SubnetSummary(id=str(doc["_id"]), network=doc["network"],
                                     name=doc.get("name"), usage=usage))
    fullest = heapq.nlargest(TOP_SUBNETS, subnets, key=lambda s: s.usage.percent)

    open_alerts = {"status": "open"}
    by_type = await _counts(db.alerts, open_alerts, "type")
    by_severity = await _counts(db.alerts, open_alerts, "severity")

    agent = await db.agents.find_one(
        {"revoked_at": None, "last_seen_at": {"$ne": None}}, {"name": 1, "last_seen_at": 1},
        sort=[("last_seen_at", -1)])
    return DashboardSummary(
        devices=devices,
        subnets=await db.subnets.count_documents({}),
        fullest_subnets=fullest,
        alerts_open=sum(by_type.values()),
        alerts_by_severity=by_severity,
        alerts_by_type=by_type,
        duplicate_ips=by_type.get("duplicate_ip", 0),
        last_agent_check_in=AgentCheckIn(name=agent["name"], last_seen_at=agent["last_seen_at"])
        if agent else None,
    )
