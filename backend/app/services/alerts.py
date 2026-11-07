"""Alerts with a stable key, so one problem is always one alert.

Lifecycle: a check reports which problems exist right now.
- a new key            -> a new open alert
- an open key again    -> the same alert, last_seen and details updated
- a resolved key again -> the same alert reopened (occurrences + 1)
- an open key missing  -> auto-resolved
The unique index on alerts.key makes "one alert per problem" a database guarantee.

Phase 3 checks: duplicate IPs and subnets over the usage threshold. They run after every agent
report and after IPAM changes (Render has no scheduler, so checks run on new data).
"""

import ipaddress
from datetime import datetime, timedelta

from pymongo.asynchronous.database import AsyncDatabase
from pymongo.errors import DuplicateKeyError

from app.config import Settings
from app.services import ipam
from app.services.ipaddr import key_to_ip

# Below threshold minus this, a subnet usage alert resolves. Stops flapping around 80 %.
USAGE_HYSTERESIS = 5
# Point-to-point links (/30, /31, /32, IPv6 /126+) are full by design; don't alert on them.
MIN_USABLE_FOR_USAGE_ALERT = 6


async def upsert_alert(db: AsyncDatabase, *, key: str, type_: str, severity: str, message: str,
                       target: dict, details: dict, now: datetime) -> str:
    existing = await db.alerts.find_one({"key": key}, {"status": 1})
    if existing is None:
        try:
            await db.alerts.insert_one({
                "key": key, "type": type_, "severity": severity, "status": "open",
                "message": message, "target": target, "details": details,
                "opened_at": now, "last_seen": now, "resolved_at": None, "occurrences": 1,
            })
            return "opened"
        except DuplicateKeyError:
            existing = await db.alerts.find_one({"key": key}, {"status": 1})
    update: dict = {"$set": {"message": message, "target": target, "details": details,
                             "severity": severity, "last_seen": now}}
    if existing["status"] != "open":
        # A reopened alert is a new occurrence: an old acknowledgement no longer applies.
        update["$set"] |= {"status": "open", "opened_at": now, "resolved_at": None,
                           "resolved_by": None, "acknowledged_by": None,
                           "acknowledged_at": None}
        update["$inc"] = {"occurrences": 1}
        result = "reopened"
    else:
        result = "updated"
    await db.alerts.update_one({"key": key}, update)
    return result


async def resolve_missing(db: AsyncDatabase, type_: str, active_keys: set[str],
                          now: datetime) -> int:
    result = await db.alerts.update_many(
        {"type": type_, "status": "open", "key": {"$nin": sorted(active_keys)}},
        {"$set": {"status": "resolved", "resolved_at": now, "resolved_by": None}},
    )
    return result.modified_count


async def check_duplicate_ips(db: AsyncDatabase, settings: Settings, now: datetime) -> set[str]:
    since = now - timedelta(minutes=settings.duplicate_ip_window_minutes)
    pipeline = [
        {"$match": {"last_seen": {"$gte": since}}},
        {"$group": {"_id": "$ip_key", "macs": {"$addToSet": "$mac"},
                    "devices": {"$addToSet": "$device_id"}}},
        {"$match": {"macs.1": {"$exists": True}}},  # at least two different MACs
        {"$limit": 1000},
    ]
    groups = [g async for g in await db.arp_entries.aggregate(pipeline)]
    device_ids = {d for g in groups for d in g["devices"]}
    names = {d["_id"]: d.get("sys_name") or d["mgmt_ip"]
             async for d in db.devices.find({"_id": {"$in": list(device_ids)}},
                                            {"sys_name": 1, "mgmt_ip": 1})}
    active = set()
    for group in groups:
        ip = str(key_to_ip(group["_id"]))
        macs = sorted(group["macs"])
        key = f"duplicate_ip:{group['_id']}"
        active.add(key)
        await upsert_alert(
            db, key=key, type_="duplicate_ip", severity="critical",
            message=f"IP {ip} is in use by {len(macs)} different devices "
                    f"(MAC addresses {', '.join(macs)}).",
            target={"type": "ip", "ip": ip, "ip_key": group["_id"]},
            details={"macs": macs, "seen_by": sorted(names.get(d, "unknown")
                                                     for d in group["devices"])},
            now=now,
        )
    await resolve_missing(db, "duplicate_ip", active, now)
    return active


async def check_subnet_usage(db: AsyncDatabase, settings: Settings, now: datetime) -> set[str]:
    threshold = settings.subnet_usage_alert_percent
    cutoff = ipam.stale_cutoff(now, settings.ip_stale_days)
    open_keys = {a["key"] async for a in db.alerts.find(
        {"type": "subnet_usage", "status": "open"}, {"key": 1})}
    active = set()
    async for subnet in db.subnets.find({}, {"network": 1, "name": 1}).limit(5000):
        net = ipaddress.ip_network(subnet["network"])
        if ipam.usable_count(net) < MIN_USABLE_FOR_USAGE_ALERT:
            continue
        stats = ipam.usage(net, await ipam.count_used(db, net, cutoff))
        key = f"subnet_usage:{subnet['network']}"
        percent = stats["percent"]
        if percent >= threshold or (key in open_keys and percent >= threshold - USAGE_HYSTERESIS):
            active.add(key)
            label = f"{subnet['network']}" + (f" ({subnet['name']})" if subnet.get("name") else "")
            await upsert_alert(
                db, key=key, type_="subnet_usage",
                severity="critical" if percent >= 95 else "warning",
                message=f"Subnet {label} is {percent}% full: {stats['used']} of "
                        f"{stats['usable']} usable addresses are in use.",
                target={"type": "subnet", "id": str(subnet["_id"]), "network": subnet["network"]},
                details={**stats, "threshold": threshold},
                now=now,
            )
    await resolve_missing(db, "subnet_usage", active, now)
    return active


async def run_ipam_checks(db: AsyncDatabase, settings: Settings, now: datetime) -> dict[str, int]:
    duplicates = await check_duplicate_ips(db, settings, now)
    full = await check_subnet_usage(db, settings, now)
    return {"duplicate_ip_alerts": len(duplicates), "subnet_usage_alerts": len(full)}
