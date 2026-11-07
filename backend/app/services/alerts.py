"""Alerts with a stable key, so one problem is always one alert.

Lifecycle: a check reports which problems exist right now.
- a new key            -> a new open alert
- an open key again    -> the same alert, last_seen and details updated
- a resolved key again -> the same alert reopened (occurrences + 1)
- an open key missing  -> auto-resolved
The unique index on alerts.key makes "one alert per problem" a database guarantee.

Phase 3 checks: duplicate IPs and subnets over the usage threshold. They run after every agent
report and after IPAM changes (Render has no scheduler, so checks run on new data).
Phase 5 checks (after every agent report): devices down, uplinks down, new unknown MACs.

An alert that is opened or reopened gets notify_pending=True; services/notify.py sends it.
"""

import ipaddress
from datetime import datetime, timedelta

from bson import ObjectId
from pymongo.asynchronous.database import AsyncDatabase
from pymongo.errors import DuplicateKeyError

from app.config import Settings
from app.services import ipam, topology
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
                "notify_pending": True,
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
                           "acknowledged_at": None, "notify_pending": True}
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


def _device_label(device: dict) -> str:
    name = device.get("sys_name")
    return f"{name} ({device['mgmt_ip']})" if name else device["mgmt_ip"]


async def check_devices(db: AsyncDatabase, now: datetime) -> set[str]:
    """device_down: critical when nothing answers, warning when only SNMP fails."""
    active = set()
    async for device in db.devices.find({"status": {"$in": ["down", "snmp_error"]}},
                                        {"sys_name": 1, "mgmt_ip": 1, "status": 1,
                                         "status_changed_at": 1}).limit(5000):
        key = f"device_down:{device['_id']}"
        active.add(key)
        down = device["status"] == "down"
        await upsert_alert(
            db, key=key, type_="device_down", severity="critical" if down else "warning",
            message=(f"{_device_label(device)} is down: no answer to SNMP or ping." if down else
                     f"{_device_label(device)} answers ping but not SNMP (check SNMP "
                     "credentials or access lists on the device)."),
            target={"type": "device", "id": str(device["_id"]), "mgmt_ip": device["mgmt_ip"]},
            details={"status": device["status"], "since": device.get("status_changed_at")},
            now=now,
        )
    await resolve_missing(db, "device_down", active, now)
    return active


async def check_uplinks(db: AsyncDatabase, now: datetime) -> set[str]:
    """interface_down, only for uplinks: ports where an LLDP/CDP neighbour has been seen.

    Access ports go up and down all day (PCs shut down), so alerting on them would be noise.
    A lost link stays in the links collection for a week, so a cable that was pulled still
    counts as an uplink while it is down.
    """
    neighbors: dict[tuple, str | None] = {}
    async for link in db.links.find({"if_index": {"$ne": None}},
                                    {"device_id": 1, "if_index": 1, "remote_name": 1}
                                    ).sort("last_seen", 1).limit(20000):
        neighbors[(link["device_id"], link["if_index"])] = link.get("remote_name")
    up_devices = {d["_id"]: d async for d in db.devices.find(
        {"_id": {"$in": sorted({device_id for device_id, _ in neighbors})}, "status": "up"},
        {"sys_name": 1, "mgmt_ip": 1})}
    ports = [{"device_id": d, "if_index": i} for d, i in sorted(neighbors) if d in up_devices]
    active = set()
    if ports:
        query = {"$or": ports, "admin_status": "up", "oper_status": {"$nin": ["up", "dormant"]}}
        async for iface in db.interfaces.find(query, {"device_id": 1, "if_index": 1, "name": 1,
                                                      "alias": 1, "oper_status": 1}):
            device = up_devices[iface["device_id"]]
            port = iface.get("name") or f"ifIndex {iface['if_index']}"
            neighbor = neighbors.get((iface["device_id"], iface["if_index"]))
            to = f" (to {neighbor})" if neighbor else ""
            key = f"interface_down:{iface['device_id']}:{iface['if_index']}"
            active.add(key)
            await upsert_alert(
                db, key=key, type_="interface_down", severity="critical",
                message=f"Uplink {port}{to} on {_device_label(device)} is down "
                        f"(enabled, but link status is {iface.get('oper_status')}).",
                target={"type": "interface", "device_id": str(iface["device_id"]),
                        "if_index": iface["if_index"], "name": iface.get("name")},
                details={"oper_status": iface.get("oper_status"), "alias": iface.get("alias"),
                         "neighbor": neighbor},
                now=now,
            )
    await resolve_missing(db, "interface_down", active, now)
    return active


MAX_NEW_MAC_ALERTS_PER_RUN = 50


async def check_new_macs(db: AsyncDatabase, settings: Settings, now: datetime) -> int:
    """new_mac: a MAC address that no switch has ever reported before.

    The first NEW_MAC_LEARNING_HOURS after NetMap first sees a MAC table are a learning period:
    everything already on the network is the baseline. After that, a never-seen MAC that isn't a
    known device interface or a reserved IP's MAC raises a warning. It never auto-resolves (a
    rogue device unplugged again is still worth knowing about); an engineer resolves it, which
    marks the MAC as known.
    """
    pending = [m async for m in db.mac_addresses.find({"pending_check": True}).limit(5000)]
    if not pending:
        return 0
    first = await db.mac_addresses.find_one({}, {"first_seen": 1}, sort=[("first_seen", 1)])
    learning = now - first["first_seen"] < timedelta(hours=settings.new_mac_learning_hours)
    opened = 0
    if not learning:
        macs = [m["mac"] for m in pending]
        known = {i["mac"] async for i in db.interfaces.find({"mac": {"$in": macs}}, {"mac": 1})}
        known |= {r["reservation"]["mac"] async for r in db.ip_addresses.find(
            {"reservation.mac": {"$in": macs}}, {"reservation.mac": 1})}
        device_ids = sorted({m["first_device_id"] for m in pending})
        devices = {d["_id"]: d async for d in db.devices.find(
            {"_id": {"$in": device_ids}}, {"sys_name": 1, "mgmt_ip": 1})}
        for mac in pending:
            if mac["mac"] in known or opened >= MAX_NEW_MAC_ALERTS_PER_RUN:
                continue
            # Same uplink-aware logic as "locate": the access port, not a trunk that also saw it.
            found = (await topology.locate(db, mac["mac"], now))["location"]
            if found:
                device_id, if_index, vlan_id = (ObjectId(found["device_id"]), found["if_index"],
                                                found["vlan"])
            else:
                device_id, if_index, vlan_id = (mac["first_device_id"], mac["first_if_index"],
                                                mac.get("first_vlan"))
            device = devices.get(device_id) or await db.devices.find_one(
                {"_id": device_id}, {"sys_name": 1, "mgmt_ip": 1})
            iface = await db.interfaces.find_one({"device_id": device_id, "if_index": if_index},
                                                 {"name": 1})
            port = (iface or {}).get("name") or f"ifIndex {if_index}"
            where = f"{_device_label(device)} port {port}" if device else "a switch"
            if not found:
                where += " (an uplink: the exact access port is unknown)"
            vlan = f", VLAN {vlan_id}" if vlan_id else ""
            arp = await db.arp_entries.find_one({"mac": mac["mac"]}, {"ip": 1},
                                                sort=[("last_seen", -1)])
            await upsert_alert(
                db, key=f"new_mac:{mac['mac']}", type_="new_mac", severity="warning",
                message=f"New unknown device {mac['mac']} appeared on {where}{vlan}"
                        + (f", using IP {arp['ip']}." if arp else "."),
                target={"type": "mac", "mac": mac["mac"]},
                details={"device_id": str(device_id), "if_index": if_index, "port": port,
                         "vlan": vlan_id, "ip": arp["ip"] if arp else None,
                         "exact_port": bool(found)},
                now=now,
            )
            opened += 1
    await db.mac_addresses.update_many({"_id": {"$in": [m["_id"] for m in pending]}},
                                       {"$unset": {"pending_check": ""}})
    return opened


async def run_monitoring_checks(db: AsyncDatabase, settings: Settings,
                                now: datetime) -> dict[str, int]:
    down = await check_devices(db, now)
    uplinks = await check_uplinks(db, now)
    new_macs = await check_new_macs(db, settings, now)
    return {"device_down_alerts": len(down), "interface_down_alerts": len(uplinks),
            "new_mac_alerts_opened": new_macs}


async def run_ipam_checks(db: AsyncDatabase, settings: Settings, now: datetime) -> dict[str, int]:
    duplicates = await check_duplicate_ips(db, settings, now)
    full = await check_subnet_usage(db, settings, now)
    return {"duplicate_ip_alerts": len(duplicates), "subnet_usage_alerts": len(full)}
