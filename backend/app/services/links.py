"""Stores LLDP/CDP neighbours as links and works out which NetMap device is on the far end.

A neighbour only tells us what it claims about itself (its name, port and management address),
so the far end is matched to a known device by, in order:
  1. management IP = the device's mgmt_ip
  2. management IP = an address on one of the device's interfaces
  3. system name (CDP often appends a domain: "CORE-SW-1.campus.local" matches "CORE-SW-1")
  4. chassis ID = the MAC of one of the device's interfaces
A neighbour that matches nothing (an ISP router, a phone, an unmanaged switch) is kept as an
"external" neighbour, so the map still shows that something is plugged in there.

Links not reported in a cycle are marked "lost" (shown as a broken link on the map) and
MongoDB deletes them after LINK_TTL_SECONDS without being seen (TTL index in db.py).
"""

import secrets
from datetime import datetime

from bson import ObjectId
from pymongo import UpdateOne
from pymongo.asynchronous.database import AsyncDatabase

from app.models.report import ReportDevice, ReportLink
from app.services.ipaddr import ip_key
from app.services.ipam import normalize_mac

MAX_DEVICES_FOR_NAME_MATCH = 5000


def short_name(name: str | None) -> str | None:
    """Lower-case host part of a name: "CORE-SW-1.campus.local" -> "core-sw-1"."""
    if not name:
        return None
    return name.strip().split(".")[0].lower() or None


def remote_key(link: ReportLink) -> str:
    """Identifies the neighbour on a port (a port can have several, e.g. a phone and a PC)."""
    return (link.remote_chassis_id or link.remote_name or
            (str(link.remote_mgmt_ip) if link.remote_mgmt_ip else "unknown"))[:255]


async def _matchers(db: AsyncDatabase, links: list[ReportLink]) -> dict:
    ips = {str(link.remote_mgmt_ip) for link in links if link.remote_mgmt_ip}
    by_mgmt = {d["mgmt_ip"]: d["_id"] async for d in db.devices.find(
        {"mgmt_ip": {"$in": sorted(ips)}}, {"mgmt_ip": 1})}
    by_iface_ip = {a["ip"]: a["device_id"] async for a in db.ip_addresses.find(
        {"ip_key": {"$in": sorted(ip_key(ip) for ip in ips)}, "device_id": {"$exists": True}},
        {"ip": 1, "device_id": 1})}

    names: dict[str, ObjectId | None] = {}
    async for d in db.devices.find({"sys_name": {"$ne": None}}, {"sys_name": 1}).limit(
            MAX_DEVICES_FOR_NAME_MATCH):
        name = short_name(d.get("sys_name"))
        if name:
            # Two devices with the same name: ambiguous, so the name matches neither.
            names[name] = None if name in names else d["_id"]

    macs = {normalize_mac(link.remote_chassis_id) for link in links if link.remote_chassis_id}
    macs.discard(None)
    by_mac = {i["mac"]: i["device_id"] async for i in db.interfaces.find(
        {"mac": {"$in": sorted(macs)}}, {"mac": 1, "device_id": 1})}
    return {"mgmt": by_mgmt, "iface_ip": by_iface_ip, "name": names, "mac": by_mac}


def match_remote(link: ReportLink, matchers: dict) -> ObjectId | None:
    ip = str(link.remote_mgmt_ip) if link.remote_mgmt_ip else None
    if ip and ip in matchers["mgmt"]:
        return matchers["mgmt"][ip]
    if ip and ip in matchers["iface_ip"]:
        return matchers["iface_ip"][ip]
    name = short_name(link.remote_name)
    if name and matchers["name"].get(name):
        return matchers["name"][name]
    mac = normalize_mac(link.remote_chassis_id) if link.remote_chassis_id else None
    if mac and mac in matchers["mac"]:
        return matchers["mac"][mac]
    return None


def _remote_if_index(link: ReportLink, interfaces: list[dict]) -> int | None:
    """Which of the remote device's interfaces the neighbour says it is using."""
    wanted = {t.strip().lower() for t in (link.remote_port, link.remote_port_descr) if t}
    port_mac = normalize_mac(link.remote_port) if link.remote_port else None
    for iface in interfaces:
        names = {t.lower() for t in (iface.get("name"), iface.get("descr")) if t}
        if wanted & names or (port_mac and iface.get("mac") == port_mac):
            return iface["if_index"]
    return None


async def ingest_links(db: AsyncDatabase, devices: list[tuple[ObjectId, ReportDevice]],
                       now: datetime) -> int:
    """Upsert the links of every polled device; mark the ones that disappeared as lost."""
    all_links = [link for _, device in devices for link in device.links]
    matchers = await _matchers(db, all_links) if all_links else {}
    matched: dict[int, ObjectId | None] = {}
    for _, device in devices:
        for link in device.links:
            matched[id(link)] = match_remote(link, matchers)
    remote_ids = {r for r in matched.values() if r is not None}
    remote_ifaces: dict[ObjectId, list[dict]] = {}
    async for iface in db.interfaces.find(
            {"device_id": {"$in": sorted(remote_ids)}},
            {"device_id": 1, "if_index": 1, "name": 1, "descr": 1, "mac": 1}):
        remote_ifaces.setdefault(iface["device_id"], []).append(iface)

    cycle = secrets.token_hex(8)  # marks the rows written by this report
    ops = []
    for device_id, device in devices:
        for link in device.links:
            remote_id = matched[id(link)]
            if remote_id == device_id:
                remote_id = None  # a device can't be its own neighbour (bad LLDP data)
            fields = link.model_dump(exclude={"remote_mgmt_ip"})
            ops.append(UpdateOne(
                {"device_id": device_id, "protocol": link.protocol, "if_index": link.if_index,
                 "remote_key": remote_key(link)},
                {"$set": {**fields,
                          "remote_mgmt_ip": str(link.remote_mgmt_ip) if link.remote_mgmt_ip
                          else None,
                          "remote_device_id": remote_id,
                          "remote_if_index": _remote_if_index(link, remote_ifaces.get(remote_id,
                                                                                        []))
                          if remote_id else None,
                          "status": "active", "cycle": cycle, "last_seen": now},
                 "$setOnInsert": {"first_seen": now}},
                upsert=True,
            ))
    if ops:
        await db.links.bulk_write(ops, ordered=False)
    await db.links.update_many(
        {"device_id": {"$in": [device_id for device_id, _ in devices]}, "cycle": {"$ne": cycle},
         "status": "active"},
        {"$set": {"status": "lost"}},
    )
    return len(ops)
