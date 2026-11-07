"""IP addresses: search, IP → MAC → device → port detail, and manual reservations.

The unique index on ip_addresses.ip_key is what makes a duplicate reservation impossible:
two simultaneous requests for one free IP can't both insert a record.
"""

import ipaddress
import re
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pymongo.errors import DuplicateKeyError

from app.api.subnets import ip_rows, require_engineer
from app.models.common import IpPath
from app.models.ipam import ReservationCreate
from app.security.rbac import CurrentUser, require_user
from app.security.sessions import utcnow
from app.services import audit, ipam
from app.services.alerts import run_ipam_checks
from app.services.ipaddr import ip_key, network_key_range
from app.services.topology import locate

router = APIRouter(prefix="/api/ips", tags=["ipam"], dependencies=[Depends(require_user)])

MAX_RESULTS = 200
# Letters, digits and the punctuation of IPs, MACs, CIDRs and host names. No quotes, braces,
# "$", "*" or other regex/operator characters can get in.
SearchText = Annotated[str, Query(min_length=1, max_length=100,
                                  pattern=r"^[A-Za-z0-9.:_\- /]+$")]


def _parse_ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "Not a valid IP address") from None


@router.get("/search")
async def search(request: Request, q: SearchText) -> dict:
    db = request.app.state.db
    kind, value = ipam.classify_query(q)
    devices: list[dict] = []
    if kind == "ip":
        query: dict = {"ip_key": ip_key(value)}
    elif kind == "network":
        start_key, end_key = network_key_range(value)
        query = {"ip_key": {"$gte": start_key, "$lte": end_key}}
    elif kind == "mac":
        query = {"$or": [{"mac": value}, {"reservation.mac": value}]}
    else:
        # re.escape: the text is matched literally, so "." or ".*" can't widen the search.
        pattern = {"$regex": re.escape(value), "$options": "i"}
        devices = [d async for d in db.devices.find(
            {"sys_name": pattern},
            {"sys_name": 1, "mgmt_ip": 1, "vendor": 1, "status": 1}).limit(50)]
        query = {"$or": [{"reservation.hostname": pattern},
                         {"device_id": {"$in": [d["_id"] for d in devices]}}]}
    docs = [d async for d in db.ip_addresses.find(query).sort("ip_key", 1).limit(MAX_RESULTS)]
    return {
        "query_type": kind,
        "items": [row.model_dump() for row in await ip_rows(request, docs)],
        "devices": [{"id": str(d["_id"]), "name": d.get("sys_name"), "mgmt_ip": d["mgmt_ip"],
                     "vendor": d.get("vendor"), "status": d.get("status")} for d in devices],
        "truncated": len(docs) == MAX_RESULTS,
    }


@router.get("/{ip}")
async def ip_detail(request: Request, ip: IpPath) -> dict:
    """Everything known about one address: IP → MAC → device → interface (→ switch port)."""
    db = request.app.state.db
    settings = request.app.state.settings
    address = _parse_ip(ip)
    key = ip_key(address)
    now = utcnow()
    record = await db.ip_addresses.find_one({"ip_key": key})
    subnet = await ipam.containing_subnet(db, address)

    owner = None
    if record and record.get("device_id"):
        owner = await _device_port(db, record["device_id"], record.get("if_index"))
    window = now - timedelta(minutes=settings.duplicate_ip_window_minutes)
    seen_by = []
    async for entry in db.arp_entries.find({"ip_key": key}).sort("last_seen", -1).limit(50):
        seen_by.append({**(await _device_port(db, entry["device_id"], entry.get("if_index"))),
                        "mac": entry["mac"], "kind": entry.get("kind"),
                        "last_seen": entry["last_seen"], "recent": entry["last_seen"] >= window})
    alert = await db.alerts.find_one({"key": f"duplicate_ip:{key}", "status": "open"},
                                     {"_id": 0, "message": 1, "details": 1, "opened_at": 1})
    cutoff = ipam.stale_cutoff(now, settings.ip_stale_days)
    mac = record.get("mac") if record else None
    endpoint = (await db.mac_addresses.find_one({"mac": mac}, {"classification": 1})
                if mac else None)
    return {
        "ip": str(address),
        "version": address.version,
        "status": ipam.ip_status(record, cutoff) if record else "free",
        "subnet": {"id": str(subnet["_id"]), "network": subnet["network"],
                   "name": subnet.get("name")} if subnet else None,
        "mac": mac,
        # Device type from the agent's classifier, or an engineer's correction (Phase 7).
        "classification": (endpoint or {}).get("classification"),
        "macs_recent": sorted({s["mac"] for s in seen_by if s["recent"]}),
        "sources": record.get("sources", []) if record else [],
        "reservation": record.get("reservation") if record else None,
        "owner": owner,
        "seen_by": seen_by,
        # Access-switch port from the MAC address tables (services/topology.py).
        "switch_port": await _switch_port(db, str(address), now),
        "duplicate_alert": alert,
        "first_seen": record.get("first_seen") if record else None,
        "last_seen": record.get("last_seen") if record else None,
    }


async def _switch_port(db, ip: str, now) -> dict | None:
    found = await locate(db, ip, now)
    if found["location"] is None:
        return None
    return {**found["location"], "message": found["message"]}


async def _device_port(db, device_id, if_index) -> dict:
    device = await db.devices.find_one({"_id": device_id}, {"sys_name": 1, "mgmt_ip": 1})
    iface = None
    if if_index is not None:
        iface = await db.interfaces.find_one({"device_id": device_id, "if_index": if_index},
                                             {"name": 1, "alias": 1})
    return {
        "device_id": str(device_id),
        "device": device.get("sys_name") if device else None,
        "mgmt_ip": device["mgmt_ip"] if device else None,
        "if_index": if_index,
        "interface": iface.get("name") if iface else None,
        "interface_alias": iface.get("alias") if iface else None,
    }


@router.post("/reservations", status_code=status.HTTP_201_CREATED)
async def reserve(
    body: ReservationCreate, request: Request, user: CurrentUser = Depends(require_engineer)
) -> dict:
    db = request.app.state.db
    settings = request.app.state.settings
    address = body.ip
    key = ip_key(address)
    now = utcnow()
    cutoff = ipam.stale_cutoff(now, settings.ip_stale_days)

    async def refuse(code: int, reason: str, message: str):
        await audit.record(db, request, action="ip.reserve", result="failure",
                           actor=audit.user_actor(user), target={"type": "ip", "ip": str(address)},
                           details={"reason": reason})
        raise HTTPException(code, message)

    mac = None
    if body.mac:
        mac = ipam.normalize_mac(body.mac)
        if mac is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Not a valid MAC address")
    subnet = await ipam.containing_subnet(db, address)
    if subnet is None:
        await refuse(422, "no_subnet", f"{address} is not inside any known subnet")
    net = ipaddress.ip_network(subnet["network"])
    if not ipam.is_assignable(net, address):
        await refuse(422, "not_assignable",
                     f"{address} is the network or broadcast address of {net}")
    if subnet.get("gateway") == str(address):
        await refuse(409, "gateway", f"{address} is the gateway of {net}")

    reservation = {"hostname": body.hostname, "description": body.description, "mac": mac,
                   "reserved_by": user.username, "reserved_at": now}
    existing = await db.ip_addresses.find_one({"ip_key": key})
    if existing is None:
        try:
            await db.ip_addresses.insert_one({
                "ip": str(address), "ip_key": key, "version": address.version,
                "sources": ["reservation"], "first_seen": now, "reservation": reservation,
            })
        except DuplicateKeyError:
            await refuse(409, "race", f"{address} was just taken by another request")
    else:
        if existing.get("reservation"):
            await refuse(409, "already_reserved", f"{address} is already reserved")
        if existing.get("last_seen") and existing["last_seen"] >= cutoff:
            await refuse(409, "in_use", f"{address} is in use (last seen "
                         f"{existing['last_seen']:%Y-%m-%d %H:%M} UTC)")
        # Conditional update: if the IP became reserved or active since we looked, nothing
        # matches and we refuse, instead of overwriting.
        result = await db.ip_addresses.update_one(
            {"ip_key": key, "reservation": {"$exists": False},
             "$or": [{"last_seen": {"$lt": cutoff}}, {"last_seen": {"$exists": False}}]},
            {"$set": {"reservation": reservation}, "$addToSet": {"sources": "reservation"}},
        )
        if result.matched_count == 0:
            await refuse(409, "race", f"{address} was just taken by another request")

    await audit.record(db, request, action="ip.reserve", result="success",
                       actor=audit.user_actor(user), target={"type": "ip", "ip": str(address)},
                       details={"subnet": subnet["network"], "hostname": body.hostname})
    await run_ipam_checks(db, settings, now)
    return {"ip": str(address), "subnet": subnet["network"], "reservation": reservation}


@router.delete("/reservations/{ip}", status_code=status.HTTP_204_NO_CONTENT)
async def release(
    request: Request, ip: IpPath, user: CurrentUser = Depends(require_engineer)
) -> None:
    db = request.app.state.db
    address = _parse_ip(ip)
    key = ip_key(address)
    doc = await db.ip_addresses.find_one({"ip_key": key, "reservation": {"$exists": True}})
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No reservation for this IP")
    if doc.get("last_seen") is None:
        await db.ip_addresses.delete_one({"_id": doc["_id"]})  # never seen on the network
    else:
        await db.ip_addresses.update_one({"_id": doc["_id"]},
                                         {"$unset": {"reservation": ""},
                                          "$pull": {"sources": "reservation"}})
    await audit.record(db, request, action="ip.release", result="success",
                       actor=audit.user_actor(user), target={"type": "ip", "ip": str(address)},
                       details={"hostname": doc["reservation"].get("hostname")})
    await run_ipam_checks(db, request.app.state.settings, utcnow())
