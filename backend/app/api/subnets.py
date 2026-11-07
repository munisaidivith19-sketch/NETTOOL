"""Subnets: usage, manual create/edit/delete, the IP table and the next free IP.

Reading needs any role; changes need engineer or admin (CLAUDE.md 7.2).
"""

import ipaddress
from typing import Annotated, Literal

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pymongo.errors import DuplicateKeyError

from app.models.common import ObjectIdPath
from app.models.ipam import IpPage, IpRow, NextFree, SubnetCreate, SubnetOut, SubnetUpdate
from app.security.rbac import CurrentUser, require_role, require_user
from app.security.sessions import utcnow
from app.services import audit, ipam
from app.services.alerts import run_ipam_checks
from app.services.ipaddr import key_to_ip, network_key_range

router = APIRouter(prefix="/api/subnets", tags=["ipam"], dependencies=[Depends(require_user)])
require_engineer = require_role("admin", "engineer")

MAX_SUBNETS_LISTED = 1000
IpKeyCursor = Annotated[str, Query(pattern=r"^[46]:[0-9a-f]{32}$")]


def _cutoff(request: Request):
    return ipam.stale_cutoff(utcnow(), request.app.state.settings.ip_stale_days)


async def _get(request: Request, subnet_id: str) -> dict:
    doc = await request.app.state.db.subnets.find_one({"_id": ObjectId(subnet_id)})
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Subnet not found")
    return doc


async def _out(request: Request, doc: dict) -> SubnetOut:
    net = ipaddress.ip_network(doc["network"])
    used = await ipam.count_used(request.app.state.db, net, _cutoff(request))
    return SubnetOut(
        id=str(doc["_id"]), network=doc["network"], version=doc["version"],
        prefixlen=doc["prefixlen"], source=doc.get("source", "discovered"),
        name=doc.get("name"), description=doc.get("description"), vlan=doc.get("vlan"),
        gateway=doc.get("gateway"), reserved_ranges=doc.get("reserved_ranges") or [],
        usage=ipam.usage(net, used), created_at=doc.get("created_at"),
        updated_at=doc.get("updated_at"), last_discovered_at=doc.get("last_discovered_at"),
    )


def _target(doc: dict) -> dict:
    return {"type": "subnet", "id": str(doc["_id"]), "network": doc["network"]}


def _stored_fields(body, fields: set[str]) -> dict:
    """Body fields as they are stored: addresses as text, ranges as plain dicts."""
    out = {}
    for name in fields:
        value = getattr(body, name)
        if name == "gateway" and value is not None:
            value = str(value)
        elif name == "reserved_ranges" and value is not None:
            value = [{"start": str(r.start), "end": str(r.end), "note": r.note} for r in value]
        out[name] = value
    return out


async def _checks(request: Request) -> None:
    await run_ipam_checks(request.app.state.db, request.app.state.settings, utcnow())


@router.get("", response_model=list[SubnetOut])
async def list_subnets(request: Request, version: Literal[4, 6] | None = None) -> list[SubnetOut]:
    query = {} if version is None else {"version": version}
    cursor = request.app.state.db.subnets.find(query).sort(
        [("version", 1), ("start_key", 1)]).limit(MAX_SUBNETS_LISTED)
    return [await _out(request, doc) async for doc in cursor]


@router.post("", response_model=SubnetOut, status_code=status.HTTP_201_CREATED)
async def create_subnet(
    body: SubnetCreate, request: Request, user: CurrentUser = Depends(require_engineer)
) -> SubnetOut:
    db = request.app.state.db
    net = ipaddress.ip_network(body.network)
    try:
        ipam.check_subnet_fields(net, body.gateway, body.reserved_ranges)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from None

    overlaps = await ipam.find_overlaps(db, net)
    if overlaps:
        await audit.record(db, request, action="subnet.create", result="failure",
                           actor=audit.user_actor(user),
                           target={"type": "subnet", "network": str(net)},
                           details={"reason": "overlap", "overlaps": overlaps})
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"{net} overlaps existing subnet(s): {', '.join(overlaps)}")

    now = utcnow()
    start_key, end_key = network_key_range(net)
    doc = {
        "network": str(net), "version": net.version, "prefixlen": net.prefixlen,
        "start_key": start_key, "end_key": end_key, "source": "manual",
        "created_at": now, "created_by": user.username, "updated_at": now,
        **{k: v for k, v in _stored_fields(body, body.model_fields_set - {"network"}).items()
           if v is not None},
    }
    try:
        result = await db.subnets.insert_one(doc)
    except DuplicateKeyError:  # created by someone else a moment ago
        raise HTTPException(status.HTTP_409_CONFLICT, f"{net} already exists") from None
    doc["_id"] = result.inserted_id
    await audit.record(db, request, action="subnet.create", result="success",
                       actor=audit.user_actor(user), target=_target(doc),
                       details={"fields": sorted(body.model_fields_set - {"network"})})
    await _checks(request)
    return await _out(request, doc)


@router.get("/{subnet_id}", response_model=SubnetOut)
async def get_subnet(request: Request, subnet_id: ObjectIdPath) -> SubnetOut:
    return await _out(request, await _get(request, subnet_id))


@router.patch("/{subnet_id}", response_model=SubnetOut)
async def update_subnet(
    body: SubnetUpdate, request: Request, subnet_id: ObjectIdPath,
    user: CurrentUser = Depends(require_engineer),
) -> SubnetOut:
    db = request.app.state.db
    doc = await _get(request, subnet_id)
    net = ipaddress.ip_network(doc["network"])
    fields = body.model_fields_set
    gateway = body.gateway if "gateway" in fields else (
        ipaddress.ip_address(doc["gateway"]) if doc.get("gateway") else None)
    try:
        ipam.check_subnet_fields(net, gateway, body.reserved_ranges)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from None
    if not fields:
        return await _out(request, doc)

    changes = _stored_fields(body, fields)
    to_set = {k: v for k, v in changes.items() if v is not None}
    to_unset = {k: "" for k, v in changes.items() if v is None}
    update: dict = {"$set": {**to_set, "updated_at": utcnow(), "updated_by": user.username}}
    if to_unset:
        update["$unset"] = to_unset
    await db.subnets.update_one({"_id": doc["_id"]}, update)
    await audit.record(db, request, action="subnet.update", result="success",
                       actor=audit.user_actor(user), target=_target(doc),
                       details={"fields": sorted(fields)})
    await _checks(request)
    return await _out(request, await _get(request, subnet_id))


@router.delete("/{subnet_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_subnet(
    request: Request, subnet_id: ObjectIdPath, user: CurrentUser = Depends(require_engineer)
) -> None:
    db = request.app.state.db
    doc = await _get(request, subnet_id)
    # IP records and reservations are kept: they belong to addresses, not to the subnet entry.
    await db.subnets.delete_one({"_id": doc["_id"]})
    await audit.record(db, request, action="subnet.delete", result="success",
                       actor=audit.user_actor(user), target=_target(doc),
                       details={"source": doc.get("source")})
    await _checks(request)


@router.get("/{subnet_id}/ips", response_model=IpPage)
async def subnet_ips(
    request: Request, subnet_id: ObjectIdPath,
    limit: int = Query(100, ge=1, le=500), after: IpKeyCursor | None = None,
) -> IpPage:
    db = request.app.state.db
    doc = await _get(request, subnet_id)
    key_range: dict = {"$gte": doc["start_key"], "$lte": doc["end_key"]}
    if after is not None:
        key_range["$gt"] = after
    rows = [d async for d in db.ip_addresses.find({"ip_key": key_range})
            .sort("ip_key", 1).limit(limit)]
    items = await ip_rows(request, rows)
    next_after = rows[-1]["ip_key"] if len(rows) == limit else None
    return IpPage(items=items, next_after=next_after)


@router.get("/{subnet_id}/next-free", response_model=NextFree)
async def subnet_next_free(request: Request, subnet_id: ObjectIdPath) -> NextFree:
    doc = await _get(request, subnet_id)
    free = await ipam.next_free(request.app.state.db, doc, _cutoff(request))
    return NextFree(subnet=doc["network"], ip=str(free) if free is not None else None)


async def ip_rows(request: Request, docs: list[dict]) -> list[IpRow]:
    """IP records with the owning or reporting device's name attached (one extra query)."""
    db = request.app.state.db
    cutoff = _cutoff(request)
    device_ids = {d.get("device_id") or d.get("seen_by_device_id") for d in docs} - {None}
    devices = {dev["_id"]: dev async for dev in db.devices.find(
        {"_id": {"$in": list(device_ids)}}, {"sys_name": 1, "mgmt_ip": 1})}
    rows = []
    for d in docs:
        owner = d.get("device_id") or d.get("seen_by_device_id")
        device = devices.get(owner)
        reservation = d.get("reservation")
        rows.append(IpRow(
            ip=d.get("ip") or str(key_to_ip(d["ip_key"])),
            version=d.get("version", 4 if d["ip_key"].startswith("4:") else 6),
            status=ipam.ip_status(d, cutoff), mac=d.get("mac"), sources=d.get("sources", []),
            device={"id": str(device["_id"]), "name": device.get("sys_name"),
                    "mgmt_ip": device["mgmt_ip"],
                    "relation": "owner" if d.get("device_id") else "seen_by"} if device else None,
            reservation=dict(reservation) if reservation else None,
            ping_up=d.get("ping_up"), first_seen=d.get("first_seen"),
            last_seen=d.get("last_seen"),
        ))
    return rows
