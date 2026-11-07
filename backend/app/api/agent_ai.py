"""Agent routes for Phase 7 AI (HMAC-signed requests only).

The heavy work (Prophet, IsolationForest, classification) runs on the agent; the backend
only hands out training data and stores results. An agent sees and writes only:
- its own devices (devices.agent_id) and their interfaces and metrics;
- subnets that contain an address of one of its devices (interface or ARP);
- MACs seen in its own devices' switch tables.
Training data never includes users, sessions, configs, credentials or the audit log.
"""

import ipaddress
from bisect import bisect_left
from datetime import timedelta, timezone

from bson import ObjectId
from fastapi import APIRouter, BackgroundTasks, Depends, Request
from pymongo import UpdateOne
from pymongo.asynchronous.database import AsyncDatabase

from app.models.ai import AnomalyUpload, ClassificationUpload, PredictionUpload
from app.models.report import MAX_DEVICES
from app.security.agent_auth import CurrentAgent, require_agent
from app.security.sessions import utcnow
from app.services import alerts, ipam, notify

router = APIRouter(prefix="/api/agent/ai", tags=["agent"], dependencies=[Depends(require_agent)])

HISTORY_DAYS = 400
METRIC_DAYS = 7
MAX_INTERFACES = 100
MAX_POINTS = METRIC_DAYS * 24 * 12 + 50  # one sample every 5 minutes
MAX_ENDPOINTS = 5000
MAX_SUBNETS = 2000
WIRELESS_IF_TYPE = 71  # IANAifType ieee80211
WIRELESS_NAME = ("wlan", "radio", "dot11", "wifi", "wl")


async def agent_devices(db: AsyncDatabase, agent: CurrentAgent) -> dict[ObjectId, dict]:
    return {d["_id"]: d async for d in db.devices.find(
        {"agent_id": agent.id}, {"sys_name": 1, "mgmt_ip": 1, "vendor": 1, "sys_descr": 1}
    ).limit(MAX_DEVICES)}


async def agent_subnets(db: AsyncDatabase, device_ids: list[ObjectId]) -> list[dict]:
    """Subnets holding at least one address that this agent's devices own or saw in ARP."""
    keys = sorted({d["ip_key"] async for d in db.ip_addresses.find(
        {"$or": [{"device_id": {"$in": device_ids}},
                 {"seen_by_device_id": {"$in": device_ids}}]},
        {"ip_key": 1}).limit(100_000)})
    found = []
    async for subnet in db.subnets.find(
            {}, {"network": 1, "name": 1, "start_key": 1, "end_key": 1}).limit(MAX_SUBNETS):
        i = bisect_left(keys, subnet["start_key"])
        if i < len(keys) and keys[i] <= subnet["end_key"]:
            found.append(subnet)
    return found


def _label(device: dict | None) -> str:
    device = device or {}
    return str(device.get("sys_name") or device.get("mgmt_ip") or "device")


def _wireless(iface: dict | None) -> bool:
    if not iface:
        return False
    name = str(iface.get("name") or "").lower()
    return iface.get("if_type") == WIRELESS_IF_TYPE or name.startswith(WIRELESS_NAME)


@router.get("/training-data")
async def training_data(request: Request, agent: CurrentAgent = Depends(require_agent)) -> dict:
    db = request.app.state.db
    now = utcnow()
    devices = await agent_devices(db, agent)
    ids = list(devices)

    # 1. Subnet usage history (one point per day), for the exhaustion forecast.
    subnets = []
    for subnet in await agent_subnets(db, ids):
        usable = ipam.usable_count(ipaddress.ip_network(subnet["network"]))
        # Point-to-point links are full by design and a /64 never fills: no forecast.
        if not alerts.MIN_USABLE_FOR_USAGE_ALERT <= usable <= alerts.MAX_USABLE_FOR_HISTORY:
            continue
        history = [{"day": h["day"], "used": h["used"]} async for h in db.subnet_usage.find(
            {"subnet_id": subnet["_id"]}, {"day": 1, "used": 1}).sort("day", 1)
            .limit(HISTORY_DAYS)]
        subnets.append({"id": str(subnet["_id"]), "network": subnet["network"],
                        "name": subnet.get("name"), "usable": usable, "history": history})

    # 2. Interface traffic (7 days of 5-minute samples) for forecasts and anomaly detection.
    since = now - timedelta(days=METRIC_DAYS)
    pairs = [g["_id"] async for g in await db.metrics.aggregate([
        {"$match": {"device_id": {"$in": ids}, "ts": {"$gte": since}}},
        {"$group": {"_id": {"device_id": "$device_id", "if_index": "$if_index"}}},
        {"$sort": {"_id.device_id": 1, "_id.if_index": 1}},
        {"$limit": MAX_INTERFACES}])]
    uplinks = {(link["device_id"], link.get("if_index")) async for link in db.links.find(
        {"device_id": {"$in": ids}}, {"device_id": 1, "if_index": 1})}
    ifaces = {(i["device_id"], i["if_index"]): i async for i in db.interfaces.find(
        {"device_id": {"$in": ids}},
        {"device_id": 1, "if_index": 1, "name": 1, "alias": 1, "speed_mbps": 1, "if_type": 1,
         "mac": 1})}
    interfaces = []
    for pair in pairs:
        key = (pair["device_id"], pair["if_index"])
        iface = ifaces.get(key) or {}
        points = []
        async for m in db.metrics.find(
                {"device_id": key[0], "if_index": key[1], "ts": {"$gte": since}},
                {"ts": 1, "in_bps": 1, "out_bps": 1, "in_errors": 1, "out_errors": 1,
                 "interval_s": 1}).sort("ts", 1).limit(MAX_POINTS):
            seconds = m.get("interval_s") or 0
            errors = (m.get("in_errors") or 0) + (m.get("out_errors") or 0)
            ts = m["ts"] if m["ts"].tzinfo else m["ts"].replace(tzinfo=timezone.utc)
            points.append([ts.timestamp(), m.get("in_bps"), m.get("out_bps"),
                           round(errors / seconds, 3) if seconds else 0.0])
        interfaces.append({
            "device_id": str(key[0]), "if_index": key[1],
            "label": f"{_label(devices.get(key[0]))} {iface.get('name') or key[1]}",
            "speed_mbps": iface.get("speed_mbps"), "uplink": key in uplinks, "points": points})

    # 3. Endpoints (MACs in this agent's switch tables) for device-type classification.
    subnet_rows = sorted(
        [s async for s in db.subnets.find({}, {"name": 1, "network": 1, "start_key": 1,
                                                "end_key": 1}).limit(MAX_SUBNETS)],
        key=lambda s: s["start_key"])
    starts = [s["start_key"] for s in subnet_rows]
    sightings = {g["_id"]: g async for g in await db.mac_entries.aggregate([
        {"$match": {"device_id": {"$in": ids}}},
        {"$sort": {"last_seen": -1}},
        {"$group": {"_id": "$mac", "device_id": {"$first": "$device_id"},
                    "if_index": {"$first": "$if_index"}}},
        {"$limit": MAX_ENDPOINTS}])}
    macs = list(sightings)
    own_macs = {i.get("mac"): i["device_id"] for i in ifaces.values() if i.get("mac")}
    ips: dict[str, list[tuple[str, str]]] = {}
    async for record in db.ip_addresses.find({"mac": {"$in": macs}},
                                             {"mac": 1, "ip": 1, "ip_key": 1}).limit(20_000):
        ips.setdefault(record["mac"], []).append((record["ip"], record["ip_key"]))
    manual = {m["mac"] async for m in db.mac_addresses.find(
        {"mac": {"$in": macs}, "classification.source": "manual"}, {"mac": 1})}

    def subnet_name(key: str) -> str | None:
        i = bisect_left(starts, key + "~") - 1  # last subnet starting at or before the key
        if i >= 0 and subnet_rows[i]["end_key"] >= key:
            return subnet_rows[i].get("name")
        return None

    endpoints = []
    for mac in macs:
        seen = sightings[mac]
        port = ifaces.get((seen["device_id"], seen["if_index"]))
        labels = [n for n in (subnet_name(k) for _ip, k in ips.get(mac, [])) if n]
        if port and port.get("alias"):
            labels.append(port["alias"])
        endpoint = {"mac": mac, "ips": [ip for ip, _k in ips.get(mac, [])][:10],
                    "network_labels": list(dict.fromkeys(labels))[:5],
                    "seen_on_wireless": _wireless(port), "manual": mac in manual}
        if mac in own_macs:
            device = devices.get(own_macs[mac]) or {}
            endpoint["managed"] = {"device_id": str(own_macs[mac]),
                                   "vendor": device.get("vendor"),
                                   "sys_descr": (device.get("sys_descr") or "")[:300]}
        endpoints.append(endpoint)
    # Managed devices whose MAC no switch reported (a router on a routed link, the core):
    # still classify them, from their own SNMP data.
    covered = {e["managed"]["device_id"] for e in endpoints if "managed" in e}
    first_mac: dict = {}
    for (device_id, _if_index), iface in sorted(ifaces.items(),
                                               key=lambda kv: (str(kv[0][0]), kv[0][1])):
        if iface.get("mac") and device_id not in first_mac:
            first_mac[device_id] = iface["mac"]
    for device_id, mac in first_mac.items():
        if str(device_id) in covered or len(endpoints) >= MAX_ENDPOINTS:
            continue
        device = devices.get(device_id) or {}
        endpoints.append({"mac": mac, "ips": [device.get("mgmt_ip")] if device.get("mgmt_ip")
                          else [], "network_labels": [], "seen_on_wireless": False,
                          "manual": False,
                          "managed": {"device_id": str(device_id), "vendor": device.get("vendor"),
                                      "sys_descr": (device.get("sys_descr") or "")[:300]}})
    return {"generated_at": now, "subnets": subnets, "interfaces": interfaces,
            "endpoints": endpoints}


@router.post("/predictions")
async def upload_predictions(body: PredictionUpload, request: Request,
                             agent: CurrentAgent = Depends(require_agent)) -> dict:
    db = request.app.state.db
    now = utcnow()
    devices = await agent_devices(db, agent)
    subnets = {str(s["_id"]): s for s in await agent_subnets(db, list(devices))}
    names = {(i["device_id"], i["if_index"]): i.get("name") async for i in db.interfaces.find(
        {"device_id": {"$in": list(devices)}}, {"device_id": 1, "if_index": 1, "name": 1})}
    ops, sent, skipped = [], [], 0
    for item in body.predictions:
        doc = item.model_dump(mode="json")
        if item.kind == "subnet_exhaustion":
            subnet = subnets.get(item.subnet_id)
            if subnet is None:
                skipped += 1
                continue
            target_key = item.subnet_id
            doc |= {"subnet_id": subnet["_id"], "network": subnet["network"],
                    "label": subnet.get("name") or subnet["network"],
                    "percent": round(100 * item.current_used / item.usable, 1)
                    if item.usable else None}
        else:
            device_id = ObjectId(item.device_id)
            if device_id not in devices:
                skipped += 1
                continue
            target_key = f"{item.device_id}:{item.if_index}"
            doc |= {"device_id": device_id,
                    "label": f"{_label(devices[device_id])} "
                             f"{names.get((device_id, item.if_index)) or item.if_index}"}
        doc |= {"target_key": target_key, "generated_at": now, "agent_id": agent.id}
        sent.append(target_key)
        ops.append(UpdateOne({"kind": item.kind, "target_key": target_key}, {"$set": doc},
                             upsert=True))
    if ops:
        await db.predictions.bulk_write(ops, ordered=False)
    # Each upload is the agent's complete set: forecasts it no longer sends (a subnet that was
    # deleted or became too small to forecast) are removed instead of lingering for 14 days.
    removed = (await db.predictions.delete_many(
        {"agent_id": agent.id, "target_key": {"$nin": sent}})).deleted_count
    return {"status": "ok", "stored": len(ops), "skipped": skipped, "removed": removed}


@router.post("/anomalies")
async def upload_anomalies(body: AnomalyUpload, request: Request, background: BackgroundTasks,
                           agent: CurrentAgent = Depends(require_agent)) -> dict:
    db = request.app.state.db
    now = utcnow()
    devices = await agent_devices(db, agent)

    def key(device_id: str, if_index: int) -> str:
        return f"traffic_anomaly:{device_id}:{if_index}"

    opened = 0
    active = set()
    for item in body.anomalies:
        device_id = ObjectId(item.device_id)
        device = devices.get(device_id)
        if device is None:
            continue
        iface = await db.interfaces.find_one({"device_id": device_id, "if_index": item.if_index},
                                             {"name": 1})
        port = (iface or {}).get("name") or f"interface {item.if_index}"
        active.add(key(item.device_id, item.if_index))
        result = await alerts.upsert_alert(
            db, key=key(item.device_id, item.if_index), type_="traffic_anomaly",
            severity="warning", message=item.explanation,
            target={"type": "interface", "id": item.device_id, "device": _label(device),
                    "port": port, "if_index": item.if_index},
            details={"metric": item.metric, "value": item.value, "typical": item.typical,
                     "at": item.ts, "score": round(item.score, 3)},
            now=now)
        opened += result in ("opened", "reopened")
    # An interface the agent checked and found normal closes its anomaly alert.
    normal = [key(c.device_id, c.if_index) for c in body.checked
              if ObjectId(c.device_id) in devices and key(c.device_id, c.if_index) not in active]
    resolved = 0
    if normal:
        result = await db.alerts.update_many(
            {"key": {"$in": normal}, "status": "open"},
            {"$set": {"status": "resolved", "resolved_at": now, "resolved_by": None}})
        resolved = result.modified_count
    background.add_task(notify.dispatch_pending, db, request.app.state.settings)
    return {"status": "ok", "opened": opened, "resolved": resolved}


@router.post("/classifications")
async def upload_classifications(body: ClassificationUpload, request: Request,
                                 agent: CurrentAgent = Depends(require_agent)) -> dict:
    db = request.app.state.db
    now = utcnow()
    devices = await agent_devices(db, agent)
    ids = list(devices)
    macs = [item.mac for item in body.items]
    # Only MACs this agent's switches have seen, and never over an engineer's correction.
    in_scope = set(await db.mac_entries.distinct("mac", {"device_id": {"$in": ids},
                                                         "mac": {"$in": macs}}))
    managed = {i["mac"]: i["device_id"] async for i in db.interfaces.find(
        {"device_id": {"$in": ids}, "mac": {"$in": macs}}, {"mac": 1, "device_id": 1})}
    # The MAC's current addresses go next to its type, so "show all printers" says where.
    ips: dict[str, list[str]] = {}
    async for record in db.ip_addresses.find({"mac": {"$in": macs}}, {"mac": 1, "ip": 1}
                                             ).sort("ip_key", 1).limit(20_000):
        ips.setdefault(record["mac"], []).append(record["ip"])
    ops, device_ops = [], []
    for item in body.items:
        if item.mac not in in_scope and item.mac not in managed:
            continue
        ops.append(UpdateOne({"mac": item.mac}, {"$set": {"ips": ips.get(item.mac, [])[:10]}}))
        value = {"type": item.type, "confidence": item.confidence, "reasons": item.reasons,
                 "source": "auto", "at": now}
        ops.append(UpdateOne({"mac": item.mac, "classification.source": {"$ne": "manual"}},
                             {"$set": {"classification": value}}))
        if item.mac in managed and item.type in ("network_device", "access_point"):
            device_ops.append(UpdateOne(
                {"_id": managed[item.mac], "classification.source": {"$ne": "manual"}},
                {"$set": {"classification": value}}))
    stored = 0
    if ops:
        await db.mac_addresses.bulk_write(ops, ordered=False)
        # Types written by this upload (manual ones are skipped). `now` is BSON-encoded to the
        # same millisecond both when stored and in this filter, so the match is exact.
        stored = await db.mac_addresses.count_documents(
            {"mac": {"$in": macs}, "classification.source": "auto", "classification.at": now})
    if device_ops:
        await db.devices.bulk_write(device_ops, ordered=False)
    return {"status": "ok", "stored": stored}
