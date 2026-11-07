"""The network map (devices + links) and "which switch port is this device plugged into?".

Locating an endpoint: switches learn which MAC address is behind which port (the MAC address
table). A PC's MAC is learned on the access-switch port it is plugged into, but also on every
uplink/trunk between that switch and the rest of the network, because its frames cross those
too. So the core switch "sees" every PC on its trunks. To find the real port, sightings on
uplink ports are thrown out. A port counts as an uplink if:
  - an LLDP/CDP neighbour (another network device) was seen on it, or
  - its MAC table shows more than one VLAN (a trunk), or
  - more than UPLINK_MAC_THRESHOLD MACs are behind it (something is aggregating them).
The heuristic is documented in docs/known-limitations.md (an unmanaged desk switch with many
PCs on one port is reported as an uplink).
"""

import re
from datetime import datetime, timedelta

from pymongo.asynchronous.database import AsyncDatabase

from app.services import ipam
from app.services.ipaddr import ip_key

UPLINK_MAC_THRESHOLD = 10
# A MAC-table row older than this says where a device was, not where it is.
RECENT = timedelta(hours=24)
MAX_NODES = 2000
MAX_LINKS = 10000
MAX_SIGHTINGS = 50

NODE_STATUS = {"up": "up", "down": "down", "snmp_error": "warning"}


def _label(device: dict | None) -> str | None:
    if not device:
        return None
    return device.get("sys_name") or device.get("mgmt_ip")


async def build_graph(db: AsyncDatabase) -> dict:
    devices = {d["_id"]: d async for d in db.devices.find(
        {}, {"sys_name": 1, "mgmt_ip": 1, "vendor": 1, "status": 1, "sys_location": 1,
             "snmp_v2c": 1}).limit(MAX_NODES)}
    links = [link async for link in db.links.find({}).limit(MAX_LINKS)]

    alerts: dict[str, int] = {}
    async for a in db.alerts.find({"status": "open", "target.type": {"$in": ["device",
                                                                            "interface"]}},
                                  {"target": 1}).limit(5000):
        device_id = a["target"].get("id") or a["target"].get("device_id")
        alerts[device_id] = alerts.get(device_id, 0) + 1

    # Interface names and states for both ends of every link.
    ends = {(link["device_id"], link["if_index"]) for link in links if link.get("if_index")}
    ends |= {(link["remote_device_id"], link["remote_if_index"]) for link in links
             if link.get("remote_device_id") and link.get("remote_if_index")}
    interfaces = {}
    if ends:
        query = {"$or": [{"device_id": d, "if_index": i} for d, i in sorted(ends)]}
        async for iface in db.interfaces.find(query, {"device_id": 1, "if_index": 1, "name": 1,
                                                      "oper_status": 1, "admin_status": 1,
                                                      "speed_mbps": 1, "rates": 1}):
            interfaces[(iface["device_id"], iface["if_index"])] = iface

    nodes = [{
        "id": str(device_id), "label": _label(d), "mgmt_ip": d["mgmt_ip"],
        "vendor": d.get("vendor"), "location": d.get("sys_location"),
        "status": NODE_STATUS.get(d.get("status"), "warning"), "device_status": d.get("status"),
        "external": False, "open_alerts": alerts.get(str(device_id), 0),
        "snmp_v2c": bool(d.get("snmp_v2c")),
    } for device_id, d in devices.items()]

    external: dict[str, dict] = {}
    edges: dict[tuple, dict] = {}
    for link in sorted(links, key=lambda x: (x.get("status") != "active", str(x["_id"]))):
        if link["device_id"] not in devices:
            continue
        local = (str(link["device_id"]), link.get("if_index"))
        if link.get("remote_device_id") in devices:
            remote = (str(link["remote_device_id"]), link.get("remote_if_index"))
        else:
            ext_id = "ext:" + link["remote_key"]
            external.setdefault(ext_id, {
                "id": ext_id, "label": link.get("remote_name") or link.get("remote_mgmt_ip")
                or link["remote_key"], "mgmt_ip": link.get("remote_mgmt_ip"),
                "vendor": None, "location": None, "status": "external",
                "device_status": None, "external": True, "open_alerts": 0,
                "platform": link.get("remote_platform"), "snmp_v2c": False,
            })
            remote = (ext_id, None)
        _merge_edge(edges, link, local, remote, interfaces)

    for edge in edges.values():
        states = [s for s in edge.pop("_states") if s is not None]
        edge["status"] = "down" if edge["lost"] or any(s != "up" for s in states) else "up"
    return {"nodes": nodes + list(external.values()), "edges": list(edges.values()),
            "truncated": len(devices) >= MAX_NODES or len(links) >= MAX_LINKS}


def _port_name(link: dict, side: str, interfaces: dict) -> str | None:
    if side == "local":
        iface = interfaces.get((link["device_id"], link.get("if_index")))
        return (iface or {}).get("name") or link.get("local_port")
    iface = interfaces.get((link.get("remote_device_id"), link.get("remote_if_index")))
    return (iface or {}).get("name") or link.get("remote_port")


def _merge_edge(edges: dict, link: dict, local: tuple, remote: tuple, interfaces: dict) -> None:
    """Both ends of a cable usually report it (A sees B and B sees A): keep one edge.

    Edges are keyed by the unordered pair of devices plus ports. When one side's port is
    unknown, it merges with an existing edge between the same two devices that agrees on the
    known port.
    """
    local_port = _port_name(link, "local", interfaces)
    remote_port = _port_name(link, "remote", interfaces)
    states = [(interfaces.get((link["device_id"], link.get("if_index"))) or {}).get(
        "oper_status")]
    if link.get("remote_device_id"):
        states.append((interfaces.get((link["remote_device_id"], link.get("remote_if_index")))
                       or {}).get("oper_status"))
    a, b = sorted([local, remote], key=lambda e: e[0])
    for key, edge in edges.items():
        if {key[0][0], key[1][0]} != {a[0], b[0]}:
            continue
        ends = dict(key)
        if all(ends.get(dev) in (None, port) or port is None for dev, port in (a, b)):
            edge["protocols"] = sorted(set(edge["protocols"]) | {link["protocol"]})
            edge["lost"] = edge["lost"] and link.get("status") == "lost"
            edge["_states"] += states
            for dev, port in ((local[0], local_port), (remote[0], remote_port)):
                field = "source_port" if dev == edge["source"] else "target_port"
                edge[field] = edge[field] or port
            return
    source, target = local, remote
    edges[(a, b)] = {
        "id": f"{source[0]}:{source[1]}-{target[0]}:{target[1]}",
        "source": source[0], "target": target[0],
        "source_port": local_port, "target_port": remote_port,
        "protocols": [link["protocol"]], "lost": link.get("status") == "lost",
        "_states": states,
    }


# ---- locate -----------------------------------------------------------------------------------

async def _uplink_ports(db: AsyncDatabase, ports: set[tuple], since: datetime) -> dict:
    """For each (device_id, if_index): the reason it is an uplink, or None for an access port."""
    if not ports:
        return {}
    or_ports = [{"device_id": d, "if_index": i} for d, i in sorted(ports)]
    linked = {(link["device_id"], link["if_index"]) async for link in db.links.find(
        {"$or": or_ports}, {"device_id": 1, "if_index": 1})}
    stats = {}
    pipeline = [
        {"$match": {"$or": or_ports, "last_seen": {"$gte": since}}},
        {"$group": {"_id": {"d": "$device_id", "i": "$if_index"},
                    "macs": {"$addToSet": "$mac"}, "vlans": {"$addToSet": "$vlan"}}},
        {"$project": {"macs": {"$size": "$macs"}, "vlans": {"$size": "$vlans"}}},
    ]
    async for row in await db.mac_entries.aggregate(pipeline):
        stats[(row["_id"]["d"], row["_id"]["i"])] = row
    result = {}
    for port in ports:
        row = stats.get(port, {"macs": 0, "vlans": 0})
        if port in linked:
            result[port] = "network device connected (LLDP/CDP)"
        elif row["vlans"] > 1:
            result[port] = f"trunk ({row['vlans']} VLANs)"
        elif row["macs"] > UPLINK_MAC_THRESHOLD:
            result[port] = f"{row['macs']} MAC addresses behind it"
        else:
            result[port] = None
    return result


async def _resolve_query(db: AsyncDatabase, q: str) -> dict:
    """Turn the search text into a MAC (and IP / host name when known)."""
    kind, value = ipam.classify_query(q)
    found = {"query": q, "kind": kind, "ip": None, "mac": None, "hostname": None,
             "device": None}
    if kind == "ip":
        address = value
        found["ip"] = str(address)
        device = await db.devices.find_one({"mgmt_ip": str(address)})
        if device is None:
            record = await db.ip_addresses.find_one({"ip_key": ip_key(address)})
            arp = await db.arp_entries.find_one({"ip_key": ip_key(address)},
                                                sort=[("last_seen", -1)])
            found["mac"] = (arp or {}).get("mac") or (record or {}).get("mac")
            found["hostname"] = ((record or {}).get("reservation") or {}).get("hostname")
            if record and record.get("device_id"):
                device = await db.devices.find_one({"_id": record["device_id"]})
        found["device"] = device
    elif kind == "mac":
        found["mac"] = value
        arp = await db.arp_entries.find_one({"mac": value}, sort=[("last_seen", -1)])
        found["ip"] = (arp or {}).get("ip")
        iface = await db.interfaces.find_one({"mac": value}, {"device_id": 1})
        if iface:
            found["device"] = await db.devices.find_one({"_id": iface["device_id"]})
    elif kind == "hostname":
        name = q.strip()
        device = await db.devices.find_one({"sys_name": name}) or await db.devices.find_one(
            {"sys_name": {"$regex": f"^{re.escape(name)}$", "$options": "i"}})
        if device:
            found["device"] = device
        else:
            record = await db.ip_addresses.find_one(
                {"reservation.hostname": {"$regex": f"^{re.escape(name)}$", "$options": "i"}})
            if record:
                found["ip"], found["hostname"] = record["ip"], record["reservation"]["hostname"]
                found["mac"] = record.get("mac") or record["reservation"].get("mac")
                if not record.get("mac"):
                    arp = await db.arp_entries.find_one({"ip_key": record["ip_key"]},
                                                        sort=[("last_seen", -1)])
                    found["mac"] = found["mac"] or (arp or {}).get("mac")
    return found


async def locate(db: AsyncDatabase, q: str, now: datetime) -> dict:
    found = await _resolve_query(db, q)
    device = found.pop("device")
    result = {**found, "device": None, "location": None, "sightings": [], "message": None}

    if device is not None:
        # A NetMap device: its location is the far end of its own uplink.
        result["device"] = {"id": str(device["_id"]), "name": _label(device),
                            "mgmt_ip": device["mgmt_ip"], "status": device.get("status")}
        upstream = await db.links.find_one({"remote_device_id": device["_id"]},
                                           sort=[("status", 1), ("last_seen", -1)])
        if upstream:
            peer = await db.devices.find_one({"_id": upstream["device_id"]},
                                             {"sys_name": 1, "mgmt_ip": 1})
            iface = await db.interfaces.find_one(
                {"device_id": upstream["device_id"], "if_index": upstream.get("if_index")},
                {"name": 1})
            result["location"] = {
                "device_id": str(upstream["device_id"]), "device": _label(peer),
                "if_index": upstream.get("if_index"),
                "port": (iface or {}).get("name") or upstream.get("local_port"),
                "vlan": None, "last_seen": upstream["last_seen"], "via": upstream["protocol"],
            }
            result["message"] = (f"{_label(device)} is a network device, connected to "
                                 f"{_label(peer)} port {result['location']['port']}.")
            return result
        if not found["mac"]:
            result["message"] = f"{_label(device)} is a network device; no neighbour reports it."
            return result

    mac = result["mac"]
    if not mac:
        result["message"] = ("No MAC address is known for this, so it can't be located. "
                             "It must appear in an ARP table first.")
        return result

    since = now - RECENT
    entries = [e async for e in db.mac_entries.find({"mac": mac}).sort("last_seen", -1)
               .limit(MAX_SIGHTINGS)]
    if not entries:
        result["message"] = f"{mac} is not in any switch MAC address table."
        return result
    uplinks = await _uplink_ports(db, {(e["device_id"], e["if_index"]) for e in entries}, since)
    device_ids = sorted({e["device_id"] for e in entries})
    names = {d["_id"]: d async for d in db.devices.find({"_id": {"$in": device_ids}},
                                                        {"sys_name": 1, "mgmt_ip": 1})}
    ports = {(i["device_id"], i["if_index"]): i async for i in db.interfaces.find(
        {"$or": [{"device_id": e["device_id"], "if_index": e["if_index"]} for e in entries]},
        {"device_id": 1, "if_index": 1, "name": 1, "alias": 1})}
    for e in entries:
        iface = ports.get((e["device_id"], e["if_index"]), {})
        reason = uplinks.get((e["device_id"], e["if_index"]))
        result["sightings"].append({
            "device_id": str(e["device_id"]), "device": _label(names.get(e["device_id"])),
            "if_index": e["if_index"], "port": iface.get("name") or f"ifIndex {e['if_index']}",
            "port_alias": iface.get("alias"), "vlan": e.get("vlan"),
            "last_seen": e["last_seen"], "recent": e["last_seen"] >= since,
            "uplink": reason is not None, "uplink_reason": reason,
        })
    access = [s for s in result["sightings"] if not s["uplink"]]
    if access:
        best = max(access, key=lambda s: s["last_seen"])
        result["location"] = {k: best[k] for k in ("device_id", "device", "if_index", "port",
                                                   "vlan", "last_seen")} | {"via": "mac_table"}
        vlan = f", VLAN {best['vlan']}" if best["vlan"] else ""
        old = "" if best["recent"] else " (not seen in the last 24 hours)"
        result["message"] = f"{mac} is on {best['device']} port {best['port']}{vlan}{old}."
    else:
        result["message"] = (f"{mac} is only seen on uplink ports. It is probably behind a "
                             "device NetMap doesn't poll (an unmanaged switch or a wireless "
                             "bridge).")
    return result

