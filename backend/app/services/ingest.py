"""Stores an agent's discovery report in MongoDB.

Every write is an upsert keyed by a unique index, so sending the same report twice changes
timestamps but never creates duplicates. Writes are batched with bulk_write (one round trip
per collection, not one per row), which matters on a free-tier Atlas cluster.

Device status:
  up          SNMP answered
  snmp_error  SNMP failed but the management IP answers ping (usually credentials or an ACL)
  down        neither SNMP nor ping answered
Only devices that have answered SNMP at least once are created. A host that only answers ping
is recorded in ip_addresses, not as a device.
"""

from datetime import datetime
from typing import Any

from pymongo import UpdateOne
from pymongo.asynchronous.database import AsyncDatabase

from app.models.report import DiscoveryReport, ReportDevice
from app.services.ipaddr import ip_key, network_key_range, network_of


def _device_status(device: ReportDevice, ping_up: dict[str, bool]) -> str:
    if device.reachable:
        return "up"
    return "snmp_error" if ping_up.get(str(device.mgmt_ip)) else "down"


def _device_update(device: ReportDevice, status: str, agent_id: str, now: datetime) -> dict:
    fields: dict[str, Any] = {
        "status": status,
        "snmp_port": device.snmp_port,
        "snmp_version": device.snmp_version,
        # Lets the UI and Phase 6 checks flag devices still using clear-text SNMPv2c.
        "snmp_v2c": device.snmp_version == "v2c",
        "agent_id": agent_id,
        "last_polled_at": now,
        "last_error": device.error,
    }
    if device.reachable:
        fields.update(
            sys_name=device.sys_name,
            sys_descr=device.sys_descr,
            sys_location=device.sys_location,
            sys_object_id=device.sys_object_id,
            vendor=device.vendor,
            uptime_seconds=device.uptime_seconds,
            last_seen=now,
            last_error=None,
        )
    return fields


async def ingest_report(db: AsyncDatabase, agent_id: str, report: DiscoveryReport,
                        now: datetime) -> dict[str, int]:
    ping_up = {str(p.ip): p.up for p in report.ping}
    mgmt_ips = [str(d.mgmt_ip) for d in report.devices]
    existing = {
        doc["mgmt_ip"]: doc
        async for doc in db.devices.find({"mgmt_ip": {"$in": mgmt_ips}},
                                         {"_id": 1, "mgmt_ip": 1, "status": 1})
    }

    device_ops = []
    for device in report.devices:
        ip = str(device.mgmt_ip)
        status = _device_status(device, ping_up)
        known = existing.get(ip)
        if known is None and not device.reachable:
            continue  # never answered SNMP: not a device (yet)
        fields = _device_update(device, status, agent_id, now)
        if known is None or known.get("status") != status:
            fields["status_changed_at"] = now
        device_ops.append(UpdateOne(
            {"mgmt_ip": ip},
            {"$set": fields,
             "$setOnInsert": {"mgmt_ip": ip, "mgmt_ip_key": ip_key(ip), "first_seen": now}},
            upsert=True,
        ))
    if device_ops:
        await db.devices.bulk_write(device_ops, ordered=False)

    reachable = [d for d in report.devices if d.reachable]
    ids = {
        doc["mgmt_ip"]: doc["_id"]
        async for doc in db.devices.find({"mgmt_ip": {"$in": [str(d.mgmt_ip) for d in reachable]}},
                                         {"_id": 1, "mgmt_ip": 1})
    }

    interface_ops, subnet_ops, ip_ops, arp_ops = [], [], [], []
    for device in reachable:
        device_id = ids[str(device.mgmt_ip)]
        macs = {}
        for iface in device.interfaces:
            macs[iface.if_index] = iface.mac
            interface_ops.append(UpdateOne(
                {"device_id": device_id, "if_index": iface.if_index},
                {"$set": {**iface.model_dump(), "last_seen": now},
                 "$setOnInsert": {"device_id": device_id, "first_seen": now}},
                upsert=True,
            ))
        if device.interfaces:
            # The device's own interface table is authoritative: drop rows it no longer has.
            await db.interfaces.delete_many(
                {"device_id": device_id,
                 "if_index": {"$nin": [i.if_index for i in device.interfaces]}})

        for address in device.addresses:
            ip = str(address.ip)
            ip_ops.append(_ip_upsert(ip, address.ip.version, now, "interface", {
                "mac": macs.get(address.if_index),
                "device_id": device_id,
                "if_index": address.if_index,
            }))
            # Host routes (/32, /128) are loopbacks, not subnets anyone allocates from.
            host_route = address.prefixlen == (32 if address.ip.version == 4 else 128)
            if address.prefixlen is not None and not host_route:
                subnet_ops.append(_subnet_upsert(network_of(ip, address.prefixlen), now))

        for neighbor in device.neighbors:
            ip = str(neighbor.ip)
            key = ip_key(ip)
            ip_ops.append(_ip_upsert(ip, neighbor.ip.version, now, "arp", {
                "mac": neighbor.mac,
                "seen_by_device_id": device_id,
                "seen_on_if_index": neighbor.if_index,
            }))
            # One row per (IP, MAC, reporting device): two MACs for one IP is how Phase 3
            # detects duplicate IPs, so they must not overwrite each other here.
            arp_ops.append(UpdateOne(
                {"ip_key": key, "mac": neighbor.mac, "device_id": device_id},
                {"$set": {"if_index": neighbor.if_index, "kind": neighbor.kind, "last_seen": now},
                 "$setOnInsert": {"ip": ip, "ip_key": key, "mac": neighbor.mac,
                                  "device_id": device_id, "first_seen": now}},
                upsert=True,
            ))

    for result in report.ping:
        ip = str(result.ip)
        if result.up:
            ip_ops.append(_ip_upsert(ip, result.ip.version, now, "ping",
                                     {"ping_up": True, "last_ping_at": now}))
        else:
            # A silent address isn't evidence it exists, so this never creates a record.
            ip_ops.append(UpdateOne({"ip_key": ip_key(ip)},
                                    {"$set": {"ping_up": False, "last_ping_at": now}}))

    for collection, ops in (("interfaces", interface_ops), ("subnets", subnet_ops),
                            ("ip_addresses", ip_ops), ("arp_entries", arp_ops)):
        if ops:
            await db[collection].bulk_write(ops, ordered=False)

    return {
        "devices_up": sum(1 for d in report.devices if d.reachable),
        "devices_not_responding": sum(1 for d in report.devices if not d.reachable),
        "interfaces": len(interface_ops),
        "addresses": sum(len(d.addresses) for d in reachable),
        "neighbors": len(arp_ops),
        "ping_up": sum(1 for p in report.ping if p.up),
        "ping_total": len(report.ping),
    }


def _ip_upsert(ip: str, version: int, now: datetime, source: str, fields: dict) -> UpdateOne:
    key = ip_key(ip)
    return UpdateOne(
        {"ip_key": key},
        {"$set": {**{k: v for k, v in fields.items() if v is not None}, "last_seen": now},
         "$addToSet": {"sources": source},
         "$setOnInsert": {"ip": ip, "ip_key": key, "version": version, "first_seen": now}},
        upsert=True,
    )


def _subnet_upsert(network, now: datetime) -> UpdateOne:
    start_key, end_key = network_key_range(network)
    return UpdateOne(
        {"network": str(network)},
        # $setOnInsert only: a subnet an engineer created or edited by hand is never overwritten.
        {"$setOnInsert": {"network": str(network), "version": network.version,
                          "prefixlen": network.prefixlen, "start_key": start_key,
                          "end_key": end_key, "source": "discovered", "created_at": now},
         "$set": {"last_discovered_at": now}},
        upsert=True,
    )
