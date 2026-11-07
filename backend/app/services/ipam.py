"""IPAM rules: subnet usage, overlap, containment, next free IP and search parsing.

All address arithmetic uses Python integers (exact for IPv6 too) and the ip_key storage rule
from services/ipaddr.py. Database filters are built here from parsed values only.
"""

import heapq
import ipaddress
import re
from collections.abc import Iterable
from datetime import datetime, timedelta

from pymongo.asynchronous.database import AsyncDatabase

from app.services.ipaddr import IPAddress, IPNetwork, ip_key, key_to_ip, network_key_range

_HEX = re.compile(r"[0-9a-fA-F]")
_MAC_TEXT = re.compile(r"^(0x)?[0-9a-fA-F:.\-]{12,17}$")


# ---- usage maths -----------------------------------------------------------------------------

def usable_bounds(net: IPNetwork) -> tuple[int, int] | None:
    """First and last address (as integers) that can be given to a host."""
    first, last = int(net.network_address), int(net.broadcast_address)
    if net.version == 4:
        if net.prefixlen >= 31:  # /31 point-to-point (RFC 3021) and /32 use every address
            return first, last
        return first + 1, last - 1  # no network or broadcast address
    if net.prefixlen == 128:
        return first, last
    return first + 1, last  # skip the subnet-router anycast address (RFC 4291); no broadcast


def usable_count(net: IPNetwork) -> int:
    bounds = usable_bounds(net)
    return 0 if bounds is None else bounds[1] - bounds[0] + 1


def usage(net: IPNetwork, used: int) -> dict:
    usable = usable_count(net)
    percent = round(used * 100 / usable, 2) if usable else 0.0
    return {
        "size": str(net.num_addresses),
        "usable": str(usable),
        "used": str(used),
        "free": str(max(usable - used, 0)),
        "percent": percent,
    }


def stale_cutoff(now: datetime, stale_days: int) -> datetime:
    return now - timedelta(days=stale_days)


def used_filter(net: IPNetwork, cutoff: datetime) -> dict:
    """ip_addresses in the usable part of `net` that are reserved or were seen recently."""
    first, last = usable_bounds(net)
    cls = type(net.network_address)
    return {
        "ip_key": {"$gte": ip_key(cls(first)), "$lte": ip_key(cls(last))},
        "$or": [{"reservation": {"$exists": True}}, {"last_seen": {"$gte": cutoff}}],
    }


async def count_used(db: AsyncDatabase, net: IPNetwork, cutoff: datetime) -> int:
    return await db.ip_addresses.count_documents(used_filter(net, cutoff))


def ip_status(doc: dict, cutoff: datetime) -> str:
    if doc.get("reservation"):
        return "reserved"
    last_seen = doc.get("last_seen")
    return "used" if last_seen is not None and last_seen >= cutoff else "stale"


# ---- subnets ---------------------------------------------------------------------------------

def range_filter(net: IPNetwork) -> dict:
    """Subnets of the same IP version whose address range intersects `net`."""
    start_key, end_key = network_key_range(net)
    return {"version": net.version, "start_key": {"$lte": end_key}, "end_key": {"$gte": start_key}}


async def find_overlaps(db: AsyncDatabase, net: IPNetwork, exclude_id=None) -> list[str]:
    query = range_filter(net)
    if exclude_id is not None:
        query["_id"] = {"$ne": exclude_id}
    cursor = db.subnets.find(query, {"network": 1}).sort("start_key", 1).limit(20)
    return [doc["network"] async for doc in cursor]


async def containing_subnet(db: AsyncDatabase, address: IPAddress) -> dict | None:
    """The most specific subnet that contains `address`."""
    key = ip_key(address)
    cursor = db.subnets.find(
        {"version": address.version, "start_key": {"$lte": key}, "end_key": {"$gte": key}}
    ).sort("prefixlen", -1).limit(1)
    return await anext(aiter(cursor), None)


def check_subnet_fields(net: IPNetwork, gateway: IPAddress | None,
                        reserved_ranges: list | None) -> None:
    """Raise ValueError if the gateway or a reserved range doesn't belong to `net`."""
    bounds = usable_bounds(net)
    if gateway is not None:
        if gateway.version != net.version or gateway not in net:
            raise ValueError(f"gateway {gateway} is not inside {net}")
        if not bounds[0] <= int(gateway) <= bounds[1]:
            raise ValueError(f"gateway {gateway} is the network or broadcast address of {net}")
    for item in reserved_ranges or []:
        if item.start not in net or item.end not in net:
            raise ValueError(f"reserved range {item.start}-{item.end} is not inside {net}")


def excluded_intervals(net: IPNetwork, gateway: str | None,
                       reserved_ranges: Iterable[dict]) -> list[tuple[int, int]]:
    intervals = []
    if gateway:
        intervals.append((int(ipaddress.ip_address(gateway)),) * 2)
    for item in reserved_ranges:
        intervals.append((int(ipaddress.ip_address(item["start"])),
                          int(ipaddress.ip_address(item["end"]))))
    return sorted(intervals)


def first_free(net: IPNetwork, blocked: Iterable[tuple[int, int]],
               used: Iterable[int]) -> IPAddress | None:
    """Lowest usable address not inside any blocked interval or used address.

    Both inputs must be sorted ascending. The walk only visits blocked/used entries, so its cost
    depends on how many addresses are taken, never on the subnet size (a /64 is instant).
    """
    bounds = usable_bounds(net)
    candidate, last = bounds
    merged = heapq.merge(blocked, ((u, u) for u in used))
    for start, end in merged:
        if start > candidate:
            break
        candidate = max(candidate, end + 1)
        if candidate > last:
            return None
    if candidate > last:
        return None
    return type(net.network_address)(candidate)


async def next_free(db: AsyncDatabase, subnet: dict, cutoff: datetime) -> IPAddress | None:
    net = ipaddress.ip_network(subnet["network"])
    cursor = db.ip_addresses.find(used_filter(net, cutoff), {"ip_key": 1, "_id": 0})
    cursor = cursor.sort("ip_key", 1)
    used = [int(key_to_ip(doc["ip_key"])) async for doc in cursor]
    blocked = excluded_intervals(net, subnet.get("gateway"), subnet.get("reserved_ranges") or [])
    return first_free(net, blocked, used)


def is_assignable(net: IPNetwork, address: IPAddress) -> bool:
    bounds = usable_bounds(net)
    return bounds[0] <= int(address) <= bounds[1]


# ---- search ----------------------------------------------------------------------------------

def normalize_mac(text: str) -> str | None:
    """aa:bb:cc:dd:ee:ff from colon, dash, dotted (Cisco) or bare-hex text; None otherwise."""
    text = text.strip()
    if not _MAC_TEXT.match(text):
        return None
    digits = "".join(_HEX.findall(text[2:] if text.lower().startswith("0x") else text)).lower()
    if len(digits) != 12:
        return None
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def classify_query(q: str) -> tuple[str, object]:
    """Decide what a search string is: an IP, a network, a MAC, or a host name fragment."""
    q = q.strip()
    try:
        return "ip", ipaddress.ip_address(q)
    except ValueError:
        pass
    if "/" in q:
        try:
            return "network", ipaddress.ip_network(q, strict=False)
        except ValueError:
            pass
    mac = normalize_mac(q)
    if mac:
        return "mac", mac
    return "hostname", q
