"""Built-in question parser: common questions answered without any language model.

Each rule is a regular expression plus the query it produces. The query still goes through
query_guard.validate(), exactly like a model's answer, so the rules get no special trust.
Returns None when no rule matches (then the LLM is asked, if one is configured).
"""

from __future__ import annotations

import ipaddress
import re

EXAMPLES = [
    "Which switch port is 10.10.10.20 on?",
    "Show down devices",
    "Show devices on floor 2",
    "Which subnets will be full within 90 days?",
    "Fullest subnets",
    "Open critical alerts",
    "Show all printers",
    "Devices made by Cisco",
    "What is 10.10.30.10?",
    "How many devices are down?",
]

TYPE_WORDS = {
    "printer": "printer", "camera": "camera", "phone": "phone", "pc": "pc", "laptop": "pc",
    "computer": "pc", "vm": "server_vm", "server": "server_vm", "virtual machine": "server_vm",
    "access point": "access_point", "ap": "access_point", "switch": "network_device",
    "router": "network_device", "network device": "network_device",
}
MAC = re.compile(r"\b([0-9a-f]{2}([:-])[0-9a-f]{2}(\2[0-9a-f]{2}){4})\b", re.IGNORECASE)
TOKEN = re.compile(r"^[A-Za-z0-9.:_-]{1,64}$")
DEVICE_FIELDS = {"sys_name": 1, "mgmt_ip": 1, "status": 1, "vendor": 1, "sys_location": 1,
                 "classification.type": 1}


def _escape(text: str) -> str:
    return re.escape(text)[:60]


def _type_of(text: str) -> str | None:
    for word, kind in sorted(TYPE_WORDS.items(), key=lambda kv: -len(kv[0])):
        if re.search(rf"\b{word}s?\b", text):
            return kind
    return None


def _location(text: str) -> dict | None:
    floor = re.search(r"\b(?:floor|level)\s*(\d{1,2})\b|\b(\d{1,2})(?:st|nd|rd|th)\s+floor\b",
                      text)
    if floor:
        n = floor.group(1) or floor.group(2)
        return {"sys_location": {"$regex": f"(floor|level) ?{n}\\b|{n}(st|nd|rd|th) floor",
                                 "$options": "i"}}
    place = re.search(r"\b(?:in|at) (?:the )?([a-z][a-z ]{2,30}?)(?: building)?\s*\??$", text)
    if place and place.group(1) not in ("network", "subnet"):
        return {"sys_location": {"$regex": _escape(place.group(1).strip()), "$options": "i"}}
    return None


def parse(question: str) -> tuple[dict, str] | None:
    """(proposal, plain-language description) or None."""
    text = " ".join(question.lower().split()).rstrip("?.! ")

    port = re.search(r"(?:which|what) (?:switch )?port is (.+?) (?:on|connected to)$|"
                     r"^(?:where is|locate|find) (.+)$", text)
    if port:
        target = (port.group(1) or port.group(2)).strip().strip("'\"")
        original = re.search(re.escape(target), question, re.IGNORECASE)
        target = original.group(0) if original else target
        if TOKEN.match(target):
            return ({"tool": "locate", "q": target},
                    f"Look up which switch port {target} is connected to.")

    ip_or_mac = re.search(r"^(?:what|who) is (?:ip |mac |address )?(\S+)$", text)
    if ip_or_mac:
        value = ip_or_mac.group(1)
        try:
            ipaddress.ip_address(value)
            return ({"collection": "ip_addresses", "pipeline": [{"$match": {"ip": value}}]},
                    f"Find the address record for {value}.")
        except ValueError:
            if MAC.fullmatch(value):
                mac = value.replace("-", ":")
                return ({"collection": "ip_addresses", "pipeline": [{"$match": {"mac": mac}}]},
                        f"Find the addresses used by {mac}.")

    fill = re.search(r"subnets? .*(?:full|run out|exhaust).*?(\d{1,4}) days", text)
    if fill:
        days = int(fill.group(1))
        return ({"collection": "predictions", "pipeline": [
                    {"$match": {"kind": "subnet_exhaustion", "days_until_full": {"$lte": days}}},
                    {"$sort": {"days_until_full": 1}}]},
                f"Subnets forecast to be full within {days} days.")
    if re.search(r"(fullest|busiest|most used|usage of) subnets?|subnets? (usage|by usage)", text):
        return ({"collection": "predictions", "pipeline": [
                    {"$match": {"kind": "subnet_exhaustion"}}, {"$sort": {"percent": -1}},
                    {"$limit": 10}]},
                "Subnets sorted by how full they are (from the latest forecast run).")

    if "alert" in text:
        match: dict = {"status": "resolved" if "resolved" in text else "open"}
        severity = re.search(r"\b(critical|warning|info)\b", text)
        if severity:
            match["severity"] = severity.group(1)
        kind = re.search(r"\b(duplicate ip|device down|anomal|compliance|new (?:device|mac))",
                         text)
        if kind:
            match["type"] = {"duplicate ip": "duplicate_ip", "device down": "device_down",
                             "anomal": "traffic_anomaly", "compliance": "compliance"}.get(
                                 kind.group(1), "new_mac")
        return ({"collection": "alerts", "pipeline": [{"$match": match},
                                                      {"$sort": {"last_seen": -1}}]},
                "Alerts matching " + ", ".join(f"{k} = {v}" for k, v in match.items()) + ".")

    vendor = re.search(r"(?:made by|from|by|vendor) ([a-z][a-z0-9 -]{1,30})$", text)
    if vendor and "device" in text:
        name = vendor.group(1).strip()
        return ({"collection": "devices", "pipeline": [
                    {"$match": {"vendor": {"$regex": _escape(name), "$options": "i"}}},
                    {"$project": DEVICE_FIELDS}]},
                f"Network devices whose vendor matches “{name}”.")

    down = re.search(r"\b(down|offline|unreachable|not responding)\b", text)
    kind = _type_of(text)
    if down or re.search(r"\b(devices|switches|routers|aps|access points)\b", text):
        match = {}
        if down:
            match["status"] = {"$in": ["down", "snmp_error"]}
        if kind in ("access_point", "network_device"):
            match["classification.type"] = kind
        location = _location(text)
        if location:
            match |= location
        if text.startswith("how many"):
            return ({"collection": "devices", "pipeline": [{"$match": match},
                                                           {"$count": "devices"}]},
                    "Count network devices" + (" that are down." if down else "."))
        if match or re.search(r"\b(show|list|all)\b", text):
            return ({"collection": "devices", "pipeline": [
                        {"$match": match}, {"$project": DEVICE_FIELDS},
                        {"$sort": {"sys_name": 1}}]},
                    "Network devices" + (" that are down or not answering SNMP" if down else "")
                    + (" at that location" if location else "") + ".")

    if kind and kind not in ("network_device",):
        return ({"collection": "mac_addresses", "pipeline": [
                    {"$match": {"classification.type": kind}},
                    {"$project": {"mac": 1, "ips": 1, "classification.type": 1,
                                  "classification.confidence": 1, "last_seen": 1}},
                    {"$sort": {"last_seen": -1}}]},
                f"Endpoints classified as {kind.replace('_', ' ')}.")
    return None
