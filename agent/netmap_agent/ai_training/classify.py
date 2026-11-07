"""What kind of thing is behind this MAC address? An explainable, rule-based classifier.

Each clue adds points to one or more device types, and every point comes with a reason a
person can check. The type with the most points wins; confidence is its share of all points.
There is no trained model: that would need many devices labelled by hand, and a model's
reasons are harder to explain. An engineer can always correct the type in the UI.

Clues used:
- the manufacturer from the MAC's OUI (Brother → printer, Hikvision → camera, VMware → VM)
- a randomised ("private") MAC, which phones and laptops use on Wi-Fi
- words in the network's name, e.g. VLAN "Printers and phones" or subnet "CCTV"
- being seen on a wireless access point
- SNMP data, for devices NetMap manages (switch, router or access point)
- open TCP ports, only if port probing is switched on (9100 = printing, 554 = video stream)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from netmap_agent.ai_training.oui import OuiTable, is_private

TYPES = ("pc", "printer", "phone", "camera", "access_point", "network_device", "server_vm")
MIN_SCORE = 1.5  # below this the evidence is too thin: "unknown"

# Manufacturer name (lower case, regex) → points per type.
VENDOR_HINTS: list[tuple[str, dict[str, float]]] = [
    (r"brother|canon|epson|xerox|lexmark|kyocera|ricoh|konica", {"printer": 3}),
    (r"hewlett packard|\bhp\b", {"printer": 1.5, "pc": 1.5}),
    (r"hikvision|dahua|axis communications|hanwha|uniview", {"camera": 3}),
    (r"polycom|yealink|grandstream|avaya|mitel|snom", {"phone": 3}),
    (r"apple", {"phone": 1.5, "pc": 1.5}),
    (r"samsung|xiaomi|oneplus|huawei device", {"phone": 2}),
    (r"aruba|ubiquiti|ruckus|meraki", {"access_point": 2.5, "network_device": 1}),
    (r"cisco", {"network_device": 2, "phone": 0.5}),
    (r"juniper|routerboard|mikrotik|fortinet|netgear|tp-link", {"network_device": 2}),
    (r"dell|lenovo|intel corporate|asustek|acer|micro-star", {"pc": 2.5}),
    (r"vmware|virtualbox|hyper-v|qemu", {"server_vm": 3}),
    (r"raspberry pi", {"server_vm": 1.5}),
]

# Words in a subnet name or VLAN description → points.
NETWORK_HINTS: list[tuple[str, dict[str, float]]] = [
    (r"print", {"printer": 2}),
    (r"phone|voice|voip", {"phone": 2}),
    (r"cctv|camera|\bcam", {"camera": 2}),
    (r"wi-?fi|wireless|wlan|guest", {"phone": 1, "pc": 0.5}),
    (r"staff|office|student|desk", {"pc": 1}),
    (r"\blab|server|\bvm|datacent", {"server_vm": 1, "pc": 0.5}),
    (r"manage|mgmt|infra", {"network_device": 1}),
]

PORT_HINTS: dict[int, tuple[dict[str, float], str]] = {
    9100: ({"printer": 3}, "raw printing (9100)"),
    515: ({"printer": 2}, "LPD printing (515)"),
    631: ({"printer": 2}, "IPP printing (631)"),
    554: ({"camera": 3}, "video streaming RTSP (554)"),
    5060: ({"phone": 3}, "VoIP SIP (5060)"),
    3389: ({"pc": 2}, "Windows Remote Desktop (3389)"),
    445: ({"pc": 1.5}, "Windows file sharing (445)"),
    22: ({"server_vm": 1, "network_device": 0.5}, "SSH (22)"),
}
PROBE_PORTS = tuple(PORT_HINTS)

LABELS = {
    "pc": "PC or laptop", "printer": "printer", "phone": "phone", "camera": "camera",
    "access_point": "access point", "network_device": "network device",
    "server_vm": "server or VM", "unknown": "unknown",
}


@dataclass
class Result:
    type: str
    confidence: float
    reasons: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"type": self.type, "confidence": self.confidence, "reasons": self.reasons[:8]}


def _add(scores: dict[str, float], hints: dict[str, float]) -> None:
    for kind, points in hints.items():
        scores[kind] = scores.get(kind, 0.0) + points


def _best(scores: dict[str, float]) -> str:
    return max(scores, key=lambda kind: (scores[kind], -TYPES.index(kind)))


def classify(endpoint: dict, oui: OuiTable, open_ports: list[int] | None = None) -> Result:
    """endpoint: {mac, managed: {vendor, sys_descr} | None, network_labels: [..],
    seen_on_wireless: bool}. All of it is device data: treated as plain text."""
    scores: dict[str, float] = {}
    reasons: list[str] = []
    managed = endpoint.get("managed")
    if managed:
        text = f"{managed.get('vendor') or ''} {managed.get('sys_descr') or ''}".lower()
        if re.search(r"access point|wireless|\bap\b|aruba|ubiquiti|unifi", text):
            _add(scores, {"access_point": 5})
            reasons.append("Managed by NetMap over SNMP; its description says access point")
        else:
            _add(scores, {"network_device": 5})
            reasons.append("Managed by NetMap over SNMP (switch or router)")

    mac = endpoint.get("mac") or ""
    vendor = oui.vendor(mac)
    if vendor:
        lowered = vendor.lower()
        for pattern, hints in VENDOR_HINTS:
            if re.search(pattern, lowered):
                _add(scores, hints)
                reasons.append(f"Manufacturer from MAC address: {vendor}")
                break
        else:
            reasons.append(f"Manufacturer from MAC address: {vendor} (no type hint)")
    elif is_private(mac) and not mac.lower().startswith("52:54:00"):
        _add(scores, {"phone": 1.5, "pc": 1})
        reasons.append("Randomised (private) MAC address, as phones and laptops use on Wi-Fi")

    for label in endpoint.get("network_labels") or []:
        lowered = str(label).lower()[:120]
        for pattern, hints in NETWORK_HINTS:
            if re.search(pattern, lowered):
                _add(scores, hints)
                reasons.append(f"On network “{str(label)[:60]}”")
                break

    if endpoint.get("seen_on_wireless") and not managed:
        _add(scores, {"phone": 1, "pc": 0.5})
        reasons.append("Connected through a wireless access point")

    for port in sorted(set(open_ports or [])):
        if port in PORT_HINTS:
            hints, what = PORT_HINTS[port]
            _add(scores, hints)
            reasons.append(f"Open port: {what}")

    if not scores or max(scores.values()) < MIN_SCORE:
        return Result("unknown", 0.0, reasons or ["No clue about this device yet"])
    best = _best(scores)
    total = sum(scores.values())
    return Result(best, round(scores[best] / total, 2), reasons)
