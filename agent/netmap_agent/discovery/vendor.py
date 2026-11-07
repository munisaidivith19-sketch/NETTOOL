"""Vendor detection from sysObjectID.

sysObjectID looks like 1.3.6.1.4.1.<enterprise>.<product...>. The enterprise number is assigned
by IANA to the manufacturer, so it identifies the vendor even when sysDescr is vague.
"""

ENTERPRISE_PREFIX = (1, 3, 6, 1, 4, 1)

VENDORS = {
    9: "Cisco",
    11: "HP",
    2636: "Juniper",
    8072: "Net-SNMP",
    12356: "Fortinet",
    14823: "Aruba",
    14988: "MikroTik",
    25461: "Palo Alto Networks",
    30065: "Arista",
}


def enterprise_number(sys_object_id: str | None) -> int | None:
    if not sys_object_id:
        return None
    try:
        parts = tuple(int(p) for p in sys_object_id.strip().strip(".").split("."))
    except ValueError:
        return None
    if len(parts) <= len(ENTERPRISE_PREFIX) or parts[: len(ENTERPRISE_PREFIX)] != ENTERPRISE_PREFIX:
        return None
    return parts[len(ENTERPRISE_PREFIX)]


def detect_vendor(sys_object_id: str | None) -> str:
    number = enterprise_number(sys_object_id)
    if number is None:
        return "unknown"
    return VENDORS.get(number, f"enterprise {number}")
