"""SNMP OIDs and pure parsers for table indexes.

SNMP tables encode the row key inside the OID. For example an ipAddressTable row for
192.168.1.10 has the index  1.4.192.168.1.10  (type=ipv4, length=4, then the 4 octets).
These functions turn those index tuples back into addresses. They do no network I/O, so every
case (IPv4, IPv6, zoned addresses, both MIB generations) is unit-tested.
"""

import ipaddress
from dataclasses import dataclass

# SNMPv2-MIB system group (scalars, ".0" instance)
SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
SYSTEM_SCALARS = (SYS_DESCR, SYS_OBJECT_ID, SYS_UPTIME, SYS_NAME, SYS_LOCATION)

# IF-MIB ifTable / ifXTable columns (index = ifIndex)
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_TYPE = "1.3.6.1.2.1.2.2.1.3"
IF_MTU = "1.3.6.1.2.1.2.2.1.4"
IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
IF_PHYS_ADDRESS = "1.3.6.1.2.1.2.2.1.6"
IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"  # Mbit/s
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"

# IP-MIB ipAddressTable (RFC 4293, IPv4 + IPv6). Index = addrType.len.addr
IP_ADDRESS_IFINDEX = "1.3.6.1.2.1.4.34.1.3"
IP_ADDRESS_TYPE = "1.3.6.1.2.1.4.34.1.4"  # 1 unicast, 2 anycast, 3 broadcast
IP_ADDRESS_PREFIX = "1.3.6.1.2.1.4.34.1.5"  # pointer into ipAddressPrefixTable
# Older ipAddrTable (IPv4 only). Index = the 4 octets of the address
IP_ADENT_IFINDEX = "1.3.6.1.2.1.4.20.1.2"
IP_ADENT_NETMASK = "1.3.6.1.2.1.4.20.1.3"

# IP-MIB ipNetToPhysicalTable (ARP + IPv6 neighbours). Index = ifIndex.addrType.len.addr
IP_NET_TO_PHYS_ADDRESS = "1.3.6.1.2.1.4.35.1.4"
IP_NET_TO_PHYS_TYPE = "1.3.6.1.2.1.4.35.1.6"  # 1 other, 2 invalid, 3 dynamic, 4 static, 5 local
# Older ipNetToMediaTable (IPv4 ARP only). Index = ifIndex.a.b.c.d
IP_NET_TO_MEDIA_PHYS_ADDRESS = "1.3.6.1.2.1.4.22.1.2"
IP_NET_TO_MEDIA_TYPE = "1.3.6.1.2.1.4.22.1.4"  # 1 other, 2 invalid, 3 dynamic, 4 static

IF_STATUS = {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "notPresent",
             7: "lowerLayerDown"}
NEIGHBOR_TYPE = {1: "other", 2: "invalid", 3: "dynamic", 4: "static", 5: "local"}

# InetAddressType values (RFC 4001)
_IPV4, _IPV6, _IPV4Z, _IPV6Z = 1, 2, 3, 4


class OidIndexError(ValueError):
    """An OID index that doesn't describe a valid address."""


@dataclass(frozen=True)
class InetIndex:
    address: str
    version: int
    remainder: tuple[int, ...]  # sub-ids after the address (e.g. a prefix length)


def suffix(oid: str, column: str) -> tuple[int, ...]:
    """The index part of a full OID, e.g. suffix("1.3.6.1.2.1.2.2.1.2.7", IF_DESCR) == (7,)."""
    prefix = column + "."
    if not oid.startswith(prefix):
        raise OidIndexError(f"{oid} is not under {column}")
    return tuple(int(p) for p in oid[len(prefix):].split("."))


def _octets(values: tuple[int, ...]) -> bytes:
    if any(not 0 <= v <= 255 for v in values):
        raise OidIndexError("octet out of range")
    return bytes(values)


def parse_inet_index(index: tuple[int, ...]) -> InetIndex:
    """Parse InetAddressType + length-prefixed InetAddress from the start of an index."""
    if len(index) < 2:
        raise OidIndexError("index too short")
    addr_type, length = index[0], index[1]
    raw = index[2 : 2 + length]
    if len(raw) != length:
        raise OidIndexError("index shorter than its declared length")
    octets = _octets(raw)
    if addr_type == _IPV4 and length == 4:
        address, version = ipaddress.IPv4Address(octets), 4
    elif addr_type == _IPV6 and length == 16:
        address, version = ipaddress.IPv6Address(octets), 6
    elif addr_type == _IPV4Z and length == 8:  # 4 address bytes + 4-byte zone index
        address, version = ipaddress.IPv4Address(octets[:4]), 4
    elif addr_type == _IPV6Z and length == 20:
        address, version = ipaddress.IPv6Address(octets[:16]), 6
    else:
        raise OidIndexError(f"unsupported address type {addr_type} with length {length}")
    return InetIndex(str(address), version, index[2 + length :])


def parse_ipv4_index(index: tuple[int, ...]) -> str:
    """ipAddrTable index: exactly the four octets of an IPv4 address."""
    if len(index) != 4:
        raise OidIndexError("IPv4 index must have 4 octets")
    return str(ipaddress.IPv4Address(_octets(index)))


def parse_address_index(oid: str, column: str) -> InetIndex:
    """ipAddressTable row → address."""
    return parse_inet_index(suffix(oid, column))


def parse_prefix_pointer(pointer: str) -> int | None:
    """ipAddressPrefix points at ipAddressPrefixTable.<column>.ifIndex.type.len.addr.prefixLen.

    The prefix length is the last sub-id. "0.0" (no prefix) and malformed pointers give None.
    """
    parts = pointer.strip().split(".")
    if len(parts) < 4 or pointer.strip() in ("0.0", ".0.0"):
        return None
    try:
        length = int(parts[-1])
    except ValueError:
        return None
    return length if 0 <= length <= 128 else None


def netmask_to_prefix(netmask: str) -> int | None:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
    except ValueError:
        return None  # non-contiguous or invalid masks are ignored


def parse_net_to_physical_index(oid: str, column: str) -> tuple[int, InetIndex]:
    """ipNetToPhysicalTable row → (ifIndex, address)."""
    index = suffix(oid, column)
    if len(index) < 3:
        raise OidIndexError("index too short")
    return index[0], parse_inet_index(index[1:])


def parse_net_to_media_index(oid: str, column: str) -> tuple[int, str]:
    """ipNetToMediaTable row → (ifIndex, IPv4 address)."""
    index = suffix(oid, column)
    if len(index) != 5:
        raise OidIndexError("ipNetToMedia index must be ifIndex + 4 octets")
    return index[0], parse_ipv4_index(index[1:])


# ---- Phase 5: neighbours (LLDP, CDP), MAC tables (BRIDGE / Q-BRIDGE), traffic counters -------

# LLDP-MIB (IEEE 802.1AB) lldpRemTable. Index = timeMark.localPortNum.remIndex
LLDP_REM_CHASSIS_SUBTYPE = "1.0.8802.1.1.2.1.4.1.1.4"
LLDP_REM_CHASSIS_ID = "1.0.8802.1.1.2.1.4.1.1.5"
LLDP_REM_PORT_SUBTYPE = "1.0.8802.1.1.2.1.4.1.1.6"
LLDP_REM_PORT_ID = "1.0.8802.1.1.2.1.4.1.1.7"
LLDP_REM_PORT_DESC = "1.0.8802.1.1.2.1.4.1.1.8"
LLDP_REM_SYS_NAME = "1.0.8802.1.1.2.1.4.1.1.9"
# lldpRemManAddrTable. Index = timeMark.localPortNum.remIndex.addrSubtype.addrLen.addr
LLDP_REM_MAN_ADDR_IF_SUBTYPE = "1.0.8802.1.1.2.1.4.2.1.3"
# lldpLocPortTable. Index = localPortNum (not always the ifIndex)
LLDP_LOC_PORT_ID = "1.0.8802.1.1.2.1.3.7.1.3"
LLDP_LOC_PORT_DESC = "1.0.8802.1.1.2.1.3.7.1.4"

# CISCO-CDP-MIB cdpCacheTable. Index = ifIndex.deviceIndex
CDP_CACHE_ADDRESS_TYPE = "1.3.6.1.4.1.9.9.23.1.2.1.1.3"  # 1 = ip
CDP_CACHE_ADDRESS = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"
CDP_CACHE_DEVICE_ID = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
CDP_CACHE_DEVICE_PORT = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
CDP_CACHE_PLATFORM = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"

# BRIDGE-MIB: bridge port number -> ifIndex, and the VLAN-unaware forwarding table
DOT1D_BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"  # index = bridge port
DOT1D_TP_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"  # index = 6 MAC octets
DOT1D_TP_FDB_STATUS = "1.3.6.1.2.1.17.4.3.1.3"
# Q-BRIDGE-MIB: VLAN-aware forwarding table. Index = fdbId.mac (fdbId is the VLAN on most
# switches, which use one forwarding database per VLAN)
DOT1Q_TP_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"
DOT1Q_TP_FDB_STATUS = "1.3.6.1.2.1.17.7.1.2.2.1.3"
FDB_STATUS = {1: "other", 2: "invalid", 3: "learned", 4: "self", 5: "mgmt"}

# IF-MIB traffic counters. HC = 64-bit (ifXTable); the 32-bit ones wrap after 4 GB.
IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"
IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"
IF_IN_OCTETS = "1.3.6.1.2.1.2.2.1.10"
IF_OUT_OCTETS = "1.3.6.1.2.1.2.2.1.16"
IF_IN_ERRORS = "1.3.6.1.2.1.2.2.1.14"
IF_OUT_ERRORS = "1.3.6.1.2.1.2.2.1.20"

# LldpChassisIdSubtype / LldpPortIdSubtype values that hold a MAC or a network address
_CHASSIS_MAC, _CHASSIS_NETWORK = 4, 5
_PORT_MAC, _PORT_NETWORK = 3, 4
# IANA AddressFamilyNumbers, used by LLDP management addresses
_FAMILY_IPV4, _FAMILY_IPV6 = 1, 2


def parse_lldp_rem_index(index: tuple[int, ...]) -> tuple[int, int]:
    """lldpRemTable index → (localPortNum, remIndex). The timeMark is ignored."""
    if len(index) != 3:
        raise OidIndexError("lldpRemTable index must be timeMark.localPortNum.remIndex")
    return index[1], index[2]


def parse_lldp_man_addr_index(index: tuple[int, ...]) -> tuple[int, int, str]:
    """lldpRemManAddrTable index → (localPortNum, remIndex, management IP)."""
    if len(index) < 5:
        raise OidIndexError("index too short")
    family, length = index[3], index[4]
    raw = index[5:]
    if len(raw) != length:
        raise OidIndexError("address length doesn't match")
    if family == _FAMILY_IPV4 and length == 4:
        address = str(ipaddress.IPv4Address(_octets(raw)))
    elif family == _FAMILY_IPV6 and length == 16:
        address = str(ipaddress.IPv6Address(_octets(raw)))
    else:
        raise OidIndexError(f"unsupported management address family {family}")
    return index[1], index[2], address


def parse_mac_index(index: tuple[int, ...]) -> str:
    """A MAC address encoded as 6 sub-ids (dot1dTpFdbTable index)."""
    if len(index) != 6:
        raise OidIndexError("MAC index must have 6 octets")
    return ":".join(f"{b:02x}" for b in _octets(index))


def parse_qbridge_fdb_index(index: tuple[int, ...]) -> tuple[int, str]:
    """dot1qTpFdbTable index → (fdbId, MAC)."""
    if len(index) != 7:
        raise OidIndexError("dot1qTpFdb index must be fdbId + 6 MAC octets")
    return index[0], parse_mac_index(index[1:])


def parse_cdp_index(index: tuple[int, ...]) -> tuple[int, int]:
    """cdpCacheTable index → (ifIndex, deviceIndex)."""
    if len(index) != 2:
        raise OidIndexError("cdpCache index must be ifIndex.deviceIndex")
    return index[0], index[1]


def _printable(raw: bytes) -> str | None:
    text = raw.decode("utf-8", errors="replace")
    text = "".join(ch if ch.isprintable() else " " for ch in text).strip()
    return text[:255] or None


def _network_address(raw: bytes) -> str | None:
    """IANA family byte + address bytes (LLDP 'networkAddress' subtype)."""
    if len(raw) == 5 and raw[0] == _FAMILY_IPV4:
        return str(ipaddress.IPv4Address(raw[1:]))
    if len(raw) == 17 and raw[0] == _FAMILY_IPV6:
        return str(ipaddress.IPv6Address(raw[1:]))
    return None


def lldp_chassis_id(subtype: int | None, raw: bytes) -> str | None:
    """Render an LLDP chassis ID: a MAC as aa:bb:.., an address as text, anything else as text."""
    if subtype == _CHASSIS_MAC and len(raw) == 6:
        return ":".join(f"{b:02x}" for b in raw)
    if subtype == _CHASSIS_NETWORK:
        return _network_address(raw) or raw.hex()
    return _printable(raw)


def lldp_port_id(subtype: int | None, raw: bytes) -> str | None:
    if subtype == _PORT_MAC and len(raw) == 6:
        return ":".join(f"{b:02x}" for b in raw)
    if subtype == _PORT_NETWORK:
        return _network_address(raw) or raw.hex()
    return _printable(raw)


def cdp_address(address_type: int | None, raw: bytes) -> str | None:
    """cdpCacheAddress: 4 bytes for IPv4 when cdpCacheAddressType is ip(1)."""
    if address_type == 1 and len(raw) == 4:
        return str(ipaddress.IPv4Address(raw))
    return None
