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
