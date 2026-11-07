"""Small, pure helpers for addresses. Everything that reaches ping or SNMP passes through here."""

import ipaddress
import re

# A ping sweep of more than this many addresses per range is refused (an IPv4 /22).
MAX_RANGE_ADDRESSES = 1024
# All ranges together. Keeps one cycle's ping list well under the backend's report limit (8192).
MAX_TOTAL_SCAN_ADDRESSES = 4096
DEFAULT_SNMP_PORT = 161

_HEX = re.compile(r"[0-9a-fA-F]")


def parse_scan_range(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    network = ipaddress.ip_network(value.strip(), strict=False)
    if network.num_addresses > MAX_RANGE_ADDRESSES:
        raise ValueError(
            f"Range {network} has {network.num_addresses} addresses; the maximum is "
            f"{MAX_RANGE_ADDRESSES} (an IPv4 /22 or an IPv6 /118). Split it into smaller ranges."
        )
    return network


def hosts_of(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> list[str]:
    if network.num_addresses == 1:
        return [str(network.network_address)]
    return [str(host) for host in network.hosts()]


def parse_target(value: str) -> tuple[str, int]:
    """Parse "host", "host:port", "[ipv6]:port" or a bare IPv6 address. Hosts must be IPs."""
    value = value.strip()
    if value.startswith("["):
        host, sep, port = value[1:].partition("]")
        port = port.lstrip(":") if sep else ""
    elif value.count(":") == 1:
        host, port = value.split(":")
    else:
        host, port = value, ""
    address = ipaddress.ip_address(host)  # raises ValueError for names and garbage
    port_number = int(port) if port else DEFAULT_SNMP_PORT
    if not 1 <= port_number <= 65535:
        raise ValueError(f"Invalid port in target {value!r}")
    return str(address), port_number


def validate_ip(value: str) -> str:
    return str(ipaddress.ip_address(value))


def normalize_mac(value: str | bytes | None) -> str | None:
    """Return a MAC as aa:bb:cc:dd:ee:ff, or None if it isn't a usable 6-byte MAC.

    Accepts raw SNMP octets (6 bytes) and text in colon, dash, dotted-Cisco or bare-hex form.
    """
    if value is None:
        return None
    if isinstance(value, bytes):
        if len(value) != 6:
            return None
        digits = value.hex()
    else:
        text = value.strip()
        if text.lower().startswith("0x"):
            text = text[2:]
        digits = "".join(_HEX.findall(text))
        if len(digits) != 12 or len(re.sub(r"[0-9a-fA-F:.\-\s]", "", text)) != 0:
            return None
    digits = digits.lower()
    if digits in ("000000000000", "ffffffffffff"):
        return None
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))
