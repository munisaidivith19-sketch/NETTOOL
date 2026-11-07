"""The CLAUDE.md section 5 storage rule for IP addresses.

Every address is stored with  ip_key = "<version>:<32 hex digits of the integer value>".
Fixed-width hex makes string order equal numeric order, and the "4:"/"6:" prefix keeps the two
families apart, so "every IP in this subnet" is a simple range query:
    {"ip_key": {"$gte": start_key, "$lte": end_key}}
"""

import ipaddress

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def ip_key(address: str | IPAddress) -> str:
    addr = ipaddress.ip_address(address)
    return f"{addr.version}:{int(addr):032x}"


def network_key_range(network: str | IPNetwork) -> tuple[str, str]:
    """(first, last) ip_key of a network, inclusive of the network and broadcast addresses."""
    net = ipaddress.ip_network(network, strict=False)
    return ip_key(net.network_address), ip_key(net.broadcast_address)


def network_of(address: str | IPAddress, prefixlen: int) -> IPNetwork:
    return ipaddress.ip_network(f"{ipaddress.ip_address(address)}/{prefixlen}", strict=False)
