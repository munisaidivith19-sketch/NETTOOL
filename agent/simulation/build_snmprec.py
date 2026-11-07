"""Generate snmpsim data files (simulation/data/<device>/netmap-sim.snmprec) from topology.py.

Run from the agent folder:  python -m simulation.build_snmprec

.snmprec format, one line per OID:  OID|TYPE|VALUE
  2 Integer  4 OctetString  4x OctetString as hex  6 ObjectIdentifier  64 IpAddress
  65 Counter32  66 Gauge32  67 TimeTicks
The file name ("netmap-sim") is the SNMPv2c community and the SNMPv3 context name.
"""

import ipaddress
from pathlib import Path

from simulation.topology import DEVICES, Iface, SimDevice

DATA_DIR = Path(__file__).with_name("data")
DATA_FILE = "netmap-sim.snmprec"
GAUGE_MAX = 4_294_967_295


def _hex(mac: str) -> str:
    return mac.replace(":", "")


def _inet_index(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """InetAddressType.length.octets, as used by ipAddressTable and ipNetToPhysicalTable."""
    raw = address.packed
    addr_type = 1 if address.version == 4 else 2
    return ".".join(str(x) for x in (addr_type, len(raw), *raw))


def _records(device: SimDevice) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = [
        ("1.3.6.1.2.1.1.1.0", "4", device.sys_descr),
        ("1.3.6.1.2.1.1.2.0", "6", device.sys_object_id),
        ("1.3.6.1.2.1.1.3.0", "67", str(device.uptime_seconds * 100)),
        ("1.3.6.1.2.1.1.4.0", "4", "netops@campus.example"),
        ("1.3.6.1.2.1.1.5.0", "4", device.sys_name),
        ("1.3.6.1.2.1.1.6.0", "4", device.sys_location),
        ("1.3.6.1.2.1.2.1.0", "2", str(len(device.interfaces))),
    ]
    for iface in device.interfaces:
        rows += _interface_rows(iface)
    for iface in device.interfaces:
        for cidr in iface.ipv4 + iface.ipv6:
            rows += _address_rows(iface, ipaddress.ip_interface(cidr))
    for n in device.neighbors:
        address = ipaddress.ip_address(n.ip)
        index = f"{n.if_index}.{_inet_index(address)}"
        rows += [
            (f"1.3.6.1.2.1.4.35.1.4.{index}", "4x", _hex(n.mac)),
            (f"1.3.6.1.2.1.4.35.1.6.{index}", "2", "3"),  # dynamic
            (f"1.3.6.1.2.1.4.35.1.7.{index}", "2", "1"),  # reachable
        ]
        if address.version == 4:  # the older ARP table has IPv4 only
            media = f"{n.if_index}.{address}"
            rows += [
                (f"1.3.6.1.2.1.4.22.1.2.{media}", "4x", _hex(n.mac)),
                (f"1.3.6.1.2.1.4.22.1.4.{media}", "2", "3"),
            ]
    return rows


def _interface_rows(iface: Iface) -> list[tuple[str, str, str]]:
    i = iface.index
    return [
        (f"1.3.6.1.2.1.2.2.1.1.{i}", "2", str(i)),
        (f"1.3.6.1.2.1.2.2.1.2.{i}", "4", iface.descr),
        (f"1.3.6.1.2.1.2.2.1.3.{i}", "2", str(iface.if_type)),
        (f"1.3.6.1.2.1.2.2.1.4.{i}", "2", "1500"),
        (f"1.3.6.1.2.1.2.2.1.5.{i}", "66", str(min(GAUGE_MAX, iface.speed_mbps * 1_000_000))),
        (f"1.3.6.1.2.1.2.2.1.6.{i}", "4x", _hex(iface.mac)),
        (f"1.3.6.1.2.1.2.2.1.7.{i}", "2", "1" if iface.admin_up else "2"),
        (f"1.3.6.1.2.1.2.2.1.8.{i}", "2", "1" if iface.oper_up else "2"),
        (f"1.3.6.1.2.1.31.1.1.1.1.{i}", "4", iface.name),
        (f"1.3.6.1.2.1.31.1.1.1.15.{i}", "66", str(iface.speed_mbps)),
        (f"1.3.6.1.2.1.31.1.1.1.18.{i}", "4", iface.alias),
    ]


def _address_rows(iface: Iface, address: ipaddress.IPv4Interface | ipaddress.IPv6Interface):
    index = _inet_index(address.ip)
    network = address.network
    prefix_pointer = (f"1.3.6.1.2.1.4.32.1.5.{iface.index}.{_inet_index(network.network_address)}"
                      f".{network.prefixlen}")
    rows = [
        (f"1.3.6.1.2.1.4.34.1.3.{index}", "2", str(iface.index)),
        (f"1.3.6.1.2.1.4.34.1.4.{index}", "2", "1"),  # unicast
        (f"1.3.6.1.2.1.4.34.1.5.{index}", "6", prefix_pointer),
    ]
    if address.version == 4:  # the older ipAddrTable has IPv4 only
        rows += [
            (f"1.3.6.1.2.1.4.20.1.2.{address.ip}", "2", str(iface.index)),
            (f"1.3.6.1.2.1.4.20.1.3.{address.ip}", "64", str(network.netmask)),
        ]
    return rows


def _oid_key(oid: str) -> tuple[int, ...]:
    return tuple(int(p) for p in oid.split("."))


def build(data_dir: Path = DATA_DIR) -> list[Path]:
    written = []
    for device in DEVICES:
        rows = sorted(_records(device), key=lambda r: _oid_key(r[0]))
        target = data_dir / device.slug / DATA_FILE
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("".join(f"{o}|{t}|{v}\n" for o, t, v in rows), encoding="utf-8",
                          newline="\n")
        written.append(target)
    return written


if __name__ == "__main__":
    for path in build():
        print(f"wrote {path}")
