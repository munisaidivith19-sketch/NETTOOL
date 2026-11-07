"""Generate snmpsim data files (simulation/data/<device>/netmap-sim.snmprec) from topology.py.

Run from the agent folder:  python -m simulation.build_snmprec

.snmprec format, one line per OID:  OID|TYPE|VALUE
  2 Integer  4 OctetString  4x OctetString as hex  6 ObjectIdentifier  64 IpAddress
  65 Counter32  66 Gauge32  67 TimeTicks  70 Counter64
A "65:numeric" / "70:numeric" type uses snmpsim's numeric variation module: the value is
initial + rate * (seconds since snmpsim started), so traffic counters grow while you watch.
The file name ("netmap-sim") is the SNMPv2c community and the SNMPv3 context name.
"""

import ipaddress
from pathlib import Path

from simulation.topology import CABLES, DEVICES, EXTERNAL_NEIGHBORS, Iface, SimDevice

DATA_DIR = Path(__file__).with_name("data")
DATA_FILE = "netmap-sim.snmprec"
GAUGE_MAX = 4_294_967_295
LLDP_REM = "1.0.8802.1.1.2.1.4.1.1"
LLDP_MAN_ADDR = "1.0.8802.1.1.2.1.4.2.1"
LLDP_LOC_PORT = "1.0.8802.1.1.2.1.3.7.1"
CDP_CACHE = "1.3.6.1.4.1.9.9.23.1.2.1.1"


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
    rows += _neighbor_protocol_rows(device)
    rows += _fdb_rows(device)
    rows += _counter_rows(device)
    return rows


def _ipv4_dotted(ip: str) -> str:
    return ".".join(str(b) for b in ipaddress.IPv4Address(ip).packed)


def _neighbor_protocol_rows(device: SimDevice) -> list[tuple[str, str, str]]:
    """LLDP-MIB and CISCO-CDP-MIB rows for every cable end (and external neighbour)."""
    rows = []
    lldp_peers = []  # (local ifIndex, sys name, port id, port descr, chassis MAC, mgmt IP)
    for cable in CABLES:
        for local, local_if, remote, remote_if in ((cable.a, cable.a_if, cable.b, cable.b_if),
                                                   (cable.b, cable.b_if, cable.a, cable.a_if)):
            if local is not device:
                continue
            port = remote.iface(remote_if)
            if cable.protocol == "lldp":
                lldp_peers.append((local_if, remote.sys_name, port.name, port.alias,
                                   remote.chassis_mac, remote.mgmt_ip))
            else:
                # CDP announces the address of the far interface on this link if it has one.
                address = (port.ipv4[0].split("/")[0] if port.ipv4 else remote.mgmt_ip)
                index = f"{local_if}.1"
                rows += [
                    (f"{CDP_CACHE}.3.{index}", "2", "1"),  # address type ip
                    (f"{CDP_CACHE}.4.{index}", "4x", ipaddress.IPv4Address(address).packed.hex()),
                    (f"{CDP_CACHE}.6.{index}", "4", remote.sys_name),
                    (f"{CDP_CACHE}.7.{index}", "4", port.descr),
                    (f"{CDP_CACHE}.8.{index}", "4", remote.platform),
                ]
    for ext in EXTERNAL_NEIGHBORS:
        if ext.device is device:
            lldp_peers.append((ext.if_index, ext.sys_name, ext.port, "", ext.chassis_mac,
                               ext.mgmt_ip))
    if not lldp_peers:
        return rows

    for iface in device.interfaces:  # lldpLocPortTable: the device's own LLDP port numbers
        if iface.if_type != 6:
            continue
        num = device.lldp_ports.get(iface.index, iface.index)
        rows += [
            (f"{LLDP_LOC_PORT}.2.{num}", "2", "5"),  # port id subtype: interfaceName
            (f"{LLDP_LOC_PORT}.3.{num}", "4", iface.name),
            (f"{LLDP_LOC_PORT}.4.{num}", "4", iface.descr),
        ]
    for local_if, sys_name, port_id, port_descr, chassis, mgmt_ip in lldp_peers:
        index = f"0.{device.lldp_ports.get(local_if, local_if)}.1"  # timeMark.port.remIndex
        rows += [
            (f"{LLDP_REM}.4.{index}", "2", "4"),  # chassis id subtype: macAddress
            (f"{LLDP_REM}.5.{index}", "4x", _hex(chassis)),
            (f"{LLDP_REM}.6.{index}", "2", "5"),  # port id subtype: interfaceName
            (f"{LLDP_REM}.7.{index}", "4", port_id),
            (f"{LLDP_REM}.8.{index}", "4", port_descr),
            (f"{LLDP_REM}.9.{index}", "4", sys_name),
            (f"{LLDP_MAN_ADDR}.3.{index}.1.4.{_ipv4_dotted(mgmt_ip)}", "2", "2"),  # ifIndex
        ]
    return rows


def _fdb_rows(device: SimDevice) -> list[tuple[str, str, str]]:
    """BRIDGE-MIB / Q-BRIDGE-MIB MAC address tables."""
    if not device.fdb_mib:
        return []
    rows = []
    for iface in device.interfaces:  # dot1dBasePortIfIndex: bridge port -> ifIndex
        if iface.if_type in (6, 71):
            port = device.bridge_ports.get(iface.index, iface.index)
            rows.append((f"1.3.6.1.2.1.17.1.4.1.2.{port}", "2", str(iface.index)))
    for entry in device.fdb:
        mac = ".".join(str(int(b, 16)) for b in entry.mac.split(":"))
        port = device.bridge_ports.get(entry.if_index, entry.if_index) if entry.if_index else 0
        if device.fdb_mib == "q-bridge":
            base, index = "1.3.6.1.2.1.17.7.1.2.2.1", f"{entry.vlan}.{mac}"
        else:
            base, index = "1.3.6.1.2.1.17.4.3.1", mac
        rows += [(f"{base}.2.{index}", "2", str(port)), (f"{base}.3.{index}", "2",
                                                          str(entry.status))]
    return rows


def _counter_rows(device: SimDevice) -> list[tuple[str, str, str]]:
    """Octet and error counters. Octets grow at a fixed rate per interface (numeric variation)."""
    rows = []
    bits = device.counter_bits
    for iface in device.interfaces:
        i = iface.index
        if iface.oper_up:
            rates = device.traffic.get(i, (2_000 + 400 * i, 1_000 + 250 * i))
        else:
            rates = (0, 0)
        if bits == 64:
            columns, tag = ("1.3.6.1.2.1.31.1.1.1.6", "1.3.6.1.2.1.31.1.1.1.10"), "70"
        else:
            columns, tag = ("1.3.6.1.2.1.2.2.1.10", "1.3.6.1.2.1.2.2.1.16"), "65"
        for column, rate in zip(columns, rates, strict=True):
            # As if the device had been counting since it booted.
            initial = (device.uptime_seconds * rate) % 2**bits
            if rate:
                rows.append((f"{column}.{i}", f"{tag}:numeric",
                             f"initial={initial},rate={rate},wrap=1"))
            else:
                rows.append((f"{column}.{i}", tag, str(initial)))
        in_errors = 17 if (device.sys_name, i) == ("ACCESS-SW-1", 5) else 0
        rows += [(f"1.3.6.1.2.1.2.2.1.14.{i}", "65", str(in_errors)),
                 (f"1.3.6.1.2.1.2.2.1.20.{i}", "65", "0")]
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
