"""A small simulated campus network, used to generate snmpsim data files.

Everything here is made up for demos and tests:
- IPv4 uses private 10.10.0.0/16 plus 203.0.113.0/24 (RFC 5737 documentation range) for the WAN
- IPv6 uses 2001:db8::/32 (RFC 3849 documentation range)
- sysObjectIDs use each vendor's real IANA enterprise number with illustrative product suffixes
- MAC prefixes use OUIs registered to the matching vendor, so device-type classification
  (Phase 7) has realistic input; the rest of each MAC is invented

Each device listens on its own loopback address (127.0.0.11-15, UDP 1161) when simulated.
"""

from dataclasses import dataclass, field

SIM_PORT = 1161


@dataclass
class Iface:
    index: int
    name: str
    descr: str
    if_type: int  # 6 ethernet, 24 loopback, 53 virtual (VLAN SVI), 71 wifi
    speed_mbps: int
    mac: str
    alias: str = ""
    admin_up: bool = True
    oper_up: bool = True
    ipv4: list[str] = field(default_factory=list)  # "a.b.c.d/len"
    ipv6: list[str] = field(default_factory=list)  # "x::y/len"


@dataclass
class Neighbor:
    if_index: int
    ip: str
    mac: str


@dataclass
class SimDevice:
    slug: str
    listen: str
    sys_name: str
    sys_descr: str
    sys_object_id: str
    sys_location: str
    uptime_seconds: int
    interfaces: list[Iface]
    neighbors: list[Neighbor] = field(default_factory=list)


def _endpoints(vlan_if: int, subnet: str, oui: str, start: int, count: int) -> list[Neighbor]:
    base = subnet.rsplit(".", 1)[0]
    return [
        Neighbor(vlan_if, f"{base}.{start + i}",
                 f"{oui}:{0x10 + vlan_if:02x}:{0x20:02x}:{start + i:02x}")
        for i in range(count)
    ]


EDGE_ROUTER = SimDevice(
    slug="edge-router",
    listen="127.0.0.11",
    sys_name="EDGE-RTR-1",
    sys_descr="Cisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.9(3)M "
              "(simulated)",
    sys_object_id="1.3.6.1.4.1.9.1.1041",
    sys_location="Main building, server room rack A",
    uptime_seconds=1_209_600,
    interfaces=[
        Iface(1, "Gi0/0", "GigabitEthernet0/0", 6, 1000, "00:00:0c:a1:00:01", "WAN to ISP",
              ipv4=["203.0.113.2/30"], ipv6=["2001:db8:ffff::2/126"]),
        Iface(2, "Gi0/1", "GigabitEthernet0/1", 6, 1000, "00:00:0c:a1:00:02", "Uplink to CORE-SW-1",
              ipv4=["10.10.0.1/30"], ipv6=["2001:db8:10::1/126"]),
        Iface(3, "Gi0/2", "GigabitEthernet0/2", 6, 1000, "00:00:0c:a1:00:03", "spare",
              admin_up=False, oper_up=False),
        Iface(4, "Lo0", "Loopback0", 24, 8000, "", "router id", ipv4=["10.10.255.1/32"]),
    ],
    neighbors=[
        Neighbor(1, "203.0.113.1", "00:00:0c:ee:00:01"),
        Neighbor(2, "10.10.0.2", "00:00:0c:c0:00:01"),
        Neighbor(2, "2001:db8:10::2", "00:00:0c:c0:00:01"),
    ],
)

CORE_SWITCH = SimDevice(
    slug="core-switch",
    listen="127.0.0.12",
    sys_name="CORE-SW-1",
    sys_descr="Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), "
              "Version 17.9.4 (simulated)",
    sys_object_id="1.3.6.1.4.1.9.1.2494",
    sys_location="Main building, server room rack A",
    uptime_seconds=3_456_000,
    interfaces=[
        Iface(1, "Gi1/0/1", "GigabitEthernet1/0/1", 6, 1000, "00:00:0c:c0:00:01",
              "Uplink to EDGE-RTR-1", ipv4=["10.10.0.2/30"], ipv6=["2001:db8:10::2/126"]),
        Iface(2, "Gi1/0/2", "GigabitEthernet1/0/2", 6, 1000, "00:00:0c:c0:00:02",
              "Trunk to ACCESS-SW-1"),
        Iface(3, "Gi1/0/3", "GigabitEthernet1/0/3", 6, 1000, "00:00:0c:c0:00:03",
              "Trunk to ACCESS-SW-2"),
        Iface(4, "Gi1/0/4", "GigabitEthernet1/0/4", 6, 1000, "00:00:0c:c0:00:04", "AP-1 uplink"),
        Iface(10, "Vl10", "Vlan10", 53, 1000, "00:00:0c:c0:10:00", "Staff",
              ipv4=["10.10.10.1/24"], ipv6=["2001:db8:10:10::1/64"]),
        Iface(20, "Vl20", "Vlan20", 53, 1000, "00:00:0c:c0:20:00", "Students and labs",
              ipv4=["10.10.20.1/24"], ipv6=["2001:db8:10:20::1/64"]),
        Iface(30, "Vl30", "Vlan30", 53, 1000, "00:00:0c:c0:30:00", "Printers and phones",
              ipv4=["10.10.30.1/24"]),
        Iface(99, "Vl99", "Vlan99", 53, 1000, "00:00:0c:c0:99:00", "Network management",
              ipv4=["10.10.99.1/24"]),
    ],
    neighbors=[
        Neighbor(1, "10.10.0.1", "00:00:0c:a1:00:02"),
        *_endpoints(10, "10.10.10.0", "00:14:22", 20, 6),   # staff PCs (Dell)
        *_endpoints(20, "10.10.20.0", "00:50:56", 50, 8),   # lab VMs (VMware)
        *_endpoints(30, "10.10.30.0", "3c:d9:2b", 10, 3),   # printers (HP)
        Neighbor(99, "10.10.99.11", "3c:d9:2b:99:00:11"),   # ACCESS-SW-1
        Neighbor(99, "10.10.99.12", "4c:5e:0c:99:00:12"),   # ACCESS-SW-2
        Neighbor(99, "10.10.99.21", "00:0b:86:99:00:21"),   # AP-1
        Neighbor(10, "2001:db8:10:10::20", "00:14:22:1a:20:14"),
        Neighbor(10, "2001:db8:10:10::21", "00:14:22:1a:20:15"),
        Neighbor(20, "2001:db8:10:20::50", "00:50:56:24:20:32"),
    ],
)

ACCESS_SW_1 = SimDevice(
    slug="access-sw-1",
    listen="127.0.0.13",
    sys_name="ACCESS-SW-1",
    sys_descr="HP J9774A 2530-8G-PoEP Switch, revision YA.16.10.0019 (simulated)",
    sys_object_id="1.3.6.1.4.1.11.2.3.7.11.172",
    sys_location="Main building, floor 1, IDF cabinet",
    uptime_seconds=864_000,
    interfaces=[
        *[Iface(i, str(i), f"{i}", 6, 1000, f"3c:d9:2b:99:01:{i:02x}", f"Desk port {i}",
                oper_up=i <= 5) for i in range(1, 9)],
        Iface(9, "9", "9", 6, 1000, "3c:d9:2b:99:01:09", "Uplink to CORE-SW-1"),
        Iface(99, "VLAN99", "DEFAULT_VLAN99", 53, 1000, "3c:d9:2b:99:00:11", "Management",
              ipv4=["10.10.99.11/24"]),
    ],
    neighbors=[Neighbor(99, "10.10.99.1", "00:00:0c:c0:99:00")],
)

ACCESS_SW_2 = SimDevice(
    slug="access-sw-2",
    listen="127.0.0.14",
    sys_name="ACCESS-SW-2",
    sys_descr="RouterOS CRS326-24G-2S+ 7.14 (simulated)",
    sys_object_id="1.3.6.1.4.1.14988.1",
    sys_location="Lab building, floor 2, comms room",
    uptime_seconds=432_000,
    interfaces=[
        *[Iface(i, f"ether{i}", f"ether{i}", 6, 1000, f"4c:5e:0c:99:02:{i:02x}", f"Lab bench {i}",
                oper_up=i <= 6) for i in range(1, 9)],
        Iface(25, "sfp-sfpplus1", "sfp-sfpplus1", 6, 10000, "4c:5e:0c:99:02:19",
              "Uplink to CORE-SW-1"),
        Iface(99, "vlan99", "vlan99", 53, 1000, "4c:5e:0c:99:00:12", "Management",
              ipv4=["10.10.99.12/24"]),
    ],
    neighbors=[Neighbor(99, "10.10.99.1", "00:00:0c:c0:99:00")],
)

AP_1 = SimDevice(
    slug="ap-1",
    listen="127.0.0.15",
    sys_name="AP-1-LIBRARY",
    sys_descr="ArubaOS (MODEL: 515), Version 8.10.0.10 (simulated)",
    sys_object_id="1.3.6.1.4.1.14823.1.2.95",
    sys_location="Library, ground floor ceiling",
    uptime_seconds=172_800,
    interfaces=[
        Iface(1, "bond0", "Ethernet uplink", 6, 1000, "00:0b:86:99:00:21", "Uplink to CORE-SW-1",
              ipv4=["10.10.99.21/24"]),
        Iface(2, "wifi0", "Radio 5 GHz", 71, 1200, "00:0b:86:99:50:00", "campus-5g"),
        Iface(3, "wifi1", "Radio 2.4 GHz", 71, 300, "00:0b:86:99:24:00", "campus-2g"),
    ],
    neighbors=[Neighbor(1, "10.10.99.1", "00:00:0c:c0:99:00")],
)

DEVICES = [EDGE_ROUTER, CORE_SWITCH, ACCESS_SW_1, ACCESS_SW_2, AP_1]
