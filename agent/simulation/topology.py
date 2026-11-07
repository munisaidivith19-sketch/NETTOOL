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
class FdbEntry:
    """One row of a switch MAC address table: this MAC was learned on this port."""

    mac: str
    if_index: int
    vlan: int | None = None  # None on switches with only the VLAN-unaware BRIDGE-MIB table
    status: int = 3  # 3 learned, 4 self (the switch's own MAC)


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
    mgmt_ip: str = ""  # in-band address the device announces in LLDP / CDP
    platform: str = ""  # CDP platform string
    fdb_mib: str = ""  # "q-bridge" (VLAN-aware), "bridge" (BRIDGE-MIB only) or "" (no table)
    fdb: list[FdbEntry] = field(default_factory=list)
    bridge_ports: dict[int, int] = field(default_factory=dict)  # ifIndex -> bridge port number
    lldp_ports: dict[int, int] = field(default_factory=dict)  # ifIndex -> lldpLocPortNum
    counter_bits: int = 64  # 32 = only the old ifInOctets/ifOutOctets (they wrap after 4 GB)
    traffic: dict[int, tuple[int, int]] = field(default_factory=dict)  # ifIndex -> in/out B/s

    def iface(self, if_index: int) -> Iface:
        return next(i for i in self.interfaces if i.index == if_index)

    @property
    def chassis_mac(self) -> str:
        """The MAC an LLDP neighbour reports as this device's chassis ID."""
        with_mac = [i for i in self.interfaces if i.mac]  # loopbacks have no MAC
        for iface in with_mac:
            if any(c.startswith(self.mgmt_ip + "/") for c in iface.ipv4):
                return iface.mac
        return with_mac[0].mac


def _endpoints(vlan_if: int, subnet: str, oui: str, start: int, count: int) -> list[Neighbor]:
    base = subnet.rsplit(".", 1)[0]
    return [
        Neighbor(vlan_if, f"{base}.{start + i}",
                 f"{oui}:{0x10 + vlan_if:02x}:{0x20:02x}:{start + i:02x}")
        for i in range(count)
    ]


# Endpoints. Their MACs appear in the core's ARP table and in the access switches' MAC tables.
STAFF_PCS = _endpoints(10, "10.10.10.0", "00:14:22", 20, 6)  # Dell
LAB_VMS = _endpoints(20, "10.10.20.0", "00:50:56", 50, 8)  # VMware
PRINTERS = _endpoints(30, "10.10.30.0", "3c:d9:2b", 10, 3)  # HP
WIFI_CLIENTS = [Neighbor(20, "10.10.20.81", "f0:18:98:20:00:81"),  # Apple laptops on AP-1
                Neighbor(20, "10.10.20.82", "f0:18:98:20:00:82")]


def _fdb(endpoints: list[Neighbor], ports: list[int], vlan: int | None) -> list[FdbEntry]:
    """Endpoint i is plugged into ports[i]."""
    return [FdbEntry(n.mac, port, vlan) for n, port in zip(endpoints, ports, strict=True)]


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
    mgmt_ip="10.10.255.1",
    platform="Cisco IOSv",
    traffic={1: (3_100_000, 1_200_000), 2: (1_150_000, 3_000_000)},
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
        *STAFF_PCS, *LAB_VMS, *PRINTERS, *WIFI_CLIENTS,
        Neighbor(99, "10.10.99.11", "3c:d9:2b:99:00:11"),   # ACCESS-SW-1
        Neighbor(99, "10.10.99.12", "4c:5e:0c:99:00:12"),   # ACCESS-SW-2
        Neighbor(99, "10.10.99.21", "00:0b:86:99:00:21"),   # AP-1
        Neighbor(10, "2001:db8:10:10::20", "00:14:22:1a:20:14"),
        Neighbor(10, "2001:db8:10:10::21", "00:14:22:1a:20:15"),
        Neighbor(20, "2001:db8:10:20::50", "00:50:56:24:20:32"),
    ],
    mgmt_ip="10.10.99.1",
    platform="cisco C9300-24T",
    fdb_mib="q-bridge",
    # The trunks to the access switches see every endpoint behind them, which is why NetMap
    # must ignore ports with an LLDP/CDP neighbour when it answers "where is this PC?".
    fdb=[
        *_fdb(STAFF_PCS, [2] * 6, 10), *_fdb(PRINTERS, [2] * 3, 30),
        FdbEntry("3c:d9:2b:99:00:11", 2, 99),
        *_fdb(LAB_VMS, [3] * 8, 20), FdbEntry("4c:5e:0c:99:00:12", 3, 99),
        *_fdb(WIFI_CLIENTS, [4] * 2, 20), FdbEntry("00:0b:86:99:00:21", 4, 99),
        FdbEntry("00:00:0c:c0:10:00", 0, 10, status=4),  # its own SVI MACs
        FdbEntry("00:00:0c:c0:99:00", 0, 99, status=4),
    ],
    traffic={1: (3_000_000, 1_150_000), 2: (650_000, 1_900_000), 3: (900_000, 2_400_000),
             4: (150_000, 600_000)},
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
                oper_up=i <= 7) for i in range(1, 9)],
        Iface(9, "9", "9", 6, 1000, "3c:d9:2b:99:01:09", "Uplink to CORE-SW-1"),
        Iface(99, "VLAN99", "DEFAULT_VLAN99", 53, 1000, "3c:d9:2b:99:00:11", "Management",
              ipv4=["10.10.99.11/24"]),
    ],
    neighbors=[Neighbor(99, "10.10.99.1", "00:00:0c:c0:99:00")],
    mgmt_ip="10.10.99.11",
    fdb_mib="q-bridge",
    fdb=[
        *_fdb(STAFF_PCS, [1, 2, 3, 4, 5, 5], 10),  # two PCs behind a desk switch on port 5
        *_fdb(PRINTERS, [6, 7, 7], 30),
        FdbEntry("00:00:0c:c0:10:00", 9, 10), FdbEntry("00:00:0c:c0:99:00", 9, 99),
        FdbEntry("3c:d9:2b:99:00:11", 0, 99, status=4),
    ],
    traffic={9: (1_900_000, 650_000)},
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
    mgmt_ip="10.10.99.12",
    # BRIDGE-MIB only (no VLANs in the MAC table), and port numbers that differ from the
    # ifIndex, so the agent's bridge-port and LLDP-port mapping is exercised.
    fdb_mib="bridge",
    fdb=[
        *_fdb(LAB_VMS, [1, 2, 3, 4, 5, 6, 6, 6], None),  # three VMs on one host on ether6
        FdbEntry("00:00:0c:c0:20:00", 25, None), FdbEntry("00:00:0c:c0:99:00", 25, None),
        FdbEntry("4c:5e:0c:99:00:12", 0, None, status=4),
    ],
    bridge_ports={**{i: i for i in range(1, 9)}, 25: 9},
    lldp_ports={**{i: i for i in range(1, 9)}, 25: 9},
    traffic={25: (2_400_000, 900_000)},
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
    mgmt_ip="10.10.99.21",
    fdb_mib="bridge",
    fdb=[*_fdb(WIFI_CLIENTS, [2, 2], None), FdbEntry("00:00:0c:c0:20:00", 1, None)],
    counter_bits=32,  # an older device: its 32-bit octet counters wrap, the agent must cope
    traffic={1: (600_000, 150_000), 2: (140_000, 580_000)},
)

DEVICES = [EDGE_ROUTER, CORE_SWITCH, ACCESS_SW_1, ACCESS_SW_2, AP_1]



@dataclass
class Cable:
    """A cable between two simulated devices; both ends announce each other over `protocol`."""

    protocol: str  # "lldp" | "cdp"
    a: SimDevice
    a_if: int
    b: SimDevice
    b_if: int


@dataclass
class ExternalNeighbor:
    """A neighbour that NetMap does not manage (here: the ISP's router)."""

    device: SimDevice
    if_index: int
    sys_name: str
    port: str
    chassis_mac: str
    mgmt_ip: str


CABLES = [
    Cable("cdp", EDGE_ROUTER, 2, CORE_SWITCH, 1),
    Cable("lldp", CORE_SWITCH, 2, ACCESS_SW_1, 9),
    Cable("lldp", CORE_SWITCH, 3, ACCESS_SW_2, 25),
    Cable("lldp", CORE_SWITCH, 4, AP_1, 1),
]
EXTERNAL_NEIGHBORS = [
    ExternalNeighbor(EDGE_ROUTER, 1, "isp-pe-01.example.net", "xe-0/0/7", "00:00:0c:ee:00:01",
                     "203.0.113.1"),
]
