import pytest

from netmap_agent.discovery import oids
from netmap_agent.discovery.vendor import detect_vendor, enterprise_number

V6 = (0x20, 0x01, 0x0D, 0xB8, 0, 0x10, 0, 0x10, 0, 0, 0, 0, 0, 0, 0, 1)  # 2001:db8:10:10::1


def test_suffix():
    assert oids.suffix(oids.IF_DESCR + ".7", oids.IF_DESCR) == (7,)
    with pytest.raises(oids.OidIndexError):
        oids.suffix("1.3.6.1.2.1.2.2.1.20.7", oids.IF_DESCR)  # 20 is not 2 + "."


@pytest.mark.parametrize(
    ("index", "address", "version", "rest"),
    [
        ((1, 4, 192, 168, 1, 10), "192.168.1.10", 4, ()),
        ((2, 16, *V6), "2001:db8:10:10::1", 6, ()),
        ((3, 8, 10, 0, 0, 1, 0, 0, 0, 5), "10.0.0.1", 4, ()),  # ipv4z: zone index dropped
        ((4, 20, *V6, 0, 0, 0, 3), "2001:db8:10:10::1", 6, ()),  # ipv6z
        ((1, 4, 10, 10, 10, 0, 24), "10.10.10.0", 4, (24,)),  # trailing prefix length kept
    ],
)
def test_parse_inet_index(index, address, version, rest):
    parsed = oids.parse_inet_index(index)
    assert (parsed.address, parsed.version, parsed.remainder) == (address, version, rest)


@pytest.mark.parametrize(
    "index",
    [
        (1,),                       # too short
        (1, 4, 10, 0, 0),           # shorter than its length
        (1, 16, *V6),               # type says IPv4, length says IPv6
        (1, 4, 10, 0, 0, 256),      # octet out of range
        (9, 4, 10, 0, 0, 1),        # unknown type
    ],
)
def test_parse_inet_index_rejects_bad_input(index):
    with pytest.raises(oids.OidIndexError):
        oids.parse_inet_index(index)


def test_ip_address_table_row():
    oid = f"{oids.IP_ADDRESS_IFINDEX}.2.16." + ".".join(map(str, V6))
    assert oids.parse_address_index(oid, oids.IP_ADDRESS_IFINDEX).address == "2001:db8:10:10::1"


def test_old_ipaddr_table_index():
    assert oids.parse_ipv4_index((10, 10, 99, 1)) == "10.10.99.1"
    with pytest.raises(oids.OidIndexError):
        oids.parse_ipv4_index((10, 10, 99))


@pytest.mark.parametrize(
    ("pointer", "expected"),
    [
        ("1.3.6.1.2.1.4.32.1.5.10.1.4.10.10.10.0.24", 24),
        ("1.3.6.1.2.1.4.32.1.5.10.2.16." + ".".join(map(str, V6)) + ".64", 64),
        ("0.0", None),
        ("1.3.6.1.2.1.4.32.1.5.10.1.4.10.10.10.0.200", None),
        ("garbage", None),
    ],
)
def test_parse_prefix_pointer(pointer, expected):
    assert oids.parse_prefix_pointer(pointer) == expected


@pytest.mark.parametrize(
    ("mask", "expected"),
    [("255.255.255.0", 24), ("255.255.255.252", 30), ("255.0.255.0", None), ("nope", None)],
)
def test_netmask_to_prefix(mask, expected):
    assert oids.netmask_to_prefix(mask) == expected


def test_net_to_physical_ipv4_and_ipv6():
    col = oids.IP_NET_TO_PHYS_ADDRESS
    if_index, inet = oids.parse_net_to_physical_index(f"{col}.10.1.4.10.10.10.20", col)
    assert (if_index, inet.address) == (10, "10.10.10.20")
    if_index, inet = oids.parse_net_to_physical_index(
        f"{col}.20.2.16." + ".".join(map(str, V6)), col)
    assert (if_index, inet.version) == (20, 6)


def test_net_to_media_index():
    col = oids.IP_NET_TO_MEDIA_PHYS_ADDRESS
    assert oids.parse_net_to_media_index(f"{col}.3.10.10.30.10", col) == (3, "10.10.30.10")
    with pytest.raises(oids.OidIndexError):
        oids.parse_net_to_media_index(f"{col}.3.10.10.30", col)


@pytest.mark.parametrize(
    ("sys_object_id", "vendor"),
    [
        ("1.3.6.1.4.1.9.1.2494", "Cisco"),
        ("1.3.6.1.4.1.14988.1", "MikroTik"),
        (".1.3.6.1.4.1.2636.1.1.1.2.21", "Juniper"),
        ("1.3.6.1.4.1.30065.1.3011", "Arista"),
        ("1.3.6.1.4.1.99999.1", "enterprise 99999"),
        ("1.3.6.1.2.1.1", "unknown"),
        ("1.3.6.1.4.1", "unknown"),
        ("not.an.oid", "unknown"),
        (None, "unknown"),
    ],
)
def test_detect_vendor(sys_object_id, vendor):
    assert detect_vendor(sys_object_id) == vendor


def test_enterprise_number():
    assert enterprise_number("1.3.6.1.4.1.25461.2.3.1") == 25461


# ---- Phase 5: LLDP, CDP, MAC tables -----------------------------------------------------------

def test_lldp_rem_index():
    assert oids.parse_lldp_rem_index((0, 9, 1)) == (9, 1)
    assert oids.parse_lldp_rem_index((123456, 2, 7)) == (2, 7)  # timeMark is ignored
    with pytest.raises(oids.OidIndexError):
        oids.parse_lldp_rem_index((9, 1))


@pytest.mark.parametrize(
    ("index", "expected"),
    [
        ((0, 3, 1, 1, 4, 10, 10, 99, 1), (3, 1, "10.10.99.1")),
        ((0, 3, 1, 2, 16, *V6), (3, 1, "2001:db8:10:10::1")),
    ],
)
def test_lldp_man_addr_index(index, expected):
    assert oids.parse_lldp_man_addr_index(index) == expected


@pytest.mark.parametrize(
    "index",
    [(0, 3, 1, 1), (0, 3, 1, 1, 4, 10, 10, 99), (0, 3, 1, 6, 6, 0, 1, 2, 3, 4, 5),
     (0, 3, 1, 1, 4, 10, 10, 99, 300)],
)
def test_lldp_man_addr_index_rejects_bad_input(index):
    with pytest.raises(oids.OidIndexError):
        oids.parse_lldp_man_addr_index(index)


def test_mac_indexes():
    assert oids.parse_mac_index((0, 20, 34, 26, 32, 20)) == "00:14:22:1a:20:14"
    assert oids.parse_qbridge_fdb_index((10, 0, 20, 34, 26, 32, 20)) == (10, "00:14:22:1a:20:14")
    for bad in ((0, 20, 34, 26, 32), (0, 20, 34, 26, 32, 256)):
        with pytest.raises(oids.OidIndexError):
            oids.parse_mac_index(bad)
    with pytest.raises(oids.OidIndexError):
        oids.parse_qbridge_fdb_index((0, 20, 34, 26, 32, 20))


def test_cdp_index():
    assert oids.parse_cdp_index((2, 1)) == (2, 1)
    with pytest.raises(oids.OidIndexError):
        oids.parse_cdp_index((2,))


@pytest.mark.parametrize(
    ("subtype", "raw", "expected"),
    [
        (4, bytes.fromhex("3cd92b990011"), "3c:d9:2b:99:00:11"),  # macAddress
        (5, bytes([1, 10, 10, 99, 1]), "10.10.99.1"),  # networkAddress: family + IPv4
        (7, b"CORE-SW-1", "CORE-SW-1"),  # local: free text
        (4, b"short", "short"),  # says MAC but isn't 6 bytes: shown as text
        (1, b"evil\x1b[31m\x00name", "evil [31m name"),  # control characters removed
        (7, b"", None),
    ],
)
def test_lldp_chassis_id(subtype, raw, expected):
    assert oids.lldp_chassis_id(subtype, raw) == expected


def test_lldp_port_id():
    assert oids.lldp_port_id(3, bytes.fromhex("4c5e0c990219")) == "4c:5e:0c:99:02:19"
    assert oids.lldp_port_id(5, b"sfp-sfpplus1") == "sfp-sfpplus1"
    assert oids.lldp_port_id(5, b"x" * 400) == "x" * 255  # bounded


def test_cdp_address():
    assert oids.cdp_address(1, bytes([10, 10, 0, 2])) == "10.10.0.2"
    assert oids.cdp_address(1, b"\x0a\x0a") is None
    assert oids.cdp_address(20, bytes([10, 10, 0, 2])) is None  # not an IPv4 address type
