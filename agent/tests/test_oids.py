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
