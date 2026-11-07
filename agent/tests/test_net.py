import ipaddress

import pytest

from netmap_agent.discovery.net import (
    MAX_RANGE_ADDRESSES,
    hosts_of,
    normalize_mac,
    parse_scan_range,
    parse_target,
)


def test_range_cap():
    assert parse_scan_range("10.0.0.0/22").num_addresses == MAX_RANGE_ADDRESSES
    assert parse_scan_range("2001:db8::/118").num_addresses == MAX_RANGE_ADDRESSES
    with pytest.raises(ValueError, match="maximum"):
        parse_scan_range("10.0.0.0/21")
    with pytest.raises(ValueError, match="maximum"):
        parse_scan_range("2001:db8::/64")


def test_range_host_bits_are_tolerated():
    assert str(parse_scan_range("10.0.0.7/24")) == "10.0.0.0/24"


@pytest.mark.parametrize("bad", ["10.0.0.0/24;calc", "example.com/24", "", "10.0.0.0/24 /25"])
def test_range_rejects_non_networks(bad):
    with pytest.raises(ValueError):
        parse_scan_range(bad)


def test_hosts_of():
    assert hosts_of(ipaddress.ip_network("10.0.0.0/30")) == ["10.0.0.1", "10.0.0.2"]
    assert hosts_of(ipaddress.ip_network("10.0.0.5/32")) == ["10.0.0.5"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("10.0.0.1", ("10.0.0.1", 161)),
        ("10.0.0.1:1161", ("10.0.0.1", 1161)),
        ("2001:db8::1", ("2001:db8::1", 161)),
        ("[2001:db8::1]:1161", ("2001:db8::1", 1161)),
        ("[2001:DB8:0::1]", ("2001:db8::1", 161)),
        ("  127.0.0.11:1161 ", ("127.0.0.11", 1161)),
    ],
)
def test_parse_target(value, expected):
    assert parse_target(value) == expected


@pytest.mark.parametrize(
    "bad",
    ["router.example.com", "10.0.0.1:0", "10.0.0.1:70000", "10.0.0.1:abc", "10.0.0.1; rm -rf /",
     "[2001:db8::1]:99999", "-c 1 10.0.0.1"],
)
def test_parse_target_rejects(bad):
    with pytest.raises(ValueError):
        parse_target(bad)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (bytes.fromhex("00000c a10001".replace(" ", "")), "00:00:0c:a1:00:01"),
        ("00:00:0C:A1:00:01", "00:00:0c:a1:00:01"),
        ("00-00-0c-a1-00-01", "00:00:0c:a1:00:01"),
        ("0000.0ca1.0001", "00:00:0c:a1:00:01"),
        ("00000ca10001", "00:00:0c:a1:00:01"),
        ("0x00000ca10001", "00:00:0c:a1:00:01"),
    ],
)
def test_normalize_mac(value, expected):
    assert normalize_mac(value) == expected


@pytest.mark.parametrize(
    "bad",
    [None, b"", b"\x00\x01\x02", bytes(6), b"\xff" * 6, "00:00:00:00:00:00", "zz:00:0c:a1:00:01",
     "00:00:0c:a1:00", "00:00:0c:a1:00:01:02", "<script>00000ca10001"],
)
def test_normalize_mac_rejects(bad):
    assert normalize_mac(bad) is None
