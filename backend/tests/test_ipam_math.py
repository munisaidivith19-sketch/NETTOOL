import ipaddress
import time

import pytest

from app.services import ipam
from app.services.ipaddr import ip_key, key_to_ip


def net(text):
    return ipaddress.ip_network(text)


@pytest.mark.parametrize(
    ("network", "size", "usable"),
    [
        ("10.0.0.0/24", "256", "254"),
        ("10.0.0.0/30", "4", "2"),
        ("10.0.0.0/31", "2", "2"),  # RFC 3021 point-to-point
        ("10.0.0.1/32", "1", "1"),
        ("2001:db8::/64", "18446744073709551616", "18446744073709551615"),
        ("2001:db8::/127", "2", "1"),
        ("2001:db8::1/128", "1", "1"),
    ],
)
def test_sizes_are_exact_strings(network, size, usable):
    stats = ipam.usage(net(network), 0)
    assert (stats["size"], stats["usable"]) == (size, usable)
    assert stats["free"] == usable and stats["percent"] == 0.0


def test_percent_and_free():
    stats = ipam.usage(net("10.0.0.0/24"), 127)
    assert stats == {"size": "256", "usable": "254", "used": "127", "free": "127", "percent": 50.0}
    assert ipam.usage(net("2001:db8::/64"), 3)["percent"] == 0.0


def test_ip_key_round_trip_and_family_order():
    for text in ("0.0.0.0", "255.255.255.255"  # noqa: S104 - data, not a bind
                 , "::", "2001:db8::1", "::ffff:10.0.0.1"):
        assert str(key_to_ip(ip_key(text))) == str(ipaddress.ip_address(text))
    assert ip_key("255.255.255.255") < ip_key("::")  # every IPv4 key sorts before IPv6


def V4(text):
    return int(ipaddress.ip_address(text))


def test_first_free_skips_used_gateway_and_ranges():
    n = net("10.0.0.0/24")
    blocked = [(V4("10.0.0.1"), V4("10.0.0.1")), (V4("10.0.0.10"), V4("10.0.0.20"))]
    assert str(ipam.first_free(n, blocked, [])) == "10.0.0.2"
    used = [V4(f"10.0.0.{i}") for i in range(2, 10)]
    assert str(ipam.first_free(n, blocked, used)) == "10.0.0.21"  # steps over used + range
    used += [V4(f"10.0.0.{i}") for i in range(21, 255)]
    assert ipam.first_free(n, blocked, sorted(used)) is None  # full


def test_first_free_ipv6_is_instant_and_skips_anycast():
    n = net("2001:db8:10:10::/64")
    start = time.perf_counter()
    used = [int(ipaddress.ip_address("2001:db8:10:10::1")) + i for i in range(1000)]
    free = ipam.first_free(n, [], used)
    assert str(free) == "2001:db8:10:10::3e9"
    assert time.perf_counter() - start < 0.5


def test_point_to_point_full():
    n = net("10.0.0.0/31")
    assert ipam.first_free(n, [], [V4("10.0.0.0"), V4("10.0.0.1")]) is None


@pytest.mark.parametrize(
    ("q", "kind", "value"),
    [
        ("10.10.10.20", "ip", "10.10.10.20"),
        ("2001:db8::1", "ip", "2001:db8::1"),
        ("10.10.10.0/24", "network", "10.10.10.0/24"),
        ("10.10.10.7/24", "network", "10.10.10.0/24"),
        ("00:14:22:1A:20:14", "mac", "00:14:22:1a:20:14"),
        ("0014.221a.2014", "mac", "00:14:22:1a:20:14"),
        ("00-14-22-1a-20-14", "mac", "00:14:22:1a:20:14"),
        ("core-sw", "hostname", "core-sw"),
        ("deadbeef", "hostname", "deadbeef"),
    ],
)
def test_classify_query(q, kind, value):
    got_kind, got_value = ipam.classify_query(q)
    assert (got_kind, str(got_value)) == (kind, value)
