"""The SNMP client's table logic against every simulated device, without starting snmpsim.

FileClient answers get/walk straight from the generated .snmprec rows, so these tests cover the
cases only some devices have: LLDP port numbers and bridge port numbers that differ from the
ifIndex (ACCESS-SW-2), the VLAN-unaware BRIDGE-MIB table, and 32-bit counters (AP-1).
"""

import asyncio

import pytest

from netmap_agent.discovery.snmp import SnmpClient
from simulation import build_snmprec
from simulation.topology import ACCESS_SW_1, ACCESS_SW_2, AP_1, CORE_SWITCH, EDGE_ROUTER


class Text:
    def __init__(self, raw: bytes):
        self.raw = raw

    def asOctets(self) -> bytes:  # noqa: N802 - pysnmp's name
        return self.raw


def _value(tag: str, value: str):
    if tag in ("4", "6"):
        return Text(value.encode()) if tag == "4" else value
    if tag == "4x":
        return Text(bytes.fromhex(value))
    if tag == "64":
        return value
    if tag.endswith(":numeric"):
        return int(value.split("initial=")[1].split(",")[0])
    return int(value)


class FileClient(SnmpClient):
    def __init__(self, slug: str, rows: list[str] | None = None):  # no SNMP engine needed
        lines = rows if rows is not None else (
            build_snmprec.DATA_DIR / slug / build_snmprec.DATA_FILE).read_text().splitlines()
        self.rows = []
        for line in lines:
            oid, tag, value = line.split("|", 2)
            self.rows.append((oid, _value(tag, value)))

    async def _transport(self, host, port):
        return None

    async def get(self, transport, oid_list):
        found = dict(self.rows)
        return {oid: found[oid] for oid in oid_list if oid in found}

    async def walk(self, transport, column):
        return [(oid, value) for oid, value in self.rows if oid.startswith(column + ".")]


def poll(slug: str, rows: list[str] | None = None):
    result = asyncio.run(FileClient(slug, rows).poll("127.0.0.1", 1161))
    assert result.ok, result.error
    return result


def test_lldp_and_bridge_port_numbers_are_mapped_to_if_index():
    device = poll(ACCESS_SW_2.slug)
    [link] = device.links
    # lldpLocPortNum 9 and bridge port 9 are both ifIndex 25 (sfp-sfpplus1) on this switch.
    assert (link.if_index, link.local_port, link.remote_name) == (25, "sfp-sfpplus1", "CORE-SW-1")
    uplink_macs = {m.mac for m in device.mac_table if m.if_index == 25}
    assert uplink_macs == {"00:00:0c:c0:20:00", "00:00:0c:c0:99:00"}
    assert all(m.vlan is None for m in device.mac_table)  # BRIDGE-MIB has no VLANs
    on_ether6 = [m.mac for m in device.mac_table if m.if_index == 6]
    assert len(on_ether6) == 3


def test_qbridge_table_keeps_vlans_and_skips_self():
    device = poll(ACCESS_SW_1.slug)
    macs = {(m.mac, m.if_index, m.vlan) for m in device.mac_table}
    assert ("00:14:22:1a:20:14", 1, 10) in macs
    assert ("3c:d9:2b:2e:20:0a", 6, 30) in macs  # first printer, VLAN 30
    assert not any(m.mac == "3c:d9:2b:99:00:11" for m in device.mac_table)  # its own MAC


def test_cdp_and_external_lldp_neighbour():
    device = poll(EDGE_ROUTER.slug)
    links = {link.protocol: link for link in device.links}
    assert links["cdp"].if_index == 2 and links["cdp"].local_port == "Gi0/1"
    assert links["cdp"].remote_mgmt_ip == "10.10.0.2"
    isp = links["lldp"]
    assert (isp.remote_name, isp.remote_chassis_id) == ("isp-pe-01.example.net",
                                                         "00:00:0c:ee:00:01")


def test_32_bit_counters_fallback():
    device = poll(AP_1.slug)
    assert {c.bits for c in device.counters} == {32}
    assert all(c.in_octets is None or c.in_octets < 2**32 for c in device.counters)


def test_hc_counters_and_errors():
    device = poll(ACCESS_SW_1.slug)
    counters = {c.if_index: c for c in device.counters}
    assert counters[5].in_errors == 17 and counters[9].bits == 64
    assert counters[8].in_octets == 0  # oper down: no traffic


def test_core_sees_every_endpoint_on_its_trunks():
    device = poll(CORE_SWITCH.slug)
    trunk_ports = {m.if_index for m in device.mac_table}
    assert trunk_ports == {2, 3, 4}


@pytest.mark.parametrize(
    "rows",
    [
        # LLDP neighbour whose management address row is malformed: link kept, no mgmt IP
        ["1.0.8802.1.1.2.1.4.1.1.9.0.1.1|4|PEER",
         "1.0.8802.1.1.2.1.4.2.1.3.0.1.1.1.4.10.10|2|2"],
        # LLDP port number with no matching interface or lldpLocPortTable row
        ["1.0.8802.1.1.2.1.4.1.1.9.0.77.1|4|PEER"],
    ],
)
def test_bad_lldp_rows_do_not_break_the_poll(rows):
    base = ["1.3.6.1.2.1.1.5.0|4|SW", "1.3.6.1.2.1.2.2.1.2.1|4|eth0",
            "1.3.6.1.2.1.31.1.1.1.1.1|4|eth0"]
    device = poll("custom", base + rows)
    [link] = device.links
    assert link.remote_name == "PEER" and link.remote_mgmt_ip is None


def test_fdb_rows_with_bad_index_or_port_zero_are_skipped():
    rows = ["1.3.6.1.2.1.1.5.0|4|SW",
            "1.3.6.1.2.1.17.7.1.2.2.1.2.10.0.20.34.26.32|2|3",  # MAC too short
            "1.3.6.1.2.1.17.7.1.2.2.1.2.10.0.20.34.26.32.20|2|0",  # port 0: unknown port
            "1.3.6.1.2.1.17.7.1.2.2.1.2.10.0.20.34.26.32.21|2|3",
            "1.3.6.1.2.1.17.7.1.2.2.1.3.10.0.20.34.26.32.21|2|3"]
    device = poll("custom", rows)
    assert [(m.mac, m.if_index, m.vlan) for m in device.mac_table] == [
        ("00:14:22:1a:20:15", 3, 10)]

