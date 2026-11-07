"""End-to-end: the real SNMP client against snmpsim serving the simulated core switch over
SNMPv3 authPriv. Skipped (with the reason) when snmpsim isn't installed or can't start."""

import asyncio
import subprocess
import threading
import time

import pytest

from netmap_agent.config import AgentSettings
from netmap_agent.discovery.snmp import poll_all, use_selector_event_loop
from simulation import build_snmprec, run_simulation
from simulation.topology import CORE_SWITCH

LISTEN, PORT = "127.0.0.21", 1161
NOTHING_LISTENING = "127.0.0.22"
STARTUP_SECONDS = 30


@pytest.fixture(autouse=True)
def agent_event_loop():
    """Use the same event loop the agent's main() uses."""
    original = asyncio.get_event_loop_policy()
    use_selector_event_loop()
    yield
    asyncio.set_event_loop_policy(original)


def test_committed_data_files_match_the_generator(tmp_path):
    """The .snmprec files in git must be exactly what build_snmprec.py produces."""
    build_snmprec.build(tmp_path)
    for generated in tmp_path.rglob("*.snmprec"):
        committed = build_snmprec.DATA_DIR / generated.relative_to(tmp_path)
        assert committed.read_bytes() == generated.read_bytes(), f"rerun build_snmprec: {committed}"


@pytest.fixture(scope="module")
def responder(tmp_path_factory):
    try:
        command = run_simulation.responder_command(
            build_snmprec.DATA_DIR / CORE_SWITCH.slug, LISTEN, PORT,
            cache_dir=tmp_path_factory.mktemp("snmpsim-cache"))
    except RuntimeError as exc:
        pytest.skip(str(exc))
    process = subprocess.Popen(  # noqa: S603 - fixed argument list
        command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    ready = threading.Event()

    def drain():  # snmpsim logs every request; an unread pipe would block it
        for line in process.stdout:
            if b"Listening at" in line:
                ready.set()

    threading.Thread(target=drain, daemon=True).start()
    if not ready.wait(STARTUP_SECONDS) or process.poll() is not None:
        process.kill()
        pytest.skip(f"snmpsim did not start on {LISTEN}:{PORT}")
    time.sleep(0.3)
    yield
    process.terminate()
    process.wait(10)


def sim_settings(**values) -> AgentSettings:
    base = {
        "snmp_v3_user": run_simulation.SIM_USER,
        "snmp_v3_auth_key": run_simulation.SIM_AUTH_KEY,
        "snmp_v3_priv_key": run_simulation.SIM_PRIV_KEY,
        "snmp_v3_context": run_simulation.SIM_CONTEXT,
    }
    return AgentSettings(_env_file=None, **(base | values))


def test_poll_simulated_core_switch(responder):
    [device] = asyncio.run(poll_all(sim_settings(), [(LISTEN, PORT)]))
    assert device.ok, device.error
    assert (device.sys_name, device.vendor) == ("CORE-SW-1", "Cisco")
    assert device.uptime_seconds == CORE_SWITCH.uptime_seconds

    interfaces = {i.if_index: i for i in device.interfaces}
    assert set(interfaces) == {i.index for i in CORE_SWITCH.interfaces}
    assert interfaces[10].name == "Vl10" and interfaces[10].alias == "Staff"
    assert interfaces[1].mac == "00:00:0c:c0:00:01" and interfaces[1].oper_status == "up"

    addresses = {(a.ip, a.if_index, a.prefixlen) for a in device.addresses}
    assert ("10.10.10.1", 10, 24) in addresses
    assert ("2001:db8:10:10::1", 10, 64) in addresses
    assert ("10.10.0.2", 1, 30) in addresses

    neighbors = {(n.ip, n.mac) for n in device.neighbors}
    assert len(neighbors) == len(CORE_SWITCH.neighbors)
    assert ("2001:db8:10:20::50", "00:50:56:24:20:32") in neighbors

    links = {(link.protocol, link.if_index): link for link in device.links}
    assert set(links) == {("cdp", 1), ("lldp", 2), ("lldp", 3), ("lldp", 4)}
    sw2 = links[("lldp", 3)]
    assert (sw2.remote_name, sw2.remote_port, sw2.local_port) == (
        "ACCESS-SW-2", "sfp-sfpplus1", "Gi1/0/3")
    assert (sw2.remote_chassis_id, sw2.remote_mgmt_ip) == ("4c:5e:0c:99:00:12", "10.10.99.12")
    edge = links[("cdp", 1)]
    assert (edge.remote_name, edge.remote_mgmt_ip, edge.remote_platform) == (
        "EDGE-RTR-1", "10.10.0.1", "Cisco IOSv")

    macs = {(m.mac, m.if_index, m.vlan) for m in device.mac_table}
    assert ("00:14:22:1a:20:14", 2, 10) in macs  # a staff PC, seen on the trunk to ACCESS-SW-1
    assert ("00:50:56:24:20:32", 3, 20) in macs
    assert not any(m.mac == "00:00:0c:c0:10:00" for m in device.mac_table)  # "self" skipped
    assert len(macs) == len([e for e in CORE_SWITCH.fdb if e.status == 3])

    counters = {c.if_index: c for c in device.counters}
    assert counters[2].bits == 64 and counters[2].in_octets > 0
    assert device.counters_at is not None


def test_counters_grow(responder):
    first, = asyncio.run(poll_all(sim_settings(), [(LISTEN, PORT)]))
    time.sleep(1.1)
    second, = asyncio.run(poll_all(sim_settings(), [(LISTEN, PORT)]))
    before = {c.if_index: c.in_octets for c in first.counters}
    after = {c.if_index: c.in_octets for c in second.counters}
    assert after[2] > before[2]  # oper up: traffic flows
    assert after[1] - before[1] > after[4] - before[4]  # the WAN uplink is busier than AP-1


def test_dead_target_does_not_break_live_one(responder):
    """Regression: on Windows a "port unreachable" from one target used to make every other
    device in the same cycle time out (see use_selector_event_loop)."""
    settings = sim_settings(snmp_timeout_seconds=1, snmp_retries=0)
    live, dead = asyncio.run(poll_all(settings, [(LISTEN, PORT), (NOTHING_LISTENING, PORT)]))
    assert live.ok, live.error
    assert not dead.ok


def test_wrong_v3_key_fails_cleanly(responder):
    settings = sim_settings(snmp_v3_auth_key="wrong-auth-key-value", snmp_timeout_seconds=1,
                            snmp_retries=0)
    [device] = asyncio.run(poll_all(settings, [(LISTEN, PORT)]))
    assert not device.ok and device.error
    assert "wrong-auth-key-value" not in device.error
