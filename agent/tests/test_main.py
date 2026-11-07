import asyncio
import json

from netmap_agent import main
from netmap_agent.config import AgentSettings
from netmap_agent.discovery.snmp import Address, DevicePoll, Interface, Neighbor
from netmap_agent.report import build_report


def make(**values) -> AgentSettings:
    return AgentSettings(_env_file=None, **values)


def test_plan_targets_merges_config_and_known_devices():
    settings = make(snmp_targets="10.0.0.1,10.0.0.2:1161", scan_ranges="10.0.1.0/30")
    known = [
        {"mgmt_ip": "10.0.0.1", "snmp_port": 161},          # duplicate of a configured target
        {"mgmt_ip": "2001:db8::5", "snmp_port": 161},
        {"mgmt_ip": "not an ip"},                           # ignored, not fatal
        {"snmp_port": 161},                                 # ignored
    ]
    ping_targets, snmp_targets = main.plan_targets(settings, known)
    assert snmp_targets == [("10.0.0.1", 161), ("10.0.0.2", 1161), ("2001:db8::5", 161)]
    assert set(ping_targets) == {"10.0.0.1", "10.0.0.2", "2001:db8::5", "10.0.1.1", "10.0.1.2"}


def sample_poll() -> DevicePoll:
    return DevicePoll(
        target="10.0.0.1", port=161, ok=True, sys_name="CORE-SW-1", vendor="Cisco",
        sys_object_id="1.3.6.1.4.1.9.1.2494", uptime_seconds=100,
        interfaces=[Interface(1, name="Gi1/0/1", mac="00:00:0c:c0:00:01", oper_status="up")],
        addresses=[Address("10.0.0.1", 4, 1, 24)],
        neighbors=[Neighbor("10.0.0.20", 4, "00:14:22:00:00:20", 1, "dynamic")],
    )


def test_report_shape_and_no_credentials():
    settings = make(snmp_v3_user="netops", snmp_v3_auth_key="auth-secret-value",
                    snmp_v3_priv_key="priv-secret-value")
    failed = DevicePoll(target="10.0.0.9", port=161, ok=False, error="timeout")
    report = build_report({"10.0.0.1": True, "10.0.0.9": False}, [sample_poll(), failed],
                          settings.snmp_version)
    assert report["ping"] == [{"ip": "10.0.0.1", "up": True}, {"ip": "10.0.0.9", "up": False}]
    device, down = report["devices"]
    assert device["vendor"] == "Cisco" and device["interfaces"][0]["if_index"] == 1
    assert device["addresses"] == [{"ip": "10.0.0.1", "if_index": 1, "prefixlen": 24}]
    assert device["neighbors"][0]["kind"] == "dynamic"
    assert down == {"mgmt_ip": "10.0.0.9", "snmp_port": 161, "snmp_version": "v3",
                    "reachable": False, "error": "timeout"}
    text = json.dumps(report)
    for secret in ("auth-secret-value", "priv-secret-value", "netops"):
        assert secret not in text


def test_run_cycle_wires_everything(monkeypatch):
    settings = make(snmp_targets="10.0.0.1", scan_ranges="10.0.1.0/31")

    class FakeUploader:
        sent = None

        def known_devices(self):
            return [{"mgmt_ip": "10.0.0.2", "snmp_port": 161}]

        def send_report(self, report):
            FakeUploader.sent = report
            return {"summary": {"devices": len(report["devices"])}}

    pinged, polled = [], []

    def fake_sweep(targets, _timeout):
        pinged.extend(targets)
        return dict.fromkeys(targets, True)

    monkeypatch.setattr(main.ping, "sweep", fake_sweep)

    async def fake_poll_all(_settings, targets):
        polled.extend(targets)
        return [sample_poll()]

    monkeypatch.setattr(main.snmp, "poll_all", fake_poll_all)
    result = asyncio.run(main.run_cycle(settings, FakeUploader()))
    assert result == {"summary": {"devices": 1}}
    assert polled == [("10.0.0.1", 161), ("10.0.0.2", 161)]
    assert set(pinged) == {"10.0.0.1", "10.0.0.2", "10.0.1.0", "10.0.1.1"}
    assert FakeUploader.sent["devices"][0]["sys_name"] == "CORE-SW-1"
