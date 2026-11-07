"""Config backups, versions, diff, compliance and unconfigured detection (Phase 6)."""

from pathlib import Path

import pytest

from app.services import compliance
from app.services.configs import KEEP_VERSIONS, diff_rows, unconfigured_reasons
from tests.config_helpers import (
    CORE_CONFIG,
    WEAK_CONFIG,
    agent_call,
    fingerprint,
    seed_core,
    upload,
)
from tests.ipam_helpers import as_role, seed_report
from tests.test_ingest import _new_agent
from tests.topology_helpers import core

REPO = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("name", ["masking.py", "denylist.py", "jobsign.py"])
def test_shared_files_are_identical_on_agent_and_backend(name):
    agent_copy = REPO / "agent" / "netmap_agent" / "config_mgmt" / name
    backend_copy = REPO / "backend" / "app" / "config_mgmt" / name
    assert agent_copy.read_bytes() == backend_copy.read_bytes(), f"{name} copies differ"


def test_backup_targets_list_only_this_agents_devices(client, sync_db):
    agent, device_id = seed_core(client, sync_db, config=None)
    response = agent_call(client, agent, "GET", "/api/agent/backup-targets")
    assert response.json()["devices"] == [{"device_id": device_id, "mgmt_ip": "10.10.99.1",
                                           "last_hash": None, "requested": False}]
    as_role(client, sync_db, "admin")
    other = _new_agent(client, as_role(client, sync_db, "admin")["X-CSRF-Token"], "Other")
    assert agent_call(client, other, "GET", "/api/agent/backup-targets").json() == {
        "devices": []}


def test_upload_is_masked_versioned_and_deduplicated(client, sync_db):
    agent, device_id = seed_core(client, sync_db, config=None)
    response = upload(client, agent, device_id, WEAK_CONFIG,
                      facts={"snmp_default_community": True})
    assert response.json()["version"] == 1 and response.json()["stored"] is True
    stored = sync_db.configs.find_one({"version": 1})
    # The agent "forgot" to mask; the backend masks again before storing.
    assert "NotMaskedByTheAgent" not in stored["text"] and "public" not in stored["text"]
    assert "enable secret 9 <masked>" in stored["text"]

    # Same fingerprint, no text: nothing new is stored and no "changed" alert.
    again = upload(client, agent, device_id, None, hash_=fingerprint(WEAK_CONFIG))
    assert again.json()["stored"] is False
    assert sync_db.configs.count_documents({}) == 1
    assert sync_db.alerts.count_documents({"type": "config_changed"}) == 0

    # A real change outside NetMap: version 2 and an info alert.
    upload(client, agent, device_id, CORE_CONFIG)
    assert sync_db.configs.count_documents({}) == 2
    alert = sync_db.alerts.find_one({"type": "config_changed"})
    assert alert["severity"] == "info" and "version 2" in alert["message"]
    targets = agent_call(client, agent, "GET", "/api/agent/backup-targets").json()["devices"]
    assert targets[0]["last_hash"] == fingerprint(CORE_CONFIG)
    assert sync_db.audit_log.count_documents({"action": "config.backup"}) == 2


def test_only_the_newest_versions_are_kept(client, sync_db):
    agent, device_id = seed_core(client, sync_db, config=None)
    for n in range(KEEP_VERSIONS + 5):
        assert upload(client, agent, device_id, CORE_CONFIG + f"! {n}\n").status_code == 200
    versions = sorted(c["version"] for c in sync_db.configs.find({}, {"version": 1}))
    assert len(versions) == KEEP_VERSIONS and versions[0] == 6 and versions[-1] == 55


def test_failed_backup_is_recorded(client, sync_db):
    agent, device_id = seed_core(client, sync_db, config=None)
    sync_db.devices.update_one({}, {"$set": {"backup_requested_at": "x"}})
    upload(client, agent, device_id, None, error="auth_failed", source="manual")
    device = sync_db.devices.find_one()
    assert device["config_backup"]["status"] == "failed"
    assert device["config_backup"]["error"] == "auth_failed"
    assert "backup_requested_at" not in device


@pytest.mark.parametrize("body", [
    {"device_id": "a" * 24, "source": "scheduled", "vendor": "cisco_ios"},  # no hash
    {"device_id": "a" * 24, "source": "scheduled", "error": "Auth Failed!"},  # free text
    {"device_id": {"$ne": None}, "source": "scheduled", "error": "x_y"},
    {"device_id": "a" * 24, "source": "nightly", "error": "x_y"},
    {"device_id": "a" * 24, "source": "scheduled", "error": "x_y", "extra": 1},
    {"device_id": "a" * 24, "source": "scheduled", "vendor": "cisco_ios",
     "hash": "z" * 64},
])
def test_bad_uploads_are_rejected(client, sync_db, body):
    agent, _ = seed_core(client, sync_db, config=None)
    assert agent_call(client, agent, "POST", "/api/agent/configs", body).status_code == 422


def test_another_agents_device_is_refused(client, sync_db):
    _, device_id = seed_core(client, sync_db, config=None)
    other = _new_agent(client, as_role(client, sync_db, "admin")["X-CSRF-Token"], "Other")
    assert upload(client, other, device_id, CORE_CONFIG).status_code == 404


def test_config_text_is_for_engineers_only(client, sync_db):
    agent, device_id = seed_core(client, sync_db)
    upload(client, agent, device_id, CORE_CONFIG.replace("vlan 10\n", "vlan 10\nvlan 20\n"))
    base = f"/api/devices/{device_id}/configs"
    as_role(client, sync_db, "viewer")
    for path in (base, f"{base}/1", f"{base}/diff?from=1&to=2"):
        assert client.get(path).status_code == 403
    assert client.get("/api/configs").status_code == 200  # the overview is fine for viewers
    as_role(client, sync_db, "engineer")
    assert [v["version"] for v in client.get(base).json()] == [2, 1]
    assert "hostname CORE-SW-1" in client.get(f"{base}/1").json()["text"]
    diff = client.get(f"{base}/diff?from=1&to=2").json()
    assert diff["changed_lines"] == 1
    assert {"kind": "added", "left_no": None, "left": None, "right_no": 15,
            "right": "vlan 20"} in diff["rows"]
    assert client.get(f"{base}/9").status_code == 404
    assert client.get(f"{base}/diff?from=1&to=9").status_code == 404
    assert client.get(f"{base}/diff?from=$gt&to=2").status_code == 422


def test_backup_now(client, sync_db):
    agent, device_id = seed_core(client, sync_db)
    path = f"/api/devices/{device_id}/configs/backup-now"
    assert client.post(path, headers=as_role(client, sync_db, "viewer")).status_code == 403
    assert client.post(path, headers=as_role(client, sync_db, "engineer")).status_code == 202
    assert sync_db.audit_log.count_documents({"action": "config.backup_request"}) == 1
    targets = agent_call(client, agent, "GET", "/api/agent/backup-targets").json()["devices"]
    assert targets[0]["requested"] is True
    upload(client, agent, device_id, None, hash_=fingerprint(CORE_CONFIG), source="manual")
    targets = agent_call(client, agent, "GET", "/api/agent/backup-targets").json()["devices"]
    assert targets[0]["requested"] is False


# ------------------------------------------------------------------ compliance

def test_hardened_config_scores_100(client, sync_db):
    _, device_id = seed_core(client, sync_db)
    as_role(client, sync_db, "viewer")
    report = client.get(f"/api/devices/{device_id}/compliance").json()
    assert report["compliance"]["score"] == 100 and report["report"]["findings"] == []


def test_weak_config_findings_score_and_alert(client, sync_db):
    agent, device_id = seed_core(client, sync_db)
    upload(client, agent, device_id, WEAK_CONFIG, facts={"snmp_default_community": True})
    findings = {f["rule"]: f for f in sync_db.devices.find_one()["compliance"]["findings"]}
    assert set(findings) == {"telnet_enabled", "no_password_encryption",
                             "snmp_default_community", "no_ssh_v2", "no_login_banner",
                             "no_exec_timeout", "access_port_security"}
    assert findings["telnet_enabled"]["fix"] == "line vty 0 4\n transport input ssh"
    assert findings["snmp_default_community"]["needs_input"] is True
    device = sync_db.devices.find_one()
    # 100 - (20 + 10 + 20 + 10 + 5 + 10 + 10) = 15
    assert device["compliance"]["score"] == 15 and device["compliance"]["previous_score"] == 100
    alert = sync_db.alerts.find_one({"type": "compliance"})
    assert alert["status"] == "open" and "dropped from 100 to 15" in alert["message"]

    upload(client, agent, device_id, CORE_CONFIG)
    assert sync_db.alerts.find_one({"type": "compliance"})["status"] == "resolved"


def test_unused_ports_rule_uses_interface_status():
    config = "interface GigabitEthernet1/0/5\n!\ninterface GigabitEthernet1/0/6\n shutdown\n" \
             "interface GigabitEthernet1/0/7\n"
    interfaces = [
        {"descr": "GigabitEthernet1/0/5", "admin_status": "up", "oper_status": "down"},
        {"descr": "GigabitEthernet1/0/6", "admin_status": "down", "oper_status": "down"},
        {"name": "Gi1/0/7", "admin_status": "up", "oper_status": "up"},
    ]
    report = compliance.evaluate(config, "cisco_ios", {}, interfaces)
    unused = next(f for f in report.findings if f.rule == "unused_ports_up")
    assert unused.items == ["GigabitEthernet1/0/5"]


def test_routeros_rules():
    text = "/ip service\nset telnet disabled=yes\n/ip ssh\nset strong-crypto=yes\n"
    report = compliance.evaluate(text, "mikrotik_routeros", {"snmp_default_community": False})
    assert [(f.rule, f.items) for f in report.findings] == [
        ("insecure_services", ["ftp", "www"])]
    assert report.score == 90


# ------------------------------------------------------------------ unconfigured

def test_unconfigured_from_snmp_and_config(client, sync_db):
    fresh = core(sys_name="Switch", mgmt_ip="10.10.99.50", links=[], mac_table=[])
    fresh["interfaces"] = [{"if_index": 1, "name": "Vl1", "descr": "Vlan1", "if_type": 53,
                            "oper_status": "up"}]
    fresh["addresses"] = [{"ip": "10.10.99.50", "if_index": 1, "prefixlen": 24}]
    fresh["neighbors"] = []
    agent = seed_report(client, sync_db, fresh)
    device = sync_db.devices.find_one({"mgmt_ip": "10.10.99.50"})
    assert device["unconfigured"]["flag"] is True
    assert device["unconfigured"]["reasons"] == ["Default host name (Switch)",
                                                 "No VLANs configured besides VLAN 1"]
    factory = "hostname Switch\ninterface Vlan1\n ip address dhcp\nline vty 0 4\nend\n"
    upload(client, agent, str(device["_id"]), factory)
    reasons = sync_db.devices.find_one({"_id": device["_id"]})["unconfigured"]["reasons"]
    assert "No static management IP address (DHCP or none)" in reasons
    as_role(client, sync_db, "viewer")
    row = next(d for d in client.get("/api/configs").json() if d["mgmt_ip"] == "10.10.99.50")
    assert row["unconfigured"]["flag"] is True and row["backup"]["version"] == 1


def test_configured_device_is_not_flagged():
    device = {"sys_name": "CORE-SW-1"}
    assert unconfigured_reasons(device, [], CORE_CONFIG) == []  # layer 3 switch: routed uplink


def test_router_is_not_expected_to_have_vlans_or_a_gateway():
    router = ("hostname EDGE-RTR-1\n"
              "interface GigabitEthernet0/0\n ip address 10.10.0.1 255.255.255.252\n"
              "interface GigabitEthernet0/1\n ip address 203.0.113.2 255.255.255.0\nend\n")
    assert unconfigured_reasons({"sys_name": "EDGE-RTR-1"}, [], router) == []
    # From SNMP alone: an address on a routed port, or VLANs seen in the MAC table.
    assert unconfigured_reasons({"sys_name": "R1"}, [], None, {"routed": True}) == []
    assert unconfigured_reasons({"sys_name": "SW"}, [], None, {"vlans": [10, 20]}) == []
    assert unconfigured_reasons({"sys_name": "SW"}, [], None, {"vlans": []}) == [
        "No VLANs configured besides VLAN 1"]


def test_diff_collapses_unchanged_runs():
    old = "\n".join(f"line {n}" for n in range(1, 21))
    new = old.replace("line 10", "line ten")
    rows = diff_rows(old, new, context=2)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["skip", "same", "same", "changed", "same", "same", "skip"]
    assert rows[0]["count"] == 7 and rows[3]["left"] == "line 10" and rows[3]["right"] == "line ten"
