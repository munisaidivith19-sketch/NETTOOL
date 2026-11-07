"""Change requests: templates, denylist, four-eyes approval, signed jobs, agent results."""

from datetime import timedelta

import pytest
from bson import ObjectId

from app.config_mgmt.jobsign import verify_job
from app.config_mgmt.templates import TemplateError, render_text
from app.security.sessions import utcnow
from tests.config_helpers import CORE_CONFIG, agent_call, fingerprint, seed_core, upload
from tests.conftest import add_user, csrf, login
from tests.ipam_helpers import as_role
from tests.test_ingest import _new_agent

BASELINE_VARS = {"hostname": "CORE-SW-1", "domain_name": "campus.example",
                 "mgmt_ip": "10.10.99.2/24", "default_gateway": "10.10.99.254"}
SAFE_COMMANDS = "vlan 40\n name GUESTS\n"


def engineer(client, sync_db, name: str) -> dict:
    if sync_db.users.find_one({"username": name}) is None:
        add_user(sync_db, name, "engineer")
    return csrf(login(client, name))


def create(client, headers, device_id, **body):
    payload = {"title": "Add guest VLAN", "device_id": device_id} | (
        body or {"commands": SAFE_COMMANDS})
    return client.post("/api/changes", headers=headers, json=payload)


def submitted(client, sync_db, device_id, **body) -> str:
    """A change created and submitted by eng1, waiting for approval."""
    headers = engineer(client, sync_db, "eng1")
    response = create(client, headers, device_id, **body)
    assert response.status_code == 201, response.text
    change_id = response.json()["id"]
    response = client.post(f"/api/changes/{change_id}/submit", headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "pending_approval"
    return change_id


def approved(client, sync_db, device_id) -> str:
    change_id = submitted(client, sync_db, device_id)
    response = client.post(f"/api/changes/{change_id}/approve",
                           headers=engineer(client, sync_db, "eng2"), json={})
    assert response.status_code == 200, response.text
    return change_id


# ------------------------------------------------------------------ templates & preview

def test_template_preview_renders_and_checks(client, sync_db):
    _, device_id = seed_core(client, sync_db)
    response = client.post("/api/changes/preview", headers=engineer(client, sync_db, "eng1"),
                           json={"device_id": device_id, "template": "cisco_ios/baseline",
                                 "variables": BASELINE_VARS})
    body = response.json()
    assert response.status_code == 200, body
    assert body["commands"].startswith("archive\n path flash:archive")
    assert " ip address 10.10.99.2 255.255.255.0" in body["commands"]
    assert body["violations"] == []
    # Ports with an LLDP neighbour are protected (topology_helpers: Gi1/0/1 and Gi1/0/2).
    assert "GigabitEthernet1/0/2" in body["protected_interfaces"]
    assert sync_db.change_requests.count_documents({}) == 0  # a preview stores nothing


def test_missing_template_variable_is_rejected(client, sync_db):
    _, device_id = seed_core(client, sync_db)
    variables = {k: v for k, v in BASELINE_VARS.items() if k != "hostname"}
    response = client.post("/api/changes/preview", headers=engineer(client, sync_db, "eng1"),
                           json={"device_id": device_id, "template": "cisco_ios/baseline",
                                 "variables": variables})
    assert response.status_code == 422
    assert response.json()["violations"][0]["text"] == "hostname"


def test_strict_undefined_in_the_sandbox():
    with pytest.raises(TemplateError, match="'vlan_id' is undefined"):
        render_text("vlan {{ vlan_id }}\n", {})
    with pytest.raises(TemplateError, match="unsafe"):
        render_text("{{ ''.__class__.__mro__ }}", {})


@pytest.mark.parametrize("variables", [
    BASELINE_VARS | {"hostname": "core sw\nreload"},     # newline would add a command
    BASELINE_VARS | {"hostname": "x" * 70},
    BASELINE_VARS | {"mgmt_ip": "10.10.99.0/24"},        # network address
    BASELINE_VARS | {"default_gateway": "192.168.1.1"},  # not in the management subnet
    BASELINE_VARS | {"banner": "hi^reload"},             # the banner delimiter
    BASELINE_VARS | {"mgmt_vlan": 5000},
    BASELINE_VARS | {"shutdown_ports": ["Gi1/0/3; reload"]},
    BASELINE_VARS | {"unexpected": "x"},
])
def test_bad_template_variables_are_rejected(client, sync_db, variables):
    _, device_id = seed_core(client, sync_db)
    response = client.post("/api/changes/preview", headers=engineer(client, sync_db, "eng1"),
                           json={"device_id": device_id, "template": "cisco_ios/baseline",
                                 "variables": variables})
    assert response.status_code == 422


@pytest.mark.parametrize("body", [
    {"template": "cisco_ios/baseline", "variables": {"$where": "1"}},
    {"template": "../../etc/passwd"},
    {"template": "mikrotik_routeros/baseline", "variables": {}},  # wrong vendor for the device
    {"commands": SAFE_COMMANDS, "template": "cisco_ios/vlan"},   # both sources
    {},                                                          # neither
])
def test_bad_change_sources(client, sync_db, body):
    _, device_id = seed_core(client, sync_db)
    response = client.post("/api/changes/preview", headers=engineer(client, sync_db, "eng1"),
                           json={"device_id": device_id} | body)
    assert response.status_code == 422


def test_device_without_backup_cannot_be_changed(client, sync_db):
    _, device_id = seed_core(client, sync_db, config=None)
    response = create(client, engineer(client, sync_db, "eng1"), device_id)
    assert response.status_code == 409 and "backup" in response.json()["detail"]


# ------------------------------------------------------------------ denylist & secrets

@pytest.mark.parametrize(("commands", "reason"), [
    ("reload\n", "restarts the device"),
    ("wr er\n", "erases"),
    ("interface GigabitEthernet1/0/2\n shutdown\n", "management or uplink"),
    ("username bob privilege 15 secret Hunter2-Hunter2\n", "Secrets can't be stored"),
    ("snmp-server community s3cret RO\n", "Secrets can't be stored"),
])
def test_denylisted_change_is_blocked_on_the_backend(client, sync_db, commands, reason):
    _, device_id = seed_core(client, sync_db)
    headers = engineer(client, sync_db, "eng1")
    preview = client.post("/api/changes/preview", headers=headers,
                          json={"device_id": device_id, "commands": commands}).json()
    assert reason in preview["violations"][0]["reason"]
    # The offending line is shown masked (the preview stores nothing).
    assert "Hunter2" not in str(preview["violations"])
    assert "s3cret" not in str(preview["violations"])
    created = create(client, headers, device_id, commands=commands)
    if "Secrets" in reason:
        # Never stored, not even as a draft: the database must not hold device passwords.
        assert created.status_code == 422
        assert sync_db.change_requests.count_documents({}) == 0
        return
    change = created.json()
    assert change["status"] == "draft" and change["violations"]
    response = client.post(f"/api/changes/{change['id']}/submit", headers=headers)
    assert response.status_code == 422 and response.json()["violations"]
    assert sync_db.audit_log.find_one({"action": "change.submit"})["result"] == "denied"


def test_denylist_rechecked_at_approval(client, sync_db):
    _, device_id = seed_core(client, sync_db)
    change_id = submitted(client, sync_db, device_id)
    # Someone edits the stored commands directly in the database after submission.
    sync_db.change_requests.update_one({}, {"$set": {"commands": "reload\n"}})
    response = client.post(f"/api/changes/{change_id}/approve",
                           headers=engineer(client, sync_db, "eng2"), json={})
    assert response.status_code == 422
    assert sync_db.change_requests.find_one()["status"] == "pending_approval"


def test_removing_a_community_is_allowed(client, sync_db):
    _, device_id = seed_core(client, sync_db)
    preview = client.post("/api/changes/preview", headers=engineer(client, sync_db, "eng1"),
                          json={"device_id": device_id,
                                "commands": "no snmp-server community public\n"}).json()
    assert preview["violations"] == []


# ------------------------------------------------------------------ four-eyes

def test_creator_cannot_approve_own_change(client, sync_db):
    _, device_id = seed_core(client, sync_db)
    change_id = submitted(client, sync_db, device_id)
    response = client.post(f"/api/changes/{change_id}/approve",
                           headers=engineer(client, sync_db, "eng1"), json={})
    assert response.status_code == 403
    assert sync_db.audit_log.find_one({"action": "change.approve"})["result"] == "denied"
    assert sync_db.change_requests.find_one()["status"] == "pending_approval"


def test_admin_override_needs_a_reason_and_is_audited(client, sync_db):
    _, device_id = seed_core(client, sync_db)
    admin = as_role(client, sync_db, "admin")
    change_id = create(client, admin, device_id).json()["id"]
    client.post(f"/api/changes/{change_id}/submit", headers=admin)
    path = f"/api/changes/{change_id}/approve"
    assert client.post(path, headers=admin, json={}).status_code == 403
    assert client.post(path, headers=admin, json={"override_reason": "short"}).status_code == 422
    response = client.post(path, headers=admin,
                           json={"override_reason": "Outage: no second engineer on call"})
    assert response.status_code == 200
    assert response.json()["override_reason"] == "Outage: no second engineer on call"
    entry = sync_db.audit_log.find_one({"action": "change.approve_override"})
    assert entry["details"]["override_reason"].startswith("Outage")


def test_viewer_reads_but_cannot_act(client, sync_db):
    _, device_id = seed_core(client, sync_db)
    change_id = submitted(client, sync_db, device_id)
    viewer = as_role(client, sync_db, "viewer")
    assert client.get("/api/changes").status_code == 200
    assert client.get(f"/api/changes/{change_id}").status_code == 200
    assert client.get("/api/templates").status_code == 200
    assert create(client, viewer, device_id).status_code == 403
    assert client.post("/api/changes/preview", headers=viewer,
                       json={"device_id": device_id, "commands": "x"}).status_code == 403
    assert client.post(f"/api/changes/{change_id}/approve", headers=viewer,
                       json={}).status_code == 403


def test_illegal_transitions(client, sync_db):
    _, device_id = seed_core(client, sync_db)
    eng1 = engineer(client, sync_db, "eng1")
    draft = create(client, eng1, device_id).json()["id"]
    eng2 = engineer(client, sync_db, "eng2")
    assert client.post(f"/api/changes/{draft}/approve", headers=eng2, json={}).status_code == 409
    assert client.post(f"/api/changes/{draft}/reject", headers=eng2,
                       json={"reason": "Not now"}).status_code == 409
    eng1 = engineer(client, sync_db, "eng1")
    assert client.post(f"/api/changes/{draft}/submit", headers=eng1).status_code == 200
    assert client.post(f"/api/changes/{draft}/submit", headers=eng1).status_code == 409
    # Editing needs draft/rejected; a pending change must be rejected (or cancelled) first.
    edit = {"title": "Edited", "device_id": device_id, "commands": "vlan 41\n name X\n"}
    assert client.put(f"/api/changes/{draft}", headers=eng1, json=edit).status_code == 409
    eng2 = engineer(client, sync_db, "eng2")
    assert client.post(f"/api/changes/{draft}/reject", headers=eng2,
                       json={"reason": "Use VLAN 41"}).status_code == 200
    eng1 = engineer(client, sync_db, "eng1")
    response = client.put(f"/api/changes/{draft}", headers=eng1, json=edit)
    assert response.status_code == 200 and response.json()["status"] == "draft"
    statuses = [t["status"] for t in response.json()["timeline"]]
    assert statuses == ["draft", "pending_approval", "rejected", "draft"]


def test_approval_refused_when_device_config_changed(client, sync_db):
    agent, device_id = seed_core(client, sync_db)
    change_id = submitted(client, sync_db, device_id)
    upload(client, agent, device_id, CORE_CONFIG + "ntp server 10.10.99.5\n")
    response = client.post(f"/api/changes/{change_id}/approve",
                           headers=engineer(client, sync_db, "eng2"), json={})
    assert response.status_code == 409 and "changed since" in response.json()["detail"]


# ------------------------------------------------------------------ agent side

def test_signed_job_claim_and_successful_push(client, sync_db):
    agent, device_id = seed_core(client, sync_db)
    change_id = approved(client, sync_db, device_id)
    stored = sync_db.change_requests.find_one()
    assert stored["status"] == "approved" and stored["expires_at"] > utcnow()

    job = agent_call(client, agent, "POST", "/api/agent/jobs/claim", {}).json()["job"]
    assert job["change_id"] == change_id and job["commands"] == SAFE_COMMANDS
    assert job["before_hash"] == fingerprint(CORE_CONFIG)
    assert verify_job(agent["key"], job)  # signed with this agent's own key
    assert not verify_job(agent["key"], job | {"commands": "reload\n"})
    assert agent_call(client, agent, "POST", "/api/agent/jobs/claim", {}).json() == {"job": None}

    path = f"/api/agent/jobs/{change_id}/status"
    assert agent_call(client, agent, "POST", path, {"status": "verifying"}).status_code == 200
    new_config = CORE_CONFIG.replace("vlan 10\n", "vlan 10\nvlan 40\n name GUESTS\n")
    result = {"status": "done", "before_hash": fingerprint(CORE_CONFIG),
              "after_hash": fingerprint(new_config), "log": "Sent `configure confirm`."}
    assert agent_call(client, agent, "POST", path, result).status_code == 200
    upload(client, agent, device_id, new_config, source="post_change", change_id=change_id)

    as_role(client, sync_db, "viewer")
    change = client.get(f"/api/changes/{change_id}").json()
    assert change["status"] == "done" and change["after_version"] == 2
    assert [t["status"] for t in change["timeline"]] == [
        "draft", "pending_approval", "approved", "pushing", "verifying", "done"]
    assert sync_db.change_requests.find_one()["job"] is None  # the signed job isn't kept
    push = sync_db.audit_log.find_one({"action": "change.push"})
    assert push["result"] == "success" and push["details"]["after_hash"] == result["after_hash"]
    # A change NetMap made itself is not reported as "changed outside NetMap".
    assert sync_db.alerts.count_documents({"type": "config_changed"}) == 0
    # Late or repeated results are refused.
    assert agent_call(client, agent, "POST", path, {"status": "failed"}).status_code == 409


def test_rollback_raises_a_critical_alert(client, sync_db):
    agent, device_id = seed_core(client, sync_db)
    change_id = approved(client, sync_db, device_id)
    agent_call(client, agent, "POST", "/api/agent/jobs/claim", {})
    agent_call(client, agent, "POST", f"/api/agent/jobs/{change_id}/status",
               {"status": "rolled_back", "error": "verify_failed"})
    alert = sync_db.alerts.find_one({"type": "change_failed"})
    assert alert["severity"] == "critical" and "rolled back" in alert["message"]
    assert sync_db.audit_log.find_one({"action": "change.push"})["result"] == "failure"


def test_other_agents_cannot_claim_or_report(client, sync_db):
    agent, device_id = seed_core(client, sync_db)
    change_id = approved(client, sync_db, device_id)
    other = _new_agent(client, as_role(client, sync_db, "admin")["X-CSRF-Token"], "Other")
    assert agent_call(client, other, "POST", "/api/agent/jobs/claim", {}).json() == {
        "job": None}
    agent_call(client, agent, "POST", "/api/agent/jobs/claim", {})
    for status in ("verifying", "done"):
        response = agent_call(client, other, "POST", f"/api/agent/jobs/{change_id}/status",
                              {"status": status})
        assert response.status_code == 409
    assert sync_db.change_requests.find_one()["status"] == "pushing"


def test_unclaimed_job_expires_and_silent_agent_times_out(client, sync_db):
    agent, device_id = seed_core(client, sync_db)
    first = approved(client, sync_db, device_id)
    sync_db.change_requests.update_one({}, {"$set": {"expires_at": utcnow() - timedelta(1)}})
    assert agent_call(client, agent, "POST", "/api/agent/jobs/claim", {}).json() == {"job": None}
    assert sync_db.change_requests.find_one()["status"] == "expired"

    second = approved(client, sync_db, device_id)
    assert agent_call(client, agent, "POST", "/api/agent/jobs/claim", {}).json()["job"]
    sync_db.change_requests.update_one(
        {"_id": ObjectId(second)}, {"$set": {"claimed_at": utcnow() - timedelta(minutes=31)}})
    agent_call(client, agent, "POST", "/api/agent/jobs/claim", {})
    timed_out = sync_db.change_requests.find_one({"_id": ObjectId(second)})
    assert timed_out["status"] == "failed" and timed_out["result"]["error"] == "agent_timeout"
    assert sync_db.alerts.find_one({"type": "change_failed"})["severity"] == "critical"
    assert first != second


def test_cancel_rules(client, sync_db):
    agent, device_id = seed_core(client, sync_db)
    change_id = approved(client, sync_db, device_id)
    path = f"/api/changes/{change_id}/cancel"
    assert client.post(path, headers=engineer(client, sync_db, "eng2")).status_code == 403
    assert client.post(path, headers=engineer(client, sync_db, "eng1")).status_code == 200
    assert sync_db.change_requests.find_one()["job"] is None
    assert agent_call(client, agent, "POST", "/api/agent/jobs/claim", {}).json() == {"job": None}

    pushing = approved(client, sync_db, device_id)
    agent_call(client, agent, "POST", "/api/agent/jobs/claim", {})
    response = client.post(f"/api/changes/{pushing}/cancel",
                           headers=engineer(client, sync_db, "eng1"))
    assert response.status_code == 409


@pytest.mark.parametrize("query", ["status=$ne", "device_id=zz", "limit=0"])
def test_list_filters_are_validated(client, sync_db, query):
    as_role(client, sync_db, "viewer")
    assert client.get(f"/api/changes?{query}").status_code == 422
