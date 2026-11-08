"""Repeated failures: the audit log stays bounded and a security alert opens (Phase 8)."""

from app.security.rate_limit import IP_MAX_FAILURES
from app.services.security_events import AUDIT_LIMIT
from tests.conftest import PASSWORD, add_user, csrf, json_bytes, signed_headers

HEARTBEAT = "/api/agent/heartbeat"


def _bad_heartbeat(client, agent_id="agt_" + "0" * 16, key="not-the-key"):
    payload = json_bytes({"agent_version": "0.1.0"})
    headers = signed_headers(agent_id, key, "POST", HEARTBEAT, payload)
    return client.post(HEARTBEAT, content=payload, headers=headers)


def test_agent_auth_flood_is_counted_not_logged(client, sync_db):
    for _ in range(100):
        assert _bad_heartbeat(client).status_code == 401
    entries = list(sync_db.audit_log.find({"action": "agent.auth"}).sort("_id", 1))
    assert len(entries) == AUDIT_LIMIT + 1
    assert entries[-1]["details"]["reason"] == "suppressed"
    event = sync_db.security_events.find_one({"kind": "agent_auth"})
    assert event["count"] == 100
    alerts = list(sync_db.alerts.find({"type": "security"}))
    assert len(alerts) == 1
    assert alerts[0]["key"] == "security:agent_auth:testclient"
    assert alerts[0]["status"] == "open" and alerts[0]["details"]["count"] > AUDIT_LIMIT


def test_few_agent_failures_audited_without_alert(client, sync_db):
    for _ in range(4):
        _bad_heartbeat(client)
    assert sync_db.audit_log.count_documents({"action": "agent.auth"}) == 4
    assert sync_db.alerts.count_documents({}) == 0
    _bad_heartbeat(client)
    assert sync_db.alerts.count_documents({"type": "security"}) == 1


def test_valid_agent_unaffected(client, sync_db, admin):
    agent = client.post("/api/agents", headers=csrf(admin), json={"name": "lab"}).json()
    client.cookies.clear()
    for _ in range(30):
        _bad_heartbeat(client)
    payload = json_bytes({"agent_version": "0.1.0"})
    headers = signed_headers(agent["id"], agent["key"], "POST", HEARTBEAT, payload)
    assert client.post(HEARTBEAT, content=payload, headers=headers).status_code == 200


def test_rate_limited_logins_bounded_and_alerted(client, sync_db):
    for i in range(IP_MAX_FAILURES):
        client.post("/api/auth/login", json={"username": f"u{i}", "password": "Wrong-Pass-123"})
    for _ in range(60):
        response = client.post("/api/auth/login", json={"username": "x", "password": "y"})
        assert response.status_code == 429
    denied = sync_db.audit_log.count_documents({"action": "auth.login", "result": "denied"})
    assert denied == AUDIT_LIMIT + 1
    alert = sync_db.alerts.find_one({"key": "security:login_limited:testclient"})
    assert alert and alert["type"] == "security"


def test_lockout_opens_alert(client, sync_db):
    uid = add_user(sync_db, "alice")
    for _ in range(5):
        client.post("/api/auth/login", json={"username": "alice", "password": "Wrong-Pass-123"})
    alert = sync_db.alerts.find_one({"key": f"security:lockout:{uid}"})
    assert alert["severity"] == "warning"
    assert "alice" in alert["message"]
    assert alert["target"] == {"type": "user", "id": str(uid), "username": "alice"}


def test_change_password_guessing_counts_toward_lockout(client, sync_db):
    from tests.conftest import login

    uid = add_user(sync_db, "alice")
    token = login(client, "alice")
    for _ in range(5):
        response = client.post("/api/auth/change-password", headers=csrf(token), json={
            "current_password": "Wrong-Pass-123", "new_password": "Another-Granite-77-Lamp"})
        assert response.status_code == 400
    assert sync_db.users.find_one({"_id": uid})["locked_until"] is not None
    client.cookies.clear()
    response = client.post("/api/auth/login", json={"username": "alice", "password": PASSWORD})
    assert response.status_code == 401  # locked
