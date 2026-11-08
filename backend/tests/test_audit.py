from tests.conftest import PASSWORD, add_user, csrf, login


def _actions(sync_db):
    return [e["action"] for e in sync_db.audit_log.find({}).sort("at", 1)]


def test_login_events_audited(client, sync_db):
    add_user(sync_db, "alice")
    client.post("/api/auth/login", json={"username": "alice", "password": "Wrong-Password-1"})
    token = login(client, "alice")
    client.post("/api/auth/logout", headers=csrf(token))
    entries = list(sync_db.audit_log.find({}).sort("at", 1))
    assert [(e["action"], e["result"]) for e in entries] == [
        ("auth.login", "failure"),
        ("auth.login", "success"),
        ("auth.logout", "success"),
    ]
    success = entries[1]
    assert success["actor"]["username"] == "alice"
    assert success["ip"] and success["request_id"] and success["at"]


def test_admin_actions_audited(client, sync_db):
    add_user(sync_db, "admin1", "admin")
    token = login(client, "admin1")
    user = client.post("/api/users", headers=csrf(token), json={
        "username": "carol", "password": "Copper-Harbor-93-Falcon", "role": "viewer"}).json()
    client.patch(f"/api/users/{user['id']}", headers=csrf(token), json={"role": "engineer"})
    client.patch(f"/api/users/{user['id']}", headers=csrf(token), json={"disabled": True})
    client.post(f"/api/users/{user['id']}/reset-password", headers=csrf(token),
                json={"new_password": "Velvet-Summit-28-Copper"})
    agent = client.post("/api/agents", headers=csrf(token), json={"name": "lab"}).json()
    client.post(f"/api/agents/{agent['id']}/revoke", headers=csrf(token))
    # The admin's sign-in is two entries: the password step and the MFA code step.
    assert _actions(sync_db)[:2] == ["auth.mfa_challenge", "auth.login"]
    assert _actions(sync_db)[2:] == [
        "user.create", "user.role_change", "user.disable", "user.password_reset",
        "agent.create", "agent.revoke",
    ]


def test_audit_log_contains_no_secrets(client, sync_db):
    add_user(sync_db, "admin1", "admin")
    token = login(client, "admin1")
    client.post("/api/users", headers=csrf(token), json={
        "username": "carol", "password": "Copper-Harbor-93-Falcon", "role": "viewer"})
    key = client.post("/api/agents", headers=csrf(token), json={"name": "lab"}).json()["key"]
    everything = str(list(sync_db.audit_log.find({})))
    for secret in (PASSWORD, "Copper-Harbor-93-Falcon", key, token):
        assert secret not in everything


def test_audit_api_filters_and_pages(client, sync_db):
    add_user(sync_db, "admin1", "admin")
    token = login(client, "admin1")
    for _ in range(3):
        client.post("/api/agents", headers=csrf(token), json={"name": "lab"})
    page = client.get("/api/audit", params={"action": "agent", "limit": 2}).json()
    assert [e["action"] for e in page["items"]] == ["agent.create", "agent.create"]
    older = client.get("/api/audit", params={"action": "agent", "before": page["next_before"]})
    assert len(older.json()["items"]) == 1
    assert client.get("/api/audit", params={"actor": "admin1"}).json()["items"]


def test_audit_filters_reject_injection(client, admin):
    for params in ({"action": ".*"}, {"action": "auth|user"}, {"actor": "$ne"},
                   {"limit": 100000}):
        assert client.get("/api/audit", params=params).status_code == 422
