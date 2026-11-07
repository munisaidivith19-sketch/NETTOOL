import time

import pytest

from app.security.sessions import COOKIE_NAME
from tests.conftest import add_user, csrf, json_bytes, login, signed_headers

HEARTBEAT = "/api/agent/heartbeat"


@pytest.fixture
def agent(client, admin):
    response = client.post("/api/agents", headers=csrf(admin), json={"name": "Lab agent"})
    assert response.status_code == 201
    body = response.json()
    client.cookies.clear()  # agent requests below carry no user session
    return body


def _beat(client, agent, body=None, **sign_kwargs):
    payload = json_bytes(body or {"agent_version": "0.1.0"})
    headers = signed_headers(agent["id"], agent["key"], "POST", HEARTBEAT, payload, **sign_kwargs)
    return client.post(HEARTBEAT, content=payload, headers=headers)


def test_key_shown_once_and_never_stored_in_plain(client, admin, sync_db):
    created = client.post("/api/agents", headers=csrf(admin), json={"name": "Lab agent"}).json()
    key = created["key"]
    assert len(key) >= 43  # 32 random bytes, URL-safe base64
    stored = sync_db.agents.find_one({"_id": created["id"]})
    assert key not in str(stored)
    assert stored["key_ciphertext"] != key
    listed = client.get("/api/agents")
    assert key not in listed.text
    assert "key_ciphertext" not in listed.text
    assert listed.json()[0]["key_fingerprint"] == created["key_fingerprint"]


def test_valid_signed_heartbeat(client, agent, sync_db):
    response = _beat(client, agent)
    assert response.status_code == 200, response.text
    assert sync_db.agents.find_one({"_id": agent["id"]})["last_seen_at"] is not None


def test_replayed_request_rejected(client, agent):
    payload = json_bytes({"agent_version": "0.1.0"})
    headers = signed_headers(agent["id"], agent["key"], "POST", HEARTBEAT, payload)
    assert client.post(HEARTBEAT, content=payload, headers=headers).status_code == 200
    assert client.post(HEARTBEAT, content=payload, headers=headers).status_code == 401


def test_tampered_body_rejected(client, agent):
    payload = json_bytes({"agent_version": "0.1.0"})
    headers = signed_headers(agent["id"], agent["key"], "POST", HEARTBEAT, payload)
    tampered = json_bytes({"agent_version": "6.6.6"})
    assert client.post(HEARTBEAT, content=tampered, headers=headers).status_code == 401


def test_wrong_key_rejected(client, agent):
    forged = {**agent, "key": agent["key"][:-4] + "AAAA"}
    assert _beat(client, forged).status_code == 401


@pytest.mark.parametrize("offset", [-301, 301, -3600])
def test_timestamp_outside_window_rejected(client, agent, offset):
    assert _beat(client, agent, timestamp=int(time.time()) + offset).status_code == 401


def test_timestamp_inside_window_accepted(client, agent):
    assert _beat(client, agent, timestamp=int(time.time()) - 120).status_code == 200


def test_unknown_agent_rejected(client, agent):
    stranger = {**agent, "id": "agt_" + "f" * 16}
    assert _beat(client, stranger).status_code == 401


def test_revoked_agent_rejected(client, sync_db):
    add_user(sync_db, "admin1", "admin")
    token = login(client, "admin1")
    created = client.post("/api/agents", headers=csrf(token), json={"name": "Old"}).json()
    assert client.post(f"/api/agents/{created['id']}/revoke",
                       headers=csrf(token)).status_code == 200
    client.cookies.clear()
    assert _beat(client, created).status_code == 401


@pytest.mark.parametrize("drop", ["X-Agent-Id", "X-Timestamp", "X-Nonce", "X-Signature"])
def test_missing_header_rejected(client, agent, drop):
    payload = json_bytes({})
    headers = signed_headers(agent["id"], agent["key"], "POST", HEARTBEAT, payload)
    del headers[drop]
    assert client.post(HEARTBEAT, content=payload, headers=headers).status_code == 401


def test_failures_all_look_the_same_and_are_audited(client, agent, sync_db):
    answers = {
        _beat(client, {**agent, "key": "wrong"}).text,
        _beat(client, agent, timestamp=1).text,
        _beat(client, {**agent, "id": "agt_" + "e" * 16}).text,
    }
    assert answers == {'{"detail":"Agent authentication failed"}'}
    reasons = {e["details"]["reason"] for e in sync_db.audit_log.find({"action": "agent.auth"})}
    assert reasons == {"bad_signature", "timestamp_out_of_window", "unknown_or_revoked_agent"}


def test_agent_headers_cannot_call_user_routes(client, agent):
    headers = signed_headers(agent["id"], agent["key"], "GET", "/api/users")
    assert client.get("/api/users", headers=headers).status_code == 401


def test_session_cookie_ignored_on_agent_routes(client, sync_db):
    add_user(sync_db, "admin1", "admin")
    token = login(client, "admin1")
    assert client.cookies.get(COOKIE_NAME)
    assert client.post(HEARTBEAT, json={}, headers=csrf(token)).status_code == 401


def test_agent_name_validated(client, admin):
    for bad in ("", "x" * 65, "<script>", {"$ne": ""}):
        response = client.post("/api/agents", headers=csrf(admin), json={"name": bad})
        assert response.status_code == 422
