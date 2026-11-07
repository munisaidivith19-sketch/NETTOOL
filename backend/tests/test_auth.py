from datetime import timedelta

from app.security.rate_limit import IP_MAX_FAILURES, LOCK_AFTER_FAILURES
from app.security.sessions import COOKIE_NAME, hash_token, utcnow
from tests.conftest import PASSWORD, add_user, csrf, login


def _login(client, username, password=PASSWORD):
    client.cookies.clear()
    return client.post("/api/auth/login", json={"username": username, "password": password})


def test_login_sets_hardened_cookie(client, sync_db):
    add_user(sync_db, "alice")
    response = _login(client, "alice")
    assert response.status_code == 200
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{COOKIE_NAME}=")
    for flag in ("HttpOnly", "Secure", "SameSite=strict", "Path=/"):
        assert flag.lower() in cookie.lower(), flag
    body = response.json()
    assert body["user"]["username"] == "alice"
    assert "password_hash" not in response.text
    assert len(body["csrf_token"]) >= 32


def test_session_token_stored_only_as_hash(client, sync_db):
    add_user(sync_db, "alice")
    _login(client, "alice")
    token = client.cookies.get(COOKIE_NAME)
    session = sync_db.sessions.find_one({})
    assert session["token_hash"] == hash_token(token)
    assert token not in str(session)


def test_every_login_failure_looks_the_same(client, sync_db):
    add_user(sync_db, "alice")
    add_user(sync_db, "bob", disabled=True)
    answers = {
        (r.status_code, r.text)
        for r in (
            _login(client, "alice", "Wrong-Password-123"),
            _login(client, "nobody", PASSWORD),
            _login(client, "bob", PASSWORD),
        )
    }
    assert answers == {(401, '{"detail":"Invalid username or password"}')}


def test_account_locks_after_five_failures(client, sync_db):
    add_user(sync_db, "alice")
    for _ in range(LOCK_AFTER_FAILURES):
        assert _login(client, "alice", "Wrong-Password-123").status_code == 401
    # Even the right password is refused while locked, with the same generic message.
    response = _login(client, "alice")
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password"
    assert sync_db.audit_log.find_one({"action": "auth.lockout"}) is not None

    # After the lock time has passed, the right password works again.
    sync_db.users.update_one({"username": "alice"},
                             {"$set": {"locked_until": utcnow() - timedelta(seconds=1)}})
    assert _login(client, "alice").status_code == 200


def test_successful_login_resets_failure_count(client, sync_db):
    add_user(sync_db, "alice")
    for _ in range(LOCK_AFTER_FAILURES - 1):
        _login(client, "alice", "Wrong-Password-123")
    assert _login(client, "alice").status_code == 200
    assert sync_db.users.find_one({"username": "alice"})["failed_logins"] == 0


def test_ip_rate_limit(client, sync_db):
    for i in range(IP_MAX_FAILURES):
        assert _login(client, f"user{i}", "Wrong-Password-123").status_code == 401
    add_user(sync_db, "alice")
    response = _login(client, "alice")  # correct password, but this IP is blocked for now
    assert response.status_code == 429


def test_me_requires_login(client):
    assert client.get("/api/auth/me").status_code == 401


def test_me_returns_user_and_csrf(client, sync_db):
    add_user(sync_db, "alice", "engineer")
    token = login(client, "alice")
    body = client.get("/api/auth/me").json()
    assert body["user"]["role"] == "engineer"
    assert body["csrf_token"] == token


def test_logout_invalidates_session_server_side(client, sync_db):
    add_user(sync_db, "alice")
    token = login(client, "alice")
    stolen_cookie = client.cookies.get(COOKIE_NAME)
    assert client.post("/api/auth/logout", headers=csrf(token)).status_code == 204
    assert sync_db.sessions.count_documents({}) == 0
    # Replaying the old cookie (e.g. copied before logout) no longer works.
    client.cookies.clear()
    client.cookies.set(COOKIE_NAME, stolen_cookie)
    assert client.get("/api/auth/me").status_code == 401


def test_idle_timeout(client, sync_db):
    add_user(sync_db, "alice")
    login(client, "alice")
    sync_db.sessions.update_one({}, {"$set": {"last_seen": utcnow() - timedelta(minutes=31)}})
    assert client.get("/api/auth/me").status_code == 401
    assert sync_db.sessions.count_documents({}) == 0


def test_activity_keeps_session_alive(client, sync_db):
    add_user(sync_db, "alice")
    login(client, "alice")
    sync_db.sessions.update_one({}, {"$set": {"last_seen": utcnow() - timedelta(minutes=29)}})
    assert client.get("/api/auth/me").status_code == 200
    last_seen = sync_db.sessions.find_one({})["last_seen"]
    assert utcnow() - last_seen < timedelta(seconds=10)


def test_absolute_expiry(client, sync_db):
    add_user(sync_db, "alice")
    login(client, "alice")
    sync_db.sessions.update_one({}, {"$set": {"expires_at": utcnow() - timedelta(seconds=1)}})
    assert client.get("/api/auth/me").status_code == 401


def test_session_lifetime_is_eight_hours(client, sync_db):
    add_user(sync_db, "alice")
    login(client, "alice")
    session = sync_db.sessions.find_one({})
    assert session["expires_at"] - session["created_at"] == timedelta(hours=8)


def test_login_replaces_presented_session(client, sync_db):
    """Session fixation: a session id planted before login must not survive it."""
    add_user(sync_db, "alice")
    login(client, "alice")
    planted = client.cookies.get(COOKIE_NAME)
    response = client.post("/api/auth/login", json={"username": "alice", "password": PASSWORD})
    assert response.status_code == 200
    assert client.cookies.get(COOKIE_NAME) != planted
    assert sync_db.sessions.find_one({"token_hash": hash_token(planted)}) is None


def test_forced_password_change_flow(client, sync_db):
    add_user(sync_db, "newadmin", "admin", must_change=True)
    token = login(client, "newadmin")
    assert client.get("/api/auth/me").json()["user"]["must_change_password"] is True

    blocked = client.get("/api/users")
    assert blocked.status_code == 403
    assert blocked.json()["detail"] == "password_change_required"

    old_cookie = client.cookies.get(COOKIE_NAME)
    response = client.post("/api/auth/change-password", headers=csrf(token),
                           json={"current_password": PASSWORD,
                                 "new_password": "Quartz-Meadow-71-Signal"})
    assert response.status_code == 200, response.text
    new_token = response.json()["csrf_token"]
    assert new_token != token
    assert client.cookies.get(COOKIE_NAME) != old_cookie  # session rotated
    assert client.get("/api/users").status_code == 200


def test_change_password_revokes_other_sessions(client, sync_db):
    add_user(sync_db, "alice")
    login(client, "alice")
    other_device = client.cookies.get(COOKIE_NAME)
    token = login(client, "alice")
    response = client.post("/api/auth/change-password", headers=csrf(token),
                           json={"current_password": PASSWORD,
                                 "new_password": "Quartz-Meadow-71-Signal"})
    assert response.status_code == 200
    client.cookies.clear()
    client.cookies.set(COOKIE_NAME, other_device)
    assert client.get("/api/auth/me").status_code == 401


def test_change_password_checks_current_and_policy(client, sync_db):
    add_user(sync_db, "alice")
    token = login(client, "alice")
    wrong = client.post("/api/auth/change-password", headers=csrf(token),
                        json={"current_password": "Not-My-Password-9",
                              "new_password": "Quartz-Meadow-71-Signal"})
    assert wrong.status_code == 400
    weak = client.post("/api/auth/change-password", headers=csrf(token),
                       json={"current_password": PASSWORD, "new_password": "short"})
    assert weak.status_code == 422
    same = client.post("/api/auth/change-password", headers=csrf(token),
                       json={"current_password": PASSWORD, "new_password": PASSWORD})
    assert same.status_code == 422
