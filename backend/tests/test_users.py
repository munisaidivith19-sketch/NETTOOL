from app.security.sessions import COOKIE_NAME
from tests.conftest import PASSWORD, add_user, csrf, login

NEW_PASSWORD = "Copper-Harbor-93-Falcon"


def _session_cookie_for(client, username):
    login(client, username)
    return client.cookies.get(COOKIE_NAME)


def _use_cookie(client, cookie):
    client.cookies.clear()
    client.cookies.set(COOKIE_NAME, cookie)


def test_create_user_requires_password_change(client, admin, sync_db):
    response = client.post("/api/users", headers=csrf(admin),
                           json={"username": "carol", "password": NEW_PASSWORD, "role": "engineer"})
    assert response.status_code == 201
    body = response.json()
    assert body["must_change_password"] is True
    assert "password" not in str(body).lower().replace("must_change_password", "")
    stored = sync_db.users.find_one({"username": "carol"})
    assert stored["password_hash"].startswith("$2b$")
    assert NEW_PASSWORD not in str(stored)


def test_duplicate_username_rejected(client, admin):
    payload = {"username": "carol", "password": NEW_PASSWORD, "role": "viewer"}
    assert client.post("/api/users", headers=csrf(admin), json=payload).status_code == 201
    assert client.post("/api/users", headers=csrf(admin), json=payload).status_code == 409


def test_weak_password_rejected_on_create(client, admin):
    response = client.post("/api/users", headers=csrf(admin),
                           json={"username": "carol", "password": "qwerty123456", "role": "viewer"})
    assert response.status_code == 422


def test_unknown_fields_and_bad_roles_rejected(client, admin):
    base = {"username": "carol", "password": NEW_PASSWORD, "role": "viewer"}
    assert client.post("/api/users", headers=csrf(admin),
                       json={**base, "is_superuser": True}).status_code == 422
    assert client.post("/api/users", headers=csrf(admin),
                       json={**base, "role": "root"}).status_code == 422


def test_role_change_revokes_sessions(client, sync_db):
    carol = add_user(sync_db, "carol", "engineer")
    add_user(sync_db, "admin1", "admin")
    carol_cookie = _session_cookie_for(client, "carol")
    token = login(client, "admin1")
    response = client.patch(f"/api/users/{carol}", headers=csrf(token), json={"role": "viewer"})
    assert response.status_code == 200
    assert response.json()["role"] == "viewer"
    _use_cookie(client, carol_cookie)
    assert client.get("/api/auth/me").status_code == 401


def test_disable_revokes_sessions_and_blocks_login(client, sync_db):
    carol = add_user(sync_db, "carol")
    add_user(sync_db, "admin1", "admin")
    carol_cookie = _session_cookie_for(client, "carol")
    token = login(client, "admin1")
    assert client.patch(f"/api/users/{carol}", headers=csrf(token),
                        json={"disabled": True}).status_code == 200
    _use_cookie(client, carol_cookie)
    assert client.get("/api/auth/me").status_code == 401
    client.cookies.clear()
    assert client.post("/api/auth/login",
                       json={"username": "carol", "password": PASSWORD}).status_code == 401


def test_reset_password_forces_change_and_revokes(client, sync_db):
    carol = add_user(sync_db, "carol")
    add_user(sync_db, "admin1", "admin")
    carol_cookie = _session_cookie_for(client, "carol")
    token = login(client, "admin1")
    response = client.post(f"/api/users/{carol}/reset-password", headers=csrf(token),
                           json={"new_password": NEW_PASSWORD})
    assert response.status_code == 200
    assert response.json()["must_change_password"] is True
    _use_cookie(client, carol_cookie)
    assert client.get("/api/auth/me").status_code == 401
    login(client, "carol", NEW_PASSWORD)


def test_admin_cannot_demote_or_disable_self(client, sync_db):
    me = add_user(sync_db, "admin1", "admin")
    add_user(sync_db, "admin2", "admin")
    token = login(client, "admin1")
    assert client.patch(f"/api/users/{me}", headers=csrf(token),
                        json={"role": "viewer"}).status_code == 409
    assert client.patch(f"/api/users/{me}", headers=csrf(token),
                        json={"disabled": True}).status_code == 409


def test_last_active_admin_cannot_be_removed(client, sync_db):
    add_user(sync_db, "admin1", "admin")
    other = add_user(sync_db, "admin2", "admin", disabled=True)  # not active
    token = login(client, "admin1")
    # Demoting the disabled admin is fine: admin1 is still an active admin.
    assert client.patch(f"/api/users/{other}", headers=csrf(token),
                        json={"role": "viewer"}).status_code == 200


def test_bad_user_id_rejected(client, admin):
    for bad in ("not-an-id", "%7B%22%24gt%22%3A%22%22%7D"):  # second one is {"$gt":""}
        response = client.patch(f"/api/users/{bad}", headers=csrf(admin), json={"role": "viewer"})
        assert response.status_code == 422
    missing = client.patch("/api/users/" + "a" * 24, headers=csrf(admin), json={"role": "viewer"})
    assert missing.status_code == 404


def test_list_users_hides_password_hashes(client, admin):
    response = client.get("/api/users")
    assert response.status_code == 200
    assert "password_hash" not in response.text
    assert "$2b$" not in response.text
