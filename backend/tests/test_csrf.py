from tests.conftest import add_user, csrf, login

NEW_USER = {"username": "carol", "password": "Granite-Lantern-58-Orbit", "role": "viewer"}


def test_state_change_without_csrf_token_refused(client, admin):
    response = client.post("/api/users", json=NEW_USER)
    assert response.status_code == 403
    assert response.json()["detail"] == "Missing or invalid CSRF token"


def test_state_change_with_wrong_csrf_token_refused(client, admin):
    response = client.post("/api/users", json=NEW_USER, headers=csrf("x" * 43))
    assert response.status_code == 403


def test_token_from_another_session_refused(client, sync_db):
    add_user(sync_db, "admin1", "admin")
    add_user(sync_db, "admin2", "admin")
    other_token = login(client, "admin2")
    login(client, "admin1")
    response = client.post("/api/users", json=NEW_USER, headers=csrf(other_token))
    assert response.status_code == 403


def test_state_change_with_correct_token_allowed(client, admin):
    assert client.post("/api/users", json=NEW_USER, headers=csrf(admin)).status_code == 201


def test_reads_do_not_need_a_token(client, admin):
    assert client.get("/api/users").status_code == 200


def test_foreign_origin_refused(client, admin):
    response = client.post("/api/users", json=NEW_USER,
                           headers={**csrf(admin), "Origin": "https://evil.example"})
    assert response.status_code == 403
    assert response.json()["detail"] == "Cross-origin request refused"


def test_null_origin_refused(client, admin):
    response = client.post("/api/users", json=NEW_USER,
                           headers={**csrf(admin), "Origin": "null"})
    assert response.status_code == 403


def test_same_origin_allowed(client, admin):
    response = client.post("/api/users", json=NEW_USER,
                           headers={**csrf(admin), "Origin": "https://testserver"})
    assert response.status_code == 201


def test_login_from_foreign_origin_refused(client, sync_db):
    add_user(sync_db, "alice")
    response = client.post("/api/auth/login", headers={"Origin": "https://evil.example"},
                           json={"username": "alice", "password": "Granite-Lantern-58-Orbit"})
    assert response.status_code == 403


def test_form_post_refused(client, sync_db):
    """An HTML form on another site can only send form encodings, never JSON."""
    add_user(sync_db, "alice")
    response = client.post("/api/auth/login",
                           content="username=alice&password=Granite-Lantern-58-Orbit",
                           headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 415
