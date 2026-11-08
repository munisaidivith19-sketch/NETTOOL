"""Two-step sign-in (TOTP MFA), Phase 8."""

import json
import logging
import re
from datetime import timedelta

import pyotp
import pytest

from app.security import mfa
from app.security.sessions import utcnow
from tests.conftest import PASSWORD, TOTP_SECRET, add_user, csrf, login, totp_code


def password_step(client, username="admin1"):
    client.cookies.clear()
    response = client.post("/api/auth/login", json={"username": username, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return response


def reasons(sync_db, action="auth.mfa_failure"):
    entries = sync_db.audit_log.find({"action": action}).sort("_id", 1)
    return [e["details"].get("reason") for e in entries]


# ---- sign-in -------------------------------------------------------------------------------

def test_password_alone_gives_no_session(client, sync_db):
    add_user(sync_db, "admin1", "admin")
    response = password_step(client)
    assert response.json() == {"mfa_required": True}
    assert "netmap_session" not in response.cookies
    cookie = next(c for c in client.cookies.jar if c.name == "netmap_mfa")
    assert cookie.path == "/api/auth/mfa" and cookie.secure
    assert "httponly" in response.headers["set-cookie"].lower()
    assert client.get("/api/auth/me").status_code == 401
    assert client.get("/api/devices").status_code == 401


def test_right_code_finishes_sign_in(client, sync_db):
    add_user(sync_db, "admin1", "admin")
    password_step(client)
    response = client.post("/api/auth/mfa/verify", json={"code": totp_code()})
    assert response.status_code == 200
    token = response.json()["csrf_token"]
    assert client.get("/api/users").status_code == 200
    assert client.post("/api/auth/logout", headers=csrf(token)).status_code == 204
    entry = sync_db.audit_log.find_one({"action": "auth.login", "result": "success"})
    assert entry["details"] == {"mfa": "totp"}
    assert sync_db.mfa_challenges.count_documents({}) == 0  # used up


def test_challenge_token_is_not_a_session(client, sync_db):
    add_user(sync_db, "admin1", "admin")
    password_step(client)
    token = client.cookies.get("netmap_mfa")
    client.cookies.clear()
    client.cookies.set("netmap_session", token)
    assert client.get("/api/auth/me").status_code == 401


def test_verify_without_challenge_rejected(client, sync_db):
    add_user(sync_db, "admin1", "admin")
    response = client.post("/api/auth/mfa/verify", json={"code": totp_code()})
    assert response.status_code == 401


def test_wrong_code_rejected_and_counted(client, sync_db):
    uid = add_user(sync_db, "admin1", "admin")
    password_step(client)
    wrong = "000000" if totp_code() != "000000" else "111111"
    response = client.post("/api/auth/mfa/verify", json={"code": wrong})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired code"
    assert sync_db.users.find_one({"_id": uid})["failed_logins"] == 1
    assert reasons(sync_db) == ["bad_code"]


def test_code_cannot_be_replayed(client, sync_db):
    add_user(sync_db, "admin1", "admin")
    code = totp_code()
    password_step(client)
    assert client.post("/api/auth/mfa/verify", json={"code": code}).status_code == 200
    password_step(client)
    response = client.post("/api/auth/mfa/verify", json={"code": code})
    assert response.status_code == 401
    assert reasons(sync_db) == ["code_reused"]


def test_neighbouring_step_accepted_but_not_older(client, sync_db):
    add_user(sync_db, "admin1", "admin")
    totp = pyotp.TOTP(TOTP_SECRET)
    now = utcnow()
    password_step(client)
    previous = totp.at(now - timedelta(seconds=30))
    assert client.post("/api/auth/mfa/verify", json={"code": previous}).status_code == 200
    password_step(client)
    too_old = totp.at(now - timedelta(seconds=120))
    assert client.post("/api/auth/mfa/verify", json={"code": too_old}).status_code == 401


def test_challenge_allows_five_attempts(client, sync_db):
    add_user(sync_db, "admin1", "admin")
    password_step(client)
    wrong = "000000" if totp_code() != "000000" else "111111"
    for _ in range(mfa.CHALLENGE_MAX_ATTEMPTS):
        assert client.post("/api/auth/mfa/verify", json={"code": wrong}).status_code == 401
    response = client.post("/api/auth/mfa/verify", json={"code": totp_code()})
    assert response.status_code == 401
    assert reasons(sync_db)[-1] == "too_many_attempts"


def test_wrong_codes_lock_the_account_and_alert(client, sync_db):
    uid = add_user(sync_db, "admin1", "admin")
    wrong = "000000" if totp_code() != "000000" else "111111"
    for _ in range(5):
        password_step(client)
        client.post("/api/auth/mfa/verify", json={"code": wrong})
    assert sync_db.users.find_one({"_id": uid})["locked_until"] > utcnow()
    alert = sync_db.alerts.find_one({"key": f"security:lockout:{uid}"})
    assert alert["type"] == "security" and alert["status"] == "open"
    # Locked: even the password step now fails.
    client.cookies.clear()
    response = client.post("/api/auth/login", json={"username": "admin1", "password": PASSWORD})
    assert response.status_code == 401


def test_expired_challenge_rejected(client, sync_db):
    add_user(sync_db, "admin1", "admin")
    password_step(client)
    sync_db.mfa_challenges.update_many({}, {"$set": {"expires_at": utcnow() - timedelta(1)}})
    assert client.post("/api/auth/mfa/verify", json={"code": totp_code()}).status_code == 401


@pytest.mark.parametrize("body", [
    {}, {"code": "12345"}, {"code": "abcdef"}, {"code": {"$ne": None}},
    {"code": "123456", "recovery_code": "ABCDE-FGHJK"}, {"code": "123456", "extra": 1},
])
def test_bad_verify_bodies_rejected(client, sync_db, body):
    add_user(sync_db, "admin1", "admin")
    password_step(client)
    assert client.post("/api/auth/mfa/verify", json=body).status_code == 422


# ---- enrolment -----------------------------------------------------------------------------

def enrol(client, sync_db, username="admin1", role="admin") -> tuple[str, str, list[str]]:
    """Set MFA up through the API. Returns (csrf token, secret, recovery codes)."""
    token = login(client, username)
    setup = client.post("/api/auth/mfa/setup", headers=csrf(token))
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    enabled = client.post("/api/auth/mfa/enable", headers=csrf(token),
                          json={"code": pyotp.TOTP(secret).now()})
    assert enabled.status_code == 200, enabled.text
    return enabled.json()["session"]["csrf_token"], secret, enabled.json()["recovery_codes"]


def test_admin_without_mfa_must_set_it_up(client, sync_db):
    add_user(sync_db, "admin1", "admin", mfa=False)
    token = login(client, "admin1")  # no MFA yet: password only
    me = client.get("/api/auth/me").json()
    assert me["user"]["mfa_setup_required"] is True
    for path in ("/api/users", "/api/devices", "/api/dashboard/summary"):
        response = client.get(path)
        assert response.status_code == 403 and response.json()["detail"] == "mfa_setup_required"
    assert client.get("/api/auth/mfa").json() == {"enabled": False, "required": True,
                                                  "recovery_codes_left": 0}

    setup = client.post("/api/auth/mfa/setup", headers=csrf(token)).json()
    assert re.fullmatch(r"[A-Z2-7]{32}", setup["secret"])
    assert setup["otpauth_uri"].startswith("otpauth://totp/NetMap:admin1?")
    assert len(setup["qr"]) == len(setup["qr"][0]) and set("".join(setup["qr"])) == {"0", "1"}
    stored = sync_db.users.find_one({"username": "admin1"})["mfa"]
    assert setup["secret"] not in json.dumps(stored, default=str)  # encrypted at rest

    wrong = client.post("/api/auth/mfa/enable", headers=csrf(token), json={"code": "000000"})
    assert wrong.status_code == 400 or pyotp.TOTP(setup["secret"]).now() == "000000"
    enabled = client.post("/api/auth/mfa/enable", headers=csrf(token),
                          json={"code": pyotp.TOTP(setup["secret"]).now()})
    assert enabled.status_code == 200
    codes = enabled.json()["recovery_codes"]
    assert len(set(codes)) == 10
    assert all(re.fullmatch(r"[2-9A-HJ-NP-Z]{5}-[2-9A-HJ-NP-Z]{5}", c) for c in codes)
    new_token = enabled.json()["session"]["csrf_token"]
    assert new_token != token  # session rotated
    assert client.get("/api/users").status_code == 200
    stored = sync_db.users.find_one({"username": "admin1"})["mfa"]
    assert stored["enabled"] and "pending_ct" not in stored
    assert not any(c in json.dumps(stored, default=str) for c in codes)  # hashed
    assert sync_db.audit_log.count_documents({"action": "auth.mfa_enable",
                                              "result": "success"}) == 1


def test_enable_signs_out_other_sessions(client, sync_db):
    add_user(sync_db, "admin1", "admin", mfa=False)
    login(client, "admin1")
    sync_db.sessions.insert_one({**sync_db.sessions.find_one({}, {"_id": 0}),
                                 "token_hash": "other-device"})
    enrol(client, sync_db)
    assert sync_db.sessions.count_documents({}) == 1


def test_setup_expires(client, sync_db):
    add_user(sync_db, "admin1", "admin", mfa=False)
    token = login(client, "admin1")
    secret = client.post("/api/auth/mfa/setup", headers=csrf(token)).json()["secret"]
    sync_db.users.update_one({"username": "admin1"},
                             {"$set": {"mfa.pending_at": utcnow() - timedelta(minutes=11)}})
    response = client.post("/api/auth/mfa/enable", headers=csrf(token),
                           json={"code": pyotp.TOTP(secret).now()})
    assert response.status_code == 409


def test_setup_needs_password_change_first(client, sync_db):
    add_user(sync_db, "admin1", "admin", mfa=False, must_change=True)
    token = login(client, "admin1")
    assert client.post("/api/auth/mfa/setup", headers=csrf(token)).status_code == 403


def test_setup_refused_when_already_on(client, sync_db):
    add_user(sync_db, "admin1", "admin")
    token = login(client, "admin1")
    assert client.post("/api/auth/mfa/setup", headers=csrf(token)).status_code == 409


def test_setup_needs_csrf(client, sync_db):
    add_user(sync_db, "admin1", "admin", mfa=False)
    login(client, "admin1")
    assert client.post("/api/auth/mfa/setup").status_code == 403


def test_promoted_user_is_stopped_until_enrolled(client, sync_db):
    add_user(sync_db, "admin1", "admin")
    add_user(sync_db, "erin", "engineer")
    admin_token = login(client, "admin1")
    erin = sync_db.users.find_one({"username": "erin"})
    client.patch(f"/api/users/{erin['_id']}", headers=csrf(admin_token), json={"role": "admin"})
    login(client, "erin")
    response = client.get("/api/devices")
    assert response.status_code == 403 and response.json()["detail"] == "mfa_setup_required"


def test_viewer_may_use_mfa_optionally(client, sync_db):
    add_user(sync_db, "vera", "viewer")
    login(client, "vera")
    assert client.get("/api/devices").status_code == 200  # not required for viewers
    enrol(client, sync_db, "vera", "viewer")
    assert password_step(client, "vera").json() == {"mfa_required": True}


# ---- recovery codes ------------------------------------------------------------------------

def test_recovery_code_works_once(client, sync_db):
    add_user(sync_db, "admin1", "admin", mfa=False)
    _, _, codes = enrol(client, sync_db)
    password_step(client)
    response = client.post("/api/auth/mfa/verify", json={"recovery_code": codes[0].lower()})
    assert response.status_code == 200
    assert response.json()["recovery_codes_left"] == 9
    assert sync_db.audit_log.find_one({"action": "auth.login", "result": "success",
                                       "details.mfa": "recovery_code"})
    password_step(client)
    assert client.post("/api/auth/mfa/verify",
                       json={"recovery_code": codes[0]}).status_code == 401
    assert reasons(sync_db)[-1] == "bad_recovery_code"


def test_new_recovery_codes_replace_old_ones(client, sync_db):
    add_user(sync_db, "admin1", "admin", mfa=False)
    token, secret, old = enrol(client, sync_db)
    sync_db.users.update_one({"username": "admin1"}, {"$set": {"mfa.last_step": None}})
    assert client.post("/api/auth/mfa/recovery-codes", headers=csrf(token),
                       json={"code": "000000" if pyotp.TOTP(secret).now() != "000000"
                             else "111111"}).status_code == 400
    response = client.post("/api/auth/mfa/recovery-codes", headers=csrf(token),
                           json={"code": pyotp.TOTP(secret).now()})
    assert response.status_code == 200
    new = response.json()["recovery_codes"]
    assert not set(new) & set(old)
    password_step(client)
    assert client.post("/api/auth/mfa/verify", json={"recovery_code": old[1]}).status_code == 401
    password_step(client)
    assert client.post("/api/auth/mfa/verify", json={"recovery_code": new[1]}).status_code == 200


# ---- turning it off / resetting ------------------------------------------------------------

def test_admin_cannot_disable(client, sync_db):
    add_user(sync_db, "admin1", "admin")
    token = login(client, "admin1")
    response = client.post("/api/auth/mfa/disable", headers=csrf(token),
                           json={"password": PASSWORD, "code": totp_code()})
    assert response.status_code == 403


def test_disable_needs_password_and_code(client, sync_db):
    add_user(sync_db, "vera", "viewer", mfa=True)
    token = login(client, "vera")
    sync_db.users.update_one({"username": "vera"}, {"$set": {"mfa.last_step": None}})
    bad_password = client.post("/api/auth/mfa/disable", headers=csrf(token),
                               json={"password": "Wrong-Password-11", "code": totp_code()})
    assert bad_password.status_code == 400
    ok = client.post("/api/auth/mfa/disable", headers=csrf(token),
                     json={"password": PASSWORD, "code": totp_code()})
    assert ok.status_code == 204
    assert "mfa" not in sync_db.users.find_one({"username": "vera"})


def test_admin_resets_another_users_mfa(client, sync_db):
    add_user(sync_db, "admin1", "admin")
    other = add_user(sync_db, "admin2", "admin")
    login(client, "admin2")
    token = login(client, "admin1")
    response = client.post(f"/api/users/{other}/mfa/reset", headers=csrf(token))
    assert response.status_code == 200 and response.json()["mfa_enabled"] is False
    assert "mfa" not in sync_db.users.find_one({"_id": other})
    assert sync_db.sessions.count_documents({"user_id": other}) == 0
    entry = sync_db.audit_log.find_one({"action": "user.mfa_reset"})
    assert entry["target"]["username"] == "admin2" and entry["details"]["was_enabled"]


def test_admin_cannot_reset_own_mfa(client, sync_db):
    uid = add_user(sync_db, "admin1", "admin")
    token = login(client, "admin1")
    assert client.post(f"/api/users/{uid}/mfa/reset", headers=csrf(token)).status_code == 409


def test_viewer_cannot_reset_mfa(client, sync_db):
    other = add_user(sync_db, "admin1", "admin")
    add_user(sync_db, "vera", "viewer")
    token = login(client, "vera")
    assert client.post(f"/api/users/{other}/mfa/reset", headers=csrf(token)).status_code == 403


def test_users_list_shows_mfa(client, sync_db):
    add_user(sync_db, "admin1", "admin")
    add_user(sync_db, "vera", "viewer")
    login(client, "admin1")
    users = {u["username"]: u for u in client.get("/api/users").json()}
    assert users["admin1"]["mfa_enabled"] and not users["vera"]["mfa_enabled"]


# ---- secrets stay secret -------------------------------------------------------------------

def test_mfa_secrets_never_logged_or_audited(client, sync_db, caplog):
    caplog.set_level(logging.DEBUG)
    add_user(sync_db, "admin1", "admin", mfa=False)
    token, secret, codes = enrol(client, sync_db)
    password_step(client)
    client.post("/api/auth/mfa/verify", json={"recovery_code": codes[0]})
    password_step(client)
    client.post("/api/auth/mfa/verify", json={"code": "000000"})
    audit = json.dumps(list(sync_db.audit_log.find({}, {"_id": 0})), default=str)
    for value in [secret, *codes]:
        assert value not in caplog.text
        assert value not in audit
