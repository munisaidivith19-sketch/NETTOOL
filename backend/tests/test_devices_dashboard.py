from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.security.sessions import utcnow
from tests.conftest import BASE_URL, make_settings
from tests.ipam_helpers import as_role, core_switch, seed_report, send
from tests.test_ingest import report


def edge_router() -> dict:
    return {**core_switch(), "mgmt_ip": "10.10.99.254", "sys_name": "EDGE-RTR",
            "vendor": "MikroTik", "sys_location": "Roof cabinet", "snmp_version": "v2c",
            "interfaces": [], "addresses": [], "neighbors": []}


def dup_switch() -> dict:
    device = core_switch()
    device["neighbors"].append(
        {"ip": "10.10.10.20", "mac": "00:50:56:00:00:99", "if_index": 10, "kind": "dynamic"})
    return device


# ---- devices ---------------------------------------------------------------------------------

def test_device_list_search_and_filter(client, sync_db):
    seed_report(client, sync_db, core_switch(), edge_router())
    as_role(client, sync_db, "viewer")

    def names(**params):
        r = client.get("/api/devices", params=params)
        assert r.status_code == 200, r.text
        return [d["sys_name"] for d in r.json()]

    assert names() == ["CORE-SW-1", "EDGE-RTR"]
    assert names(q="edge") == ["EDGE-RTR"]
    assert names(q="roof") == ["EDGE-RTR"]          # by location
    assert names(q="10.10.99.1") == ["CORE-SW-1"]   # by management IP
    assert names(q="10.10.99.0/24") == ["CORE-SW-1", "EDGE-RTR"]
    assert names(status="up") == ["CORE-SW-1", "EDGE-RTR"]
    assert names(status="down") == []
    edge = next(d for d in client.get("/api/devices").json() if d["sys_name"] == "EDGE-RTR")
    assert edge["snmp_v2c"] is True


@pytest.mark.parametrize("params", [{"q": '{"$ne":null}'}, {"q": ".*"}, {"status": "$ne"},
                                    {"q": "a" * 101}, {"limit": 0}])
def test_device_list_rejects_bad_params(client, sync_db, params):
    as_role(client, sync_db, "viewer")
    assert client.get("/api/devices", params=params).status_code == 422


def test_device_detail(client, sync_db):
    seed_report(client, sync_db)
    as_role(client, sync_db, "viewer")
    device_id = client.get("/api/devices").json()[0]["id"]
    detail = client.get(f"/api/devices/{device_id}").json()
    assert detail["sys_location"] == "Server room"
    assert [i["name"] for i in detail["interfaces"]] == ["Gi1/0/1", "Vl10"]
    assert {a["ip"] for a in detail["addresses"]} == {"10.10.10.1", "2001:db8:10:10::1",
                                                      "10.10.255.2"}
    assert client.get("/api/devices/" + "0" * 24).status_code == 404
    assert client.get("/api/devices/$ne").status_code == 422


# ---- alert actions ---------------------------------------------------------------------------

def _open_duplicate(client, sync_db):
    agent = seed_report(client, sync_db, dup_switch())
    return agent, sync_db.alerts.find_one({"type": "duplicate_ip"})


def test_acknowledge_and_resolve(client, sync_db):
    _, alert = _open_duplicate(client, sync_db)
    alert_id = str(alert["_id"])
    eng = as_role(client, sync_db, "engineer")

    r = client.post(f"/api/alerts/{alert_id}/acknowledge", headers=eng)
    assert r.status_code == 200
    assert r.json()["acknowledged_by"] == "engineer1" and r.json()["status"] == "open"

    r = client.post(f"/api/alerts/{alert_id}/resolve", headers=eng)
    assert r.status_code == 200
    assert (r.json()["status"], r.json()["resolved_by"]) == ("resolved", "engineer1")
    assert client.post(f"/api/alerts/{alert_id}/resolve", headers=eng).status_code == 409
    assert client.post("/api/alerts/" + "0" * 24 + "/resolve", headers=eng).status_code == 404

    assert client.get("/api/alerts").json() == []
    every = client.get("/api/alerts", params={"status": "all"}).json()
    assert [a["id"] for a in every] == [alert_id]
    actions = [e["action"] for e in sync_db.audit_log.find({"target.type": "alert"})]
    assert sorted(actions) == ["alert.acknowledge", "alert.resolve"]


def test_resolved_by_hand_reopens_if_problem_remains(client, sync_db):
    agent, alert = _open_duplicate(client, sync_db)
    eng = as_role(client, sync_db, "engineer")
    client.post(f"/api/alerts/{alert['_id']}/acknowledge", headers=eng)
    client.post(f"/api/alerts/{alert['_id']}/resolve", headers=eng)

    assert send(client, agent, report(dup_switch())).status_code == 200  # still duplicated
    alert = sync_db.alerts.find_one({"_id": alert["_id"]})
    assert alert["status"] == "open" and alert["occurrences"] == 2
    assert alert["acknowledged_by"] is None and alert["resolved_by"] is None


def test_auto_resolve_clears_resolved_by(client, sync_db):
    agent, alert = _open_duplicate(client, sync_db)
    sync_db.arp_entries.update_one({"mac": "00:50:56:00:00:99"},
                                   {"$set": {"last_seen": utcnow() - timedelta(hours=3)}})
    assert send(client, agent, report()).status_code == 200
    alert = sync_db.alerts.find_one({"_id": alert["_id"]})
    assert alert["status"] == "resolved" and alert["resolved_by"] is None


def test_viewer_cannot_act_on_alerts(client, sync_db):
    _, alert = _open_duplicate(client, sync_db)
    viewer = as_role(client, sync_db, "viewer")
    for action in ("acknowledge", "resolve"):
        assert client.post(f"/api/alerts/{alert['_id']}/{action}",
                           headers=viewer).status_code == 403
    assert sync_db.alerts.find_one({"_id": alert["_id"]})["status"] == "open"


def test_alert_action_needs_csrf(client, sync_db):
    _, alert = _open_duplicate(client, sync_db)
    as_role(client, sync_db, "engineer")
    assert client.post(f"/api/alerts/{alert['_id']}/resolve").status_code == 403


# ---- dashboard -------------------------------------------------------------------------------

def test_summary(client, sync_db):
    seed_report(client, sync_db, dup_switch(), edge_router())
    as_role(client, sync_db, "viewer")
    r = client.get("/api/dashboard/summary")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["devices"] == {"total": 2, "up": 2, "snmp_error": 0, "down": 0}
    assert body["duplicate_ips"] == 1 and body["alerts_open"] == 1
    assert body["alerts_by_severity"] == {"critical": 1}
    assert body["last_agent_check_in"]["name"] == "Seed agent"
    # /32 loopbacks and point-to-point links are left out of "fullest subnets".
    assert [s["network"] for s in body["fullest_subnets"]] == ["10.10.10.0/24",
                                                               "2001:db8:10:10::/64"]
    assert body["fullest_subnets"][1]["usage"]["size"] == "18446744073709551616"


def test_summary_on_empty_database(client, sync_db):
    as_role(client, sync_db, "viewer")
    body = client.get("/api/dashboard/summary").json()
    assert body["devices"]["total"] == 0 and body["last_agent_check_in"] is None


# ---- serving the built frontend --------------------------------------------------------------

@pytest.fixture
def spa_client(tmp_path, sync_db):
    (tmp_path / "assets").mkdir()
    (tmp_path / "index.html").write_text("<!doctype html><div id=root></div>")
    (tmp_path / "assets" / "index-abc123.js").write_text("console.log('app')")
    (tmp_path / "favicon.svg").write_text("<svg/>")
    (tmp_path.parent / "secret.txt").write_text("outside dist")
    with TestClient(create_app(make_settings(frontend_dist=tmp_path)), base_url=BASE_URL) as c:
        yield c


def test_spa_routes(spa_client):
    for path in ("/", "/subnets/abc", "/admin/users"):
        r = spa_client.get(path)
        assert r.status_code == 200 and "id=root" in r.text, path
        assert r.headers["cache-control"] == "no-cache"
        assert "script-src 'self'" in r.headers["content-security-policy"]
        assert r.headers["x-frame-options"] == "DENY"
    asset = spa_client.get("/assets/index-abc123.js")
    assert asset.status_code == 200 and "immutable" in asset.headers["cache-control"]
    assert spa_client.get("/favicon.svg").text == "<svg/>"


def test_spa_never_answers_api_or_escapes_dist(spa_client):
    r = spa_client.get("/api/does-not-exist")
    assert r.status_code == 404 and r.headers["content-type"].startswith("application/json")
    assert spa_client.get("/api/subnets").status_code == 401  # real routes still win
    assert spa_client.get("/health").json()["status"] == "ok"
    for path in ("/../secret.txt", "/%2e%2e/secret.txt", "/assets/../../secret.txt"):
        assert "outside dist" not in spa_client.get(path).text, path


def test_no_build_means_api_only(client):
    assert client.get("/subnets").status_code == 404
