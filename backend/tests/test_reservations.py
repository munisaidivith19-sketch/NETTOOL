import threading
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from pymongo import MongoClient

from app.main import create_app
from app.security.sessions import utcnow
from app.services.ipaddr import ip_key
from tests.conftest import BASE_URL, TEST_DB, TEST_URI, csrf, login, make_settings
from tests.ipam_helpers import as_role, seed_report

RESERVE = "/api/ips/reservations"


@pytest.fixture
def eng(client, sync_db):
    seed_report(client, sync_db)
    return as_role(client, sync_db, "engineer")


def reserve(client, headers, ip, **extra):
    return client.post(RESERVE, headers=headers, json={"ip": ip, **extra})


def test_reserve_free_ip(client, sync_db, eng):
    r = reserve(client, eng, "10.10.10.50", hostname="printer-2", description="Floor 2",
                mac="00-11-22-33-44-55")
    assert r.status_code == 201, r.text
    doc = sync_db.ip_addresses.find_one({"ip_key": ip_key("10.10.10.50")})
    assert doc["reservation"]["hostname"] == "printer-2"
    assert doc["reservation"]["mac"] == "00:11:22:33:44:55"
    assert doc["reservation"]["reserved_by"] == "engineer1"
    detail = client.get("/api/ips/10.10.10.50").json()
    assert detail["status"] == "reserved" and detail["subnet"]["network"] == "10.10.10.0/24"
    assert sync_db.audit_log.find_one({"action": "ip.reserve", "result": "success"})


def test_ipv6_reservation(client, sync_db, eng):
    assert reserve(client, eng, "2001:db8:10:10::100").status_code == 201
    assert reserve(client, eng, "2001:db8:10:10::").status_code == 422  # subnet-router anycast


@pytest.mark.parametrize(
    ("ip", "code", "reason"),
    [
        ("10.10.10.20", 409, "in_use"),         # seen in ARP and ping just now
        ("10.10.10.1", 409, "in_use"),          # the switch's own interface
        ("10.10.10.0", 422, "not_assignable"),  # network address
        ("10.10.10.255", 422, "not_assignable"),
        ("172.16.0.5", 422, "no_subnet"),
    ],
)
def test_reservation_conflicts(client, sync_db, eng, ip, code, reason):
    r = reserve(client, eng, ip)
    assert r.status_code == code, r.text
    entry = sync_db.audit_log.find_one({"action": "ip.reserve", "result": "failure"})
    assert entry["details"]["reason"] == reason


def test_no_double_reservation(client, sync_db, eng):
    assert reserve(client, eng, "10.10.10.60").status_code == 201
    r = reserve(client, eng, "10.10.10.60")
    assert r.status_code == 409 and "already reserved" in r.json()["detail"]


def test_gateway_cannot_be_reserved(client, sync_db, eng):
    subnet = next(s for s in client.get("/api/subnets").json()
                  if s["network"] == "10.10.10.0/24")
    # .254 is not seen on the network, so only the gateway rule can refuse it.
    r = client.patch(f"/api/subnets/{subnet['id']}", headers=eng, json={"gateway": "10.10.10.254"})
    assert r.status_code == 200
    r = reserve(client, eng, "10.10.10.254")
    assert r.status_code == 409 and "gateway" in r.json()["detail"]


def test_stale_ip_can_be_reserved(client, sync_db, eng):
    old = utcnow() - timedelta(days=60)
    sync_db.ip_addresses.update_one({"ip_key": ip_key("10.10.10.20")},
                                    {"$set": {"last_seen": old}})
    assert client.get("/api/ips/10.10.10.20").json()["status"] == "stale"
    assert reserve(client, eng, "10.10.10.20", hostname="reused").status_code == 201
    doc = sync_db.ip_addresses.find_one({"ip_key": ip_key("10.10.10.20")})
    assert "arp" in doc["sources"] and "reservation" in doc["sources"]  # history kept


def test_next_free_skips_reservations(client, sync_db, eng):
    staff = next(s for s in client.get("/api/subnets").json() if s["network"] == "10.10.10.0/24")
    assert reserve(client, eng, "10.10.10.2").status_code == 201
    assert client.get(f"/api/subnets/{staff['id']}/next-free").json()["ip"] == "10.10.10.3"
    assert next(s for s in client.get("/api/subnets").json()
                if s["network"] == "10.10.10.0/24")["usage"]["used"] == "3"


def test_release(client, sync_db, eng):
    assert reserve(client, eng, "10.10.10.70").status_code == 201
    assert client.delete(f"{RESERVE}/10.10.10.70", headers=eng).status_code == 204
    assert sync_db.ip_addresses.find_one({"ip_key": ip_key("10.10.10.70")}) is None
    assert client.delete(f"{RESERVE}/10.10.10.70", headers=eng).status_code == 404
    assert sync_db.audit_log.find_one({"action": "ip.release"}) is not None


def test_release_keeps_discovery_history(client, sync_db, eng):
    old = utcnow() - timedelta(days=60)
    sync_db.ip_addresses.update_one({"ip_key": ip_key("10.10.10.20")},
                                    {"$set": {"last_seen": old}})
    assert reserve(client, eng, "10.10.10.20").status_code == 201
    assert client.delete(f"{RESERVE}/10.10.10.20", headers=eng).status_code == 204
    doc = sync_db.ip_addresses.find_one({"ip_key": ip_key("10.10.10.20")})
    assert doc is not None and "reservation" not in doc and "reservation" not in doc["sources"]


def test_racing_reservations_only_one_wins(client, sync_db, eng):
    """Two app instances reserve the same IP at the same moment: the unique ip_key index lets
    exactly one insert succeed."""
    results = []
    barrier = threading.Barrier(2)

    def worker():
        with TestClient(create_app(make_settings()), base_url=BASE_URL) as c:
            token = login(c, "engineer1")
            barrier.wait()
            results.append(c.post(RESERVE, headers=csrf(token),
                                  json={"ip": "10.10.10.80"}).status_code)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert sorted(results) == [201, 409]
    check = MongoClient(TEST_URI)[TEST_DB]
    assert check.ip_addresses.count_documents({"ip_key": ip_key("10.10.10.80")}) == 1


def test_viewer_cannot_reserve(client, sync_db, eng):
    viewer = as_role(client, sync_db, "viewer")
    assert reserve(client, viewer, "10.10.10.90").status_code == 403
    assert client.delete(f"{RESERVE}/10.10.10.20", headers=viewer).status_code == 403


@pytest.mark.parametrize(
    "body",
    [{"ip": "10.10.10.91", "$where": "1"}, {"ip": {"$ne": None}}, {"ip": "10.10.10.92",
     "hostname": "bad host"}, {"ip": "10.10.10.93", "mac": "zz:zz"},
     {"ip": "10.10.10.94", "hostname": "-leadingdash"}],
)
def test_bad_reservation_bodies(client, sync_db, eng, body):
    r = client.post(RESERVE, headers=eng, json=body)
    assert r.status_code == 422
    assert sync_db.ip_addresses.count_documents({"reservation": {"$exists": True}}) == 0


@pytest.mark.parametrize("q", ['{"$ne":null}', ".*", "^", "$where", "a" * 101, "10.0.0.1'--",
                               "(a+)+", "*"])
def test_search_rejects_operator_text(client, sync_db, eng, q):
    assert client.get("/api/ips/search", params={"q": q}).status_code == 422


def test_search_bracket_param_is_just_unknown(client, sync_db, eng):
    r = client.get("/api/ips/search?q[$ne]=1")
    assert r.status_code == 422  # q is missing; q[$ne] is not a parameter


def test_search_modes(client, sync_db, eng):
    def search(q):
        r = client.get("/api/ips/search", params={"q": q})
        assert r.status_code == 200, r.text
        return r.json()

    assert [i["ip"] for i in search("10.10.10.20")["items"]] == ["10.10.10.20"]
    assert search("10.10.10.0/24")["query_type"] == "network"
    assert len(search("10.10.10.0/24")["items"]) == 2
    by_mac = search("0014.221a.2014")
    assert by_mac["query_type"] == "mac"
    assert {i["ip"] for i in by_mac["items"]} == {"10.10.10.20", "2001:db8:10:10::20"}
    by_host = search("core-sw")
    assert by_host["devices"][0]["name"] == "CORE-SW-1"
    assert {i["ip"] for i in by_host["items"]} >= {"10.10.10.1", "2001:db8:10:10::1"}
    assert search("nothing-like-this")["items"] == []
    # "." is matched literally, not as "any character".
    assert search("core.sw")["devices"] == []


def test_ip_detail_chain(client, sync_db, eng):
    detail = client.get("/api/ips/10.10.10.20").json()
    assert detail["mac"] == "00:14:22:1a:20:14"
    hop = detail["seen_by"][0]
    assert (hop["device"], hop["interface"]) == ("CORE-SW-1", "Vl10")
    assert detail["switch_port"] is None  # needs MAC tables (Phase 5)
    owner = client.get("/api/ips/10.10.10.1").json()["owner"]
    assert (owner["device"], owner["interface"]) == ("CORE-SW-1", "Vl10")
    assert client.get("/api/ips/10.10.10.99").json()["status"] == "free"
    assert client.get("/api/ips/not-an-ip").status_code == 422
    assert client.get("/api/ips/1.2.3.999").status_code == 422
