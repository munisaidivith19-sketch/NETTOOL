from datetime import timedelta

from app.security.sessions import utcnow
from app.services.ipaddr import ip_key
from tests.ipam_helpers import as_role, core_switch, seed_report, send
from tests.test_ingest import report

DUP_KEY = "duplicate_ip:" + ip_key("10.10.10.20")


def with_second_mac() -> dict:
    device = core_switch()
    device["neighbors"].append(
        {"ip": "10.10.10.20", "mac": "00:50:56:00:00:99", "if_index": 10, "kind": "dynamic"})
    return device


def test_duplicate_ip_alert_lifecycle(client, sync_db):
    agent = seed_report(client, sync_db, with_second_mac())
    alerts = list(sync_db.alerts.find({"type": "duplicate_ip"}))
    assert len(alerts) == 1
    alert = alerts[0]
    assert (alert["key"], alert["status"], alert["severity"]) == (DUP_KEY, "open", "critical")
    assert alert["details"]["macs"] == ["00:14:22:1a:20:14", "00:50:56:00:00:99"]
    assert alert["details"]["seen_by"] == ["CORE-SW-1"]

    # The same report again: still one alert, not a second one.
    assert send(client, agent, report(with_second_mac())).status_code == 200
    assert sync_db.alerts.count_documents({"type": "duplicate_ip"}) == 1

    # The second MAC ages out of the window -> resolved.
    sync_db.arp_entries.update_one({"mac": "00:50:56:00:00:99"},
                                   {"$set": {"last_seen": utcnow() - timedelta(hours=3)}})
    assert send(client, agent, report()).status_code == 200
    alert = sync_db.alerts.find_one({"key": DUP_KEY})
    assert alert["status"] == "resolved" and alert["resolved_at"] is not None

    # It comes back -> the same alert reopens.
    assert send(client, agent, report(with_second_mac())).status_code == 200
    alert = sync_db.alerts.find_one({"key": DUP_KEY})
    assert alert["status"] == "open" and alert["occurrences"] == 2
    assert sync_db.alerts.count_documents({"type": "duplicate_ip"}) == 1


def test_same_mac_from_two_devices_is_not_duplicate(client, sync_db):
    edge = {**core_switch(), "mgmt_ip": "10.10.99.254", "sys_name": "EDGE",
            "interfaces": [], "addresses": [],
            "neighbors": [{"ip": "10.10.10.20", "mac": "00:14:22:1a:20:14", "if_index": 1,
                           "kind": "dynamic"}]}
    seed_report(client, sync_db, core_switch(), edge)
    assert sync_db.alerts.count_documents({"type": "duplicate_ip"}) == 0


def test_alerts_api_and_detail(client, sync_db):
    seed_report(client, sync_db, with_second_mac())
    as_role(client, sync_db, "viewer")
    alerts = client.get("/api/alerts").json()
    assert [a["type"] for a in alerts] == ["duplicate_ip"]
    assert "10.10.10.20" in alerts[0]["message"]
    detail = client.get("/api/ips/10.10.10.20").json()
    assert detail["duplicate_alert"] is not None
    assert detail["macs_recent"] == ["00:14:22:1a:20:14", "00:50:56:00:00:99"]
    assert client.get("/api/alerts", params={"status": "resolved"}).json() == []
    assert client.get("/api/alerts", params={"type": "$ne"}).status_code == 422


def _fill(sync_db, network_prefix: str, count: int):
    now = utcnow()
    for i in range(1, count + 1):
        ip = f"{network_prefix}.{i}"
        sync_db.ip_addresses.update_one(
            {"ip_key": ip_key(ip)},
            {"$set": {"ip": ip, "version": 4, "last_seen": now, "sources": ["ping"]}},
            upsert=True)


def test_subnet_usage_alert_with_hysteresis(client, sync_db):
    eng = as_role(client, sync_db, "engineer")
    subnet = client.post("/api/subnets", headers=eng,
                         json={"network": "10.77.0.0/27", "name": "Lab"}).json()  # 30 usable
    key = "subnet_usage:10.77.0.0/27"

    def recheck():  # any IPAM change runs the checks; a no-op edit is enough
        assert client.patch(f"/api/subnets/{subnet['id']}", headers=eng,
                            json={"description": "x"}).status_code == 200
        return sync_db.alerts.find_one({"key": key})

    _fill(sync_db, "10.77.0", 25)            # 83 %
    alert = recheck()
    assert alert["status"] == "open" and alert["severity"] == "warning"
    assert "Lab" in alert["message"] and alert["details"]["percent"] == 83.33

    sync_db.ip_addresses.delete_many({"ip": {"$in": ["10.77.0.25", "10.77.0.24"]}})  # 76.7 %
    assert recheck()["status"] == "open"     # still within the 5-point hysteresis band

    sync_db.ip_addresses.delete_many({"ip": {"$in": ["10.77.0.23", "10.77.0.22"]}})  # 70 %
    assert recheck()["status"] == "resolved"


def test_point_to_point_links_never_alert(client, sync_db):
    seed_report(client, sync_db)  # includes no /30 here, so add one that is "full"
    _fill(sync_db, "10.88.0", 2)
    sync_db.subnets.insert_one({"network": "10.88.0.0/30", "version": 4, "prefixlen": 30,
                                "start_key": ip_key("10.88.0.0"),
                                "end_key": ip_key("10.88.0.3"), "source": "discovered"})
    eng = as_role(client, sync_db, "engineer")
    client.post("/api/subnets", headers=eng, json={"network": "10.89.0.0/24"})
    assert sync_db.alerts.count_documents({"type": "subnet_usage"}) == 0
