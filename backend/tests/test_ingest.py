import copy
import ipaddress
import json

import pytest

from app.models.report import MAX_DEVICES, MAX_PING
from app.services.ipaddr import ip_key, network_key_range
from tests.conftest import csrf, signed_headers

REPORT = "/api/agent/report"
KNOWN = "/api/agent/known-devices"


@pytest.fixture
def agent(client, admin):
    return _new_agent(client, admin)


def _new_agent(client, admin, name="Lab agent"):
    response = client.post("/api/agents", headers=csrf(admin), json={"name": name})
    assert response.status_code == 201
    return response.json()


def send(client, agent, body, path=REPORT):
    payload = json.dumps(body).encode()
    client.cookies.clear()  # agent requests carry no user session
    headers = signed_headers(agent["id"], agent["key"], "POST", path, payload)
    return client.post(path, content=payload, headers=headers)


def get_known(client, agent):
    client.cookies.clear()
    return client.get(KNOWN, headers=signed_headers(agent["id"], agent["key"], "GET", KNOWN))


def core_switch() -> dict:
    return {
        "mgmt_ip": "10.10.99.1", "snmp_port": 161, "snmp_version": "v3", "reachable": True,
        "error": None, "sys_name": "CORE-SW-1", "sys_descr": "Cisco IOS XE (simulated)",
        "sys_location": "Server room", "sys_object_id": "1.3.6.1.4.1.9.1.2494",
        "vendor": "Cisco", "uptime_seconds": 3600,
        "interfaces": [
            {"if_index": 1, "name": "Gi1/0/1", "descr": "GigabitEthernet1/0/1", "alias": "uplink",
             "if_type": 6, "mtu": 1500, "speed_mbps": 1000, "mac": "00:00:0c:c0:00:01",
             "admin_status": "up", "oper_status": "up"},
            {"if_index": 10, "name": "Vl10", "mac": "00:00:0c:c0:10:00", "oper_status": "up"},
        ],
        "addresses": [
            {"ip": "10.10.10.1", "if_index": 10, "prefixlen": 24},
            {"ip": "2001:db8:10:10::1", "if_index": 10, "prefixlen": 64},
            {"ip": "10.10.255.2", "if_index": 1, "prefixlen": 32},
        ],
        "neighbors": [
            {"ip": "10.10.10.20", "mac": "00:14:22:1a:20:14", "if_index": 10, "kind": "dynamic"},
            {"ip": "2001:db8:10:10::20", "mac": "00:14:22:1a:20:14", "if_index": 10,
             "kind": "dynamic"},
        ],
    }


def report(*devices, ping=None) -> dict:
    return {
        "agent_version": "0.1.0",
        "collected_at": "2026-11-07T10:00:00+00:00",
        "ping": ping if ping is not None else [{"ip": "10.10.10.20", "up": True},
                                               {"ip": "10.10.10.99", "up": False}],
        "devices": list(devices) or [core_switch()],
    }


def test_ip_key_rule():
    assert ip_key("10.0.0.1") == "4:" + "0" * 24 + "0a000001"
    assert ip_key("2001:db8::1") == "6:20010db8000000000000000000000001"
    keys = [ip_key(a) for a in ("9.255.255.255", "10.0.0.1", "10.0.0.10", "::1", "2001:db8::1")]
    assert keys == sorted(keys)  # string order == numeric order, IPv4 before IPv6
    assert network_key_range("10.10.10.0/24") == (ip_key("10.10.10.0"), ip_key("10.10.10.255"))


def test_report_fills_every_collection(client, agent, sync_db):
    response = send(client, agent, report())
    assert response.status_code == 200, response.text
    summary = response.json()["summary"]
    assert summary["devices_up"] == 1 and summary["interfaces"] == 2

    device = sync_db.devices.find_one({"mgmt_ip": "10.10.99.1"})
    assert device["status"] == "up" and device["vendor"] == "Cisco"
    assert device["agent_id"] == agent["id"] and device["snmp_v2c"] is False
    assert device["mgmt_ip_key"] == ip_key("10.10.99.1")
    assert device["status_changed_at"] is not None

    vlan = sync_db.interfaces.find_one({"device_id": device["_id"], "if_index": 10})
    assert vlan["name"] == "Vl10"

    subnets = {s["network"]: s for s in sync_db.subnets.find()}
    assert set(subnets) == {"10.10.10.0/24", "2001:db8:10:10::/64"}  # the /32 is skipped
    v6 = subnets["2001:db8:10:10::/64"]
    assert (v6["version"], v6["prefixlen"], v6["source"]) == (6, 64, "discovered")
    assert (v6["start_key"], v6["end_key"]) == network_key_range("2001:db8:10:10::/64")

    gateway = sync_db.ip_addresses.find_one({"ip": "10.10.10.1"})
    assert gateway["mac"] == "00:00:0c:c0:10:00" and gateway["sources"] == ["interface"]
    host = sync_db.ip_addresses.find_one({"ip_key": ip_key("10.10.10.20")})
    assert host["mac"] == "00:14:22:1a:20:14" and sorted(host["sources"]) == ["arp", "ping"]
    assert host["ping_up"] is True
    assert sync_db.ip_addresses.find_one({"ip": "10.10.10.99"}) is None  # silent: not created
    assert sync_db.ip_addresses.find_one({"ip": "2001:db8:10:10::20"})["version"] == 6

    assert sync_db.arp_entries.count_documents({"device_id": device["_id"]}) == 2
    entry = sync_db.audit_log.find_one({"action": "agent.report"})
    assert entry["actor"]["id"] == agent["id"] and entry["details"]["interfaces"] == 2
    assert "CORE-SW-1" not in str(entry)  # counts only, no network contents


def test_resending_is_idempotent(client, agent, sync_db):
    assert send(client, agent, report()).status_code == 200
    first_seen = sync_db.ip_addresses.find_one({"ip": "10.10.10.20"})["first_seen"]
    assert send(client, agent, report()).status_code == 200
    counts = {name: sync_db[name].count_documents({}) for name in
              ("devices", "interfaces", "subnets", "ip_addresses", "arp_entries")}
    assert counts == {"devices": 1, "interfaces": 2, "subnets": 2, "ip_addresses": 5,
                      "arp_entries": 2}
    assert sync_db.ip_addresses.find_one({"ip": "10.10.10.20"})["first_seen"] == first_seen


def test_manual_subnet_never_overwritten(client, agent, sync_db):
    sync_db.subnets.insert_one({"network": "10.10.10.0/24", "source": "manual",
                                "name": "Staff VLAN", "vlan": 10})
    assert send(client, agent, report()).status_code == 200
    subnet = sync_db.subnets.find_one({"network": "10.10.10.0/24"})
    assert (subnet["source"], subnet["name"], subnet["vlan"]) == ("manual", "Staff VLAN", 10)


def test_two_macs_for_one_ip_are_both_kept(client, agent, sync_db):
    device = core_switch()
    device["neighbors"].append(
        {"ip": "10.10.10.20", "mac": "00:50:56:00:00:99", "if_index": 10, "kind": "dynamic"})
    assert send(client, agent, report(device)).status_code == 200
    macs = {e["mac"] for e in sync_db.arp_entries.find({"ip_key": ip_key("10.10.10.20")})}
    assert macs == {"00:14:22:1a:20:14", "00:50:56:00:00:99"}


def test_device_goes_down_then_snmp_error(client, agent, sync_db):
    assert send(client, agent, report()).status_code == 200
    silent = {"mgmt_ip": "10.10.99.1", "snmp_port": 161, "snmp_version": "v3",
              "reachable": False, "error": "No SNMP response received before timeout"}

    assert send(client, agent, report(silent, ping=[])).status_code == 200
    device = sync_db.devices.find_one({"mgmt_ip": "10.10.99.1"})
    assert device["status"] == "down" and device["sys_name"] == "CORE-SW-1"  # history kept
    assert device["last_error"].startswith("No SNMP response")
    down_since = device["status_changed_at"]

    ping = [{"ip": "10.10.99.1", "up": True}]
    assert send(client, agent, report(silent, ping=ping)).status_code == 200
    device = sync_db.devices.find_one({"mgmt_ip": "10.10.99.1"})
    assert device["status"] == "snmp_error" and device["status_changed_at"] >= down_since

    assert send(client, agent, report()).status_code == 200
    device = sync_db.devices.find_one({"mgmt_ip": "10.10.99.1"})
    assert device["status"] == "up" and device["last_error"] is None


def test_unreachable_unknown_device_is_not_created(client, agent, sync_db):
    silent = {"mgmt_ip": "10.10.99.50", "snmp_version": "v3", "reachable": False}
    assert send(client, agent, report(silent)).status_code == 200
    assert sync_db.devices.count_documents({}) == 0


def test_v2c_device_is_flagged(client, agent, sync_db):
    device = core_switch() | {"snmp_version": "v2c"}
    assert send(client, agent, report(device)).status_code == 200
    assert sync_db.devices.find_one({})["snmp_v2c"] is True


def test_vanished_interfaces_are_removed(client, agent, sync_db):
    assert send(client, agent, report()).status_code == 200
    device = core_switch()
    device["interfaces"] = device["interfaces"][:1]
    assert send(client, agent, report(device)).status_code == 200
    assert sync_db.interfaces.count_documents({}) == 1


def test_device_strings_are_cleaned(client, agent, sync_db):
    device = core_switch() | {"sys_descr": "IOS\x1b[31m\x00 evil\r\nline",
                              "sys_name": "<img src=x onerror=alert(1)>"}
    assert send(client, agent, report(device)).status_code == 200
    stored = sync_db.devices.find_one({})
    assert "\x1b" not in stored["sys_descr"] and "\x00" not in stored["sys_descr"]
    # HTML is stored as inert text; React escapes it on display (no dangerouslySetInnerHTML).
    assert stored["sys_name"] == "<img src=x onerror=alert(1)>"


def _mutations():
    def edit(fn):
        body = report()
        fn(body)
        return body

    yield "extra top-level key", edit(lambda b: b.update(extra=1))
    yield "mongo operator key", edit(lambda b: b["devices"][0].update({"$where": "1"}))
    yield "dotted key", edit(lambda b: b["devices"][0]["interfaces"][0].update({"a.b": 1}))
    yield "operator as value", edit(lambda b: b["devices"][0].update(mgmt_ip={"$ne": None}))
    yield "bad ip", edit(lambda b: b["devices"][0].update(mgmt_ip="10.10.99.300"))
    yield "hostname not ip", edit(lambda b: b["ping"].append({"ip": "evil.com", "up": True}))
    yield "bad mac", edit(lambda b: b["devices"][0]["neighbors"][0].update(mac="00:14:22"))
    yield "uppercase mac", edit(
        lambda b: b["devices"][0]["neighbors"][0].update(mac="00:14:22:1A:20:14"))
    yield "bad oid", edit(lambda b: b["devices"][0].update(sys_object_id="1.3.6;drop"))
    yield "v4 prefix > 32", edit(lambda b: b["devices"][0]["addresses"][0].update(prefixlen=33))
    yield "if_index 0", edit(lambda b: b["devices"][0]["interfaces"][0].update(if_index=0))
    yield "bad status", edit(lambda b: b["devices"][0]["interfaces"][0].update(oper_status="x"))
    yield "huge text", edit(lambda b: b["devices"][0].update(sys_descr="x" * 1025))
    yield "too many devices", edit(lambda b: b.update(devices=[core_switch()] * (MAX_DEVICES + 1)))
    yield "too many ping", edit(lambda b: b.update(
        ping=[{"ip": str(ipaddress.ip_address("10.0.0.0") + i), "up": False}
              for i in range(MAX_PING + 1)]))
    yield "bad version", edit(lambda b: b["devices"][0].update(snmp_version="v1"))
    yield "missing field", edit(lambda b: b.pop("collected_at"))


@pytest.mark.parametrize(("case", "body"), list(_mutations()))
def test_bad_reports_rejected(client, agent, sync_db, case, body):
    response = send(client, agent, copy.deepcopy(body))
    assert response.status_code == 422, case
    assert sync_db.devices.count_documents({}) == 0
    # Validation errors name the field but never echo the submitted data back.
    assert all("input" not in error for error in response.json()["detail"])
    assert "CORE-SW-1" not in response.text


def test_known_devices_are_per_agent(client, admin, sync_db):
    first = _new_agent(client, admin, "Agent A")
    second = _new_agent(client, admin, "Agent B")
    assert send(client, first, report()).status_code == 200
    response = get_known(client, first)
    assert response.status_code == 200
    assert response.json() == {"devices": [{"mgmt_ip": "10.10.99.1", "snmp_port": 161,
                                            "status": "up"}]}
    assert get_known(client, second).json() == {"devices": []}


def test_routes_reject_unsigned_and_user_sessions(client, admin):
    body = report()
    # Logged-in admin with a valid CSRF token, but no agent signature.
    assert client.post(REPORT, headers=csrf(admin), json=body).status_code == 401
    assert client.get(KNOWN).status_code == 401
    client.cookies.clear()
    assert client.post(REPORT, json=body).status_code == 401
