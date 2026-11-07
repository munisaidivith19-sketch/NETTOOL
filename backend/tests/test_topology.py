"""Phase 5: links, the topology graph, endpoint location, interface rates and metrics."""

from datetime import timedelta

import pytest

from app.services.links import short_name
from tests.ipam_helpers import as_role, seed_report, send
from tests.test_ingest import report
from tests.topology_helpers import PC, PC2, access, core, utc_now, with_counters


def graph(client, sync_db):
    as_role(client, sync_db, "viewer")
    r = client.get("/api/topology")
    assert r.status_code == 200, r.text
    return r.json()


# ---- links and the graph ---------------------------------------------------------------------

def test_graph_merges_both_ends_of_a_cable_and_keeps_external_neighbours(client, sync_db):
    seed_report(client, sync_db, core(), access())
    body = graph(client, sync_db)
    nodes = {n["label"]: n for n in body["nodes"]}
    assert set(nodes) == {"CORE-SW-1", "ACCESS-SW-1", "isp-pe-01.example.net"}
    assert nodes["isp-pe-01.example.net"]["external"] is True
    assert nodes["CORE-SW-1"]["status"] == "up"

    edges = body["edges"]
    assert len(edges) == 2  # core<->access reported by both switches, but one cable
    ids = {nodes["CORE-SW-1"]["id"]: "core", nodes["ACCESS-SW-1"]["id"]: "access"}
    cable = next(e for e in edges if {e["source"], e["target"]} == set(ids))
    ports = {ids[cable["source"]]: cable["source_port"], ids[cable["target"]]: cable["target_port"]}
    assert ports == {"core": "Gi1/0/2", "access": "9"}
    assert cable["status"] == "up" and cable["protocols"] == ["lldp"]

    link = sync_db.links.find_one({"remote_name": "ACCESS-SW-1"})
    assert link["remote_device_id"] == sync_db.devices.find_one({"sys_name": "ACCESS-SW-1"})["_id"]
    assert link["remote_if_index"] == 9  # "9" matched against the remote's interface names


@pytest.mark.parametrize("remote", [
    {"remote_name": "core-sw-1.campus.local"},                 # name with a domain, any case
    {"remote_chassis_id": "00:00:0c:c0:00:01"},                # chassis ID = an interface MAC
    {"remote_mgmt_ip": "10.10.10.1"},                          # an interface address, not mgmt
])
def test_remote_matching_fallbacks(client, sync_db, remote):
    link = {"protocol": "cdp", "if_index": 9, "remote_port": "GigabitEthernet1/0/2", **remote}
    seed_report(client, sync_db, core(links=[]), access(links=False) | {"links": [link]})
    stored = sync_db.links.find_one({"protocol": "cdp"})
    assert stored["remote_device_id"] == sync_db.devices.find_one({"sys_name": "CORE-SW-1"})["_id"]
    assert stored["remote_if_index"] == 2  # matched by the remote's ifDescr


def test_unmatched_neighbour_and_self_reference(client, sync_db):
    links = [{"protocol": "lldp", "if_index": 1, "remote_name": "IP-PHONE-7"},
             {"protocol": "lldp", "if_index": 2, "remote_mgmt_ip": "10.10.99.11"}]  # itself
    seed_report(client, sync_db, access(links=False) | {"links": links})
    assert all(link["remote_device_id"] is None for link in sync_db.links.find())


def test_short_name():
    assert short_name("CORE-SW-1.campus.local") == "core-sw-1"
    assert short_name("  ") is None and short_name(None) is None


def test_lost_link_and_uplink_down_alert(client, sync_db):
    agent = seed_report(client, sync_db, core(), access())
    # The cable to the core is pulled: port 9 goes down and LLDP no longer sees the core.
    assert send(client, agent, report(core(), access(port9="down", links=False))).status_code == 200
    assert sync_db.links.find_one({"device_id": sync_db.devices.find_one(
        {"sys_name": "ACCESS-SW-1"})["_id"]})["status"] == "lost"
    cable = next(e for e in graph(client, sync_db)["edges"] if "isp" not in str(e))
    assert cable["status"] == "down"

    alert = sync_db.alerts.find_one({"type": "interface_down"})
    assert alert["status"] == "open" and alert["severity"] == "critical"
    assert "Uplink 9 (to CORE-SW-1) on ACCESS-SW-1 (10.10.99.11) is down" in alert["message"]
    # Access ports going down (a PC switched off) never raise an alert.
    send(client, agent, report(core(), access(port9="down", links=False) | {
        "interfaces": access(port9="down")["interfaces"][:1] + [
            {"if_index": 2, "name": "2", "admin_status": "up", "oper_status": "down"}]}))
    assert sync_db.alerts.count_documents({"type": "interface_down"}) == 1

    send(client, agent, report(core(), access()))
    assert sync_db.alerts.find_one({"_id": alert["_id"]})["status"] == "resolved"
    assert sync_db.links.count_documents({"status": "lost"}) == 0


def test_admin_down_uplink_is_not_an_alert(client, sync_db):
    device = access(port9="down")
    device["interfaces"][2]["admin_status"] = "down"  # shut down on purpose
    seed_report(client, sync_db, core(), device)
    assert sync_db.alerts.count_documents({"type": "interface_down"}) == 0


# ---- locate ----------------------------------------------------------------------------------

def locate(client, q):
    r = client.get("/api/topology/locate", params={"q": q})
    assert r.status_code == 200, r.text
    return r.json()


def test_locate_ignores_the_core_trunk(client, sync_db):
    seed_report(client, sync_db, core(), access())
    as_role(client, sync_db, "viewer")
    for q in (PC, "00-14-22-1A-20-14", "0014.221a.2014", "10.10.10.20"):
        found = locate(client, q)
        assert found["mac"] == PC, q
        assert (found["location"]["device"], found["location"]["port"],
                found["location"]["vlan"]) == ("ACCESS-SW-1", "1", 10), q
    found = locate(client, "10.10.10.20")
    uplink = next(s for s in found["sightings"] if s["device"] == "CORE-SW-1")
    assert uplink["uplink"] and "LLDP" in uplink["uplink_reason"]
    assert found["message"] == f"{PC} is on ACCESS-SW-1 port 1, VLAN 10."

    detail = client.get("/api/ips/10.10.10.20").json()
    assert detail["switch_port"]["device"] == "ACCESS-SW-1" and detail["switch_port"]["port"] == "1"


def test_trunk_detection_without_lldp(client, sync_db):
    device = access(links=False)
    # Port 9: two VLANs = trunk. Port 2: 11 MACs behind one port = aggregation, not a PC.
    device["mac_table"] = [{"mac": PC, "if_index": 9, "vlan": 10},
                           {"mac": "00:00:0c:c0:99:00", "if_index": 9, "vlan": 99},
                           *({"mac": f"00:50:56:00:00:{i:02x}", "if_index": 2, "vlan": 20}
                             for i in range(11))]
    seed_report(client, sync_db, device)
    as_role(client, sync_db, "viewer")
    found = locate(client, PC)
    assert found["location"] is None and "only seen on uplink ports" in found["message"]
    assert "trunk (2 VLANs)" in found["sightings"][0]["uplink_reason"]
    found = locate(client, "00:50:56:00:00:01")
    assert "11 MAC addresses" in found["sightings"][0]["uplink_reason"]


def test_locate_network_device_and_unknowns(client, sync_db):
    seed_report(client, sync_db, core(), access())
    as_role(client, sync_db, "viewer")
    found = locate(client, "access-sw-1")  # host name, any case
    assert found["device"]["name"] == "ACCESS-SW-1"
    assert (found["location"]["device"], found["location"]["port"]) == ("CORE-SW-1", "Gi1/0/2")
    assert "No MAC address is known" in locate(client, "10.10.10.250")["message"]
    assert "not in any switch MAC address table" in locate(client, "aa:bb:cc:dd:ee:ff")["message"]
    assert locate(client, "no-such-host")["location"] is None


def test_locate_reserved_hostname(client, sync_db):
    seed_report(client, sync_db, core(), access())
    eng = as_role(client, sync_db, "engineer")
    sync_db.ip_addresses.update_one({"ip": "10.10.10.20"}, {"$set": {"reservation": {
        "hostname": "staff-pc-1", "mac": None}}})
    found = client.get("/api/topology/locate", params={"q": "staff-pc-1"}, headers=eng).json()
    assert found["ip"] == "10.10.10.20" and found["location"]["port"] == "1"


@pytest.mark.parametrize("q", ['{"$ne":null}', ".*", "a b", "$where", "x" * 101, ""])
def test_locate_rejects_bad_queries(client, sync_db, q):
    as_role(client, sync_db, "viewer")
    assert client.get("/api/topology/locate", params={"q": q}).status_code == 422


def test_topology_needs_login(client):
    assert client.get("/api/topology").status_code == 401
    assert client.get("/api/topology/locate", params={"q": PC2}).status_code == 401


# ---- rates and metrics -----------------------------------------------------------------------

def test_rates_and_metrics_history(client, sync_db):
    t0 = utc_now() - timedelta(seconds=300)
    agent = seed_report(client, sync_db, with_counters(access(), 1_000_000, t0))
    # 37.5 MB more in 300 s = 1 Mbit/s in, 0.5 Mbit/s out.
    send(client, agent, report(with_counters(access(), 38_500_000, t0 + timedelta(seconds=300))))
    device = sync_db.devices.find_one({"sys_name": "ACCESS-SW-1"})
    viewer = as_role(client, sync_db, "viewer")
    detail = client.get(f"/api/devices/{device['_id']}", headers=viewer).json()
    rates = {i["if_index"]: i["rates"] for i in detail["interfaces"]}
    assert rates[1]["in_bps"] == 1_000_000 and rates[1]["out_bps"] == 500_000
    assert [link["remote_name"] for link in detail["links"]] == ["CORE-SW-1"]

    # History only for the uplink (9) and the IP interface (99), not access port 1.
    assert sorted(m["if_index"] for m in sync_db.metrics.find()) == [9, 99]
    points = client.get(f"/api/devices/{device['_id']}/metrics",
                        params={"if_index": 9, "hours": 2}).json()
    assert len(points) == 1 and points[0]["in_bps"] == 1_000_000
    assert client.get(f"/api/devices/{device['_id']}/metrics",
                      params={"if_index": 1}).json() == []
    for params in ({"if_index": 0}, {"if_index": 9, "hours": 500}, {}):
        assert client.get(f"/api/devices/{device['_id']}/metrics",
                          params=params).status_code == 422
    assert client.get("/api/devices/" + "0" * 24 + "/metrics",
                      params={"if_index": 1}).status_code == 404


def test_counter_reset_gives_no_rate(client, sync_db):
    t0 = utc_now() - timedelta(seconds=300)
    agent = seed_report(client, sync_db, with_counters(access(), 5_000_000, t0))
    send(client, agent, report(with_counters(access(), 1_000, t0 + timedelta(seconds=300))))
    iface = sync_db.interfaces.find_one({"if_index": 1})
    assert iface["rates"] is None and iface["counter_sample"]["in_octets"] == 1_000
    assert sync_db.metrics.count_documents({}) == 0


def test_far_off_agent_clock_falls_back_to_server_time(client, sync_db):
    seed_report(client, sync_db, with_counters(access(), 1, utc_now() - timedelta(days=3)))
    sample = sync_db.interfaces.find_one({"if_index": 1})["counter_sample"]
    assert abs(sample["at"] - utc_now()) < timedelta(minutes=1)


@pytest.mark.parametrize("bad", [
    {"counters": [{"if_index": 1, "in_octets": 2**64, "bits": 64}]},
    {"counters": [{"if_index": 1, "in_octets": 2**32, "bits": 32}]},
    {"counters": [{"if_index": 1, "in_octets": -1}]},
    {"mac_table": [{"mac": "00:14:22:1A:20:14", "if_index": 1}]},  # upper case: not normalised
    {"mac_table": [{"mac": PC, "if_index": 1, "vlan": {"$gt": 0}}]},
    {"links": [{"protocol": "ospf", "if_index": 1}]},
    {"links": [{"protocol": "lldp", "$where": "1"}]},
    {"links": [{"protocol": "lldp", "remote_mgmt_ip": "not-an-ip"}]},
])
def test_bad_phase5_report_fields_rejected(client, sync_db, bad):
    agent = seed_report(client, sync_db)
    assert send(client, agent, report(access() | bad)).status_code == 422


def test_device_text_in_links_is_cleaned(client, sync_db):
    link = {"protocol": "lldp", "if_index": 1, "remote_name": "evil\x1b[31m\x00name"}
    seed_report(client, sync_db, access(links=False) | {"links": [link]})
    assert sync_db.links.find_one()["remote_name"] == "evil [31m name"
