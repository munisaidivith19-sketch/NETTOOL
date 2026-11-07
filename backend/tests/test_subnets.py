import pytest

from tests.ipam_helpers import as_role, core_switch, seed_report, send

SUBNETS = "/api/subnets"


def create(client, headers, **body):
    return client.post(SUBNETS, headers=headers, json=body)


def by_network(client, network):
    return next(s for s in client.get(SUBNETS).json() if s["network"] == network)


def test_create_ipv4_and_ipv6(client, sync_db):
    eng = as_role(client, sync_db, "engineer")
    r = create(client, eng, network="192.168.50.0/24", name="Guest WiFi", vlan=50,
               gateway="192.168.50.1",
               reserved_ranges=[{"start": "192.168.50.100", "end": "192.168.50.199",
                                 "note": "DHCP pool"}])
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["source"] == "manual" and body["usage"]["usable"] == "254"
    r = create(client, eng, network="2001:db8:50::/64", name="Guest v6")
    assert r.status_code == 201
    assert r.json()["usage"]["size"] == "18446744073709551616"
    stored = sync_db.subnets.find_one({"network": "192.168.50.0/24"})
    assert stored["created_by"] == "engineer1" and stored["start_key"].startswith("4:")
    entry = sync_db.audit_log.find_one({"action": "subnet.create", "result": "success",
                                        "target.network": "192.168.50.0/24"})
    assert entry["actor"]["username"] == "engineer1"


@pytest.mark.parametrize(
    "candidate",
    ["10.20.0.0/24",        # exact
     "10.20.0.128/25",      # inside
     "10.20.0.0/16",        # contains
     "10.20.0.77/32"],      # one host inside
)
# Two CIDR blocks can't partly overlap: one always contains the other, or they are disjoint.
def test_overlap_rejected(client, sync_db, candidate):
    eng = as_role(client, sync_db, "engineer")
    assert create(client, eng, network="10.20.0.0/24").status_code == 201
    r = create(client, eng, network=candidate)
    assert r.status_code == 409 and "10.20.0.0/24" in r.json()["detail"]
    failure = sync_db.audit_log.find_one({"action": "subnet.create", "result": "failure"})
    assert failure["details"]["reason"] == "overlap"


def test_adjacent_and_other_family_do_not_overlap(client, sync_db):
    eng = as_role(client, sync_db, "engineer")
    assert create(client, eng, network="10.20.0.0/24").status_code == 201
    assert create(client, eng, network="10.20.1.0/24").status_code == 201
    assert create(client, eng, network="::ffff:0:0/96").status_code == 201  # mapped v4 range


def test_overlap_with_discovered_subnet(client, sync_db):
    seed_report(client, sync_db)
    eng = as_role(client, sync_db, "engineer")
    r = create(client, eng, network="10.10.10.0/25")
    assert r.status_code == 409 and "10.10.10.0/24" in r.json()["detail"]


@pytest.mark.parametrize(
    ("body", "fragment"),
    [
        ({"network": "10.0.0.5/24"}, "did you mean 10.0.0.0/24"),
        ({"network": "10.0.0.0/33"}, "CIDR"),
        ({"network": "10.0.0.0/24", "gateway": "10.0.1.1"}, "not inside"),
        ({"network": "10.0.0.0/24", "gateway": "10.0.0.255"}, "broadcast"),
        ({"network": "10.0.0.0/24",
          "reserved_ranges": [{"start": "10.0.0.50", "end": "10.0.0.10"}]}, "lower"),
        ({"network": "10.0.0.0/24",
          "reserved_ranges": [{"start": "10.0.0.250", "end": "10.0.1.10"}]}, "not inside"),
        ({"network": "10.0.0.0/24", "vlan": 4095}, "4094"),
        ({"network": "10.0.0.0/24", "name": "<script>"}, "pattern"),
        ({"network": "10.0.0.0/24", "description": "bad\x00null"}, "pattern"),
    ],
)
def test_invalid_subnets(client, sync_db, body, fragment):
    eng = as_role(client, sync_db, "engineer")
    r = create(client, eng, **body)
    assert r.status_code == 422, r.text
    assert fragment.lower() in r.text.lower()


def test_usage_after_report_and_edits_survive_reingest(client, sync_db):
    agent = seed_report(client, sync_db)
    eng = as_role(client, sync_db, "engineer")
    staff = by_network(client, "10.10.10.0/24")
    # 10.10.10.1 (switch interface) + 10.10.10.20 (ARP + ping)
    assert staff["usage"]["used"] == "2" and staff["source"] == "discovered"
    r = client.patch(f"{SUBNETS}/{staff['id']}", headers=eng,
                     json={"name": "Staff", "vlan": 10, "gateway": "10.10.10.1"})
    assert r.status_code == 200 and r.json()["vlan"] == 10

    assert send(client, agent, _report_again()).status_code == 200  # the agent reports again
    as_role(client, sync_db, "viewer")
    staff = by_network(client, "10.10.10.0/24")
    assert (staff["name"], staff["vlan"], staff["gateway"]) == ("Staff", 10, "10.10.10.1")


def _report_again():
    from tests.test_ingest import report
    return report(core_switch())


def test_patch_can_clear_fields(client, sync_db):
    eng = as_role(client, sync_db, "engineer")
    subnet = create(client, eng, network="10.30.0.0/24", name="Old", vlan=30).json()
    r = client.patch(f"{SUBNETS}/{subnet['id']}", headers=eng, json={"name": None})
    assert r.status_code == 200 and r.json()["name"] is None and r.json()["vlan"] == 30
    r = client.patch(f"{SUBNETS}/{subnet['id']}", headers=eng, json={"network": "10.31.0.0/24"})
    assert r.status_code == 422  # the network itself can't be changed


def test_ip_table_paging_and_next_free(client, sync_db):
    seed_report(client, sync_db)
    as_role(client, sync_db, "viewer")
    staff = by_network(client, "10.10.10.0/24")
    first = client.get(f"{SUBNETS}/{staff['id']}/ips", params={"limit": 1}).json()
    assert [row["ip"] for row in first["items"]] == ["10.10.10.1"]
    assert first["items"][0]["device"]["name"] == "CORE-SW-1"
    second = client.get(f"{SUBNETS}/{staff['id']}/ips",
                        params={"limit": 1, "after": first["next_after"]}).json()
    assert second["items"][0]["ip"] == "10.10.10.20"
    assert second["items"][0]["mac"] == "00:14:22:1a:20:14"
    nxt = client.get(f"{SUBNETS}/{staff['id']}/next-free").json()
    assert nxt == {"subnet": "10.10.10.0/24", "ip": "10.10.10.2"}
    v6 = by_network(client, "2001:db8:10:10::/64")
    assert client.get(f"{SUBNETS}/{v6['id']}/next-free").json()["ip"] == "2001:db8:10:10::2"


def test_next_free_respects_gateway_and_reserved_ranges(client, sync_db):
    eng = as_role(client, sync_db, "engineer")
    subnet = create(client, eng, network="10.40.0.0/28", gateway="10.40.0.1",
                    reserved_ranges=[{"start": "10.40.0.2", "end": "10.40.0.9"}]).json()
    assert client.get(f"{SUBNETS}/{subnet['id']}/next-free").json()["ip"] == "10.40.0.10"


def test_delete_subnet(client, sync_db):
    eng = as_role(client, sync_db, "engineer")
    subnet = create(client, eng, network="10.50.0.0/24").json()
    assert client.delete(f"{SUBNETS}/{subnet['id']}", headers=eng).status_code == 204
    assert client.get(f"{SUBNETS}/{subnet['id']}").status_code == 404
    assert sync_db.audit_log.find_one({"action": "subnet.delete"}) is not None


def test_viewer_reads_but_cannot_write(client, sync_db):
    eng = as_role(client, sync_db, "engineer")
    subnet = create(client, eng, network="10.60.0.0/24").json()
    viewer = as_role(client, sync_db, "viewer")
    assert client.get(SUBNETS).status_code == 200
    assert client.get(f"{SUBNETS}/{subnet['id']}/ips").status_code == 200
    assert create(client, viewer, network="10.61.0.0/24").status_code == 403
    assert client.patch(f"{SUBNETS}/{subnet['id']}", headers=viewer,
                        json={"name": "x"}).status_code == 403
    assert client.delete(f"{SUBNETS}/{subnet['id']}", headers=viewer).status_code == 403
    admin = as_role(client, sync_db, "admin")
    assert create(client, admin, network="10.61.0.0/24").status_code == 201


def test_writes_need_csrf(client, sync_db):
    as_role(client, sync_db, "engineer")
    assert client.post(SUBNETS, json={"network": "10.70.0.0/24"}).status_code == 403


@pytest.mark.parametrize(
    "body",
    [
        {"network": "10.80.0.0/24", "$where": "1"},
        {"network": "10.80.0.0/24", "a.b": 1},
        {"network": {"$gt": ""}},
        {"network": "10.80.0.0/24", "gateway": {"$ne": None}},
        {"network": "10.80.0.0/24", "reserved_ranges": [{"start": "10.80.0.1",
                                                         "end": "10.80.0.2", "$set": 1}]},
    ],
)
def test_injection_bodies_rejected(client, sync_db, body):
    eng = as_role(client, sync_db, "engineer")
    r = client.post(SUBNETS, headers=eng, json=body)
    assert r.status_code == 422
    assert sync_db.subnets.count_documents({}) == 0


@pytest.mark.parametrize("bad", ["x", "0" * 23, "g" * 24, "$ne", "0" * 25])
def test_bad_subnet_id(client, sync_db, bad):
    as_role(client, sync_db, "viewer")
    assert client.get(f"{SUBNETS}/{bad}").status_code in (404, 422)
    assert client.get(f"{SUBNETS}/{bad}").status_code != 500


@pytest.mark.parametrize("after", ["4:zz", "{\"$gt\":\"\"}", "4:" + "0" * 31])
def test_bad_page_cursor(client, sync_db, after):
    eng = as_role(client, sync_db, "engineer")
    subnet = create(client, eng, network="10.90.0.0/24").json()
    assert client.get(f"{SUBNETS}/{subnet['id']}/ips", params={"after": after}).status_code == 422
