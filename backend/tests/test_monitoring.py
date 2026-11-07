"""Phase 5: device_down / new_mac alerts, Telegram and e-mail notifications, rate maths."""

import logging
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.services import metrics, notify
from tests.conftest import BASE_URL, make_settings
from tests.ipam_helpers import as_role, seed_report, send
from tests.test_ingest import report
from tests.topology_helpers import access, core

TOKEN = "123456:TEST-bot-token-must-never-be-logged"  # noqa: S105 - test value
NEW_MAC = "f0:18:98:20:00:81"


@pytest.fixture
def make_client(sync_db):
    opened = []

    def factory(**overrides) -> TestClient:
        c = TestClient(create_app(make_settings(**overrides)), base_url=BASE_URL)
        c.__enter__()
        opened.append(c)
        return c

    yield factory
    for c in opened:
        c.__exit__(None, None, None)


@pytest.fixture
def telegram(monkeypatch):
    """A stand-in for api.telegram.org: records every request instead of sending it."""
    sent = []
    real = httpx.AsyncClient

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json={"ok": True})

    monkeypatch.setattr(notify.httpx, "AsyncClient",
                        lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    return sent


TELEGRAM = {"telegram_bot_token": TOKEN, "telegram_chat_id": "-100123"}


def with_new_mac(device: dict, mac: str = NEW_MAC, if_index: int = 2) -> dict:
    return device | {"mac_table": [*device["mac_table"],
                                   {"mac": mac, "if_index": if_index, "vlan": 10}]}


def end_learning(sync_db) -> None:
    sync_db.mac_addresses.update_many({}, {"$set": {
        "first_seen": datetime.now(timezone.utc) - timedelta(days=2)}})


# ---- device_down -----------------------------------------------------------------------------

def test_device_down_lifecycle(client, sync_db):
    agent = seed_report(client, sync_db, core(), access())
    down = access(reachable=False)
    send(client, agent, report(core(), down, ping=[{"ip": "10.10.99.11", "up": False}]))
    alert = sync_db.alerts.find_one({"type": "device_down"})
    assert (alert["status"], alert["severity"]) == ("open", "critical")
    assert alert["message"] == "ACCESS-SW-1 (10.10.99.11) is down: no answer to SNMP or ping."

    send(client, agent, report(core(), down, ping=[{"ip": "10.10.99.11", "up": True}]))
    alert = sync_db.alerts.find_one({"_id": alert["_id"]})
    assert alert["severity"] == "warning" and "answers ping but not SNMP" in alert["message"]

    send(client, agent, report(core(), access()))
    assert sync_db.alerts.find_one({"_id": alert["_id"]})["status"] == "resolved"
    graph_status = {n["label"]: n["status"] for n in client.get(
        "/api/topology", headers=as_role(client, sync_db, "viewer")).json()["nodes"]}
    assert graph_status["ACCESS-SW-1"] == "up"


# ---- new_mac ---------------------------------------------------------------------------------

def test_new_mac_waits_for_the_learning_window(client, sync_db):
    agent = seed_report(client, sync_db, core(), access())
    send(client, agent, report(core(), with_new_mac(access())))
    assert sync_db.alerts.count_documents({"type": "new_mac"}) == 0  # still learning (24 h)
    assert sync_db.mac_addresses.count_documents({"pending_check": True}) == 0

    end_learning(sync_db)
    send(client, agent, report(core(), with_new_mac(access(), "f0:18:98:20:00:99")))
    alert = sync_db.alerts.find_one({"type": "new_mac"})
    assert alert["target"]["mac"] == "f0:18:98:20:00:99"
    assert alert["message"] == ("New unknown device f0:18:98:20:00:99 appeared on ACCESS-SW-1 "
                                "(10.10.99.11) port 2, VLAN 10.")
    assert alert["severity"] == "warning"


def test_new_mac_skips_known_devices_and_reservations(client, sync_db):
    agent = seed_report(client, sync_db, core(), access())
    end_learning(sync_db)
    sync_db.ip_addresses.insert_one({"ip": "10.10.20.9", "ip_key": "x", "reservation": {
        "hostname": "printer", "mac": "aa:aa:aa:00:00:01"}})
    device = with_new_mac(with_new_mac(access(), "aa:aa:aa:00:00:01"), "00:00:0c:c0:00:02")
    send(client, agent, report(core(), device))  # a reserved MAC and a core interface MAC
    assert sync_db.alerts.count_documents({"type": "new_mac"}) == 0


def test_resolving_new_mac_marks_it_known_and_it_stays_resolved(client, sync_db):
    agent = seed_report(client, sync_db, core(), access())
    end_learning(sync_db)
    send(client, agent, report(core(), with_new_mac(access())))
    alert = sync_db.alerts.find_one({"type": "new_mac"})
    eng = as_role(client, sync_db, "engineer")
    assert client.post(f"/api/alerts/{alert['_id']}/resolve", headers=eng).status_code == 200
    assert sync_db.mac_addresses.find_one({"mac": NEW_MAC})["known_by"] == "engineer1"

    send(client, agent, report(core(), with_new_mac(access())))  # still plugged in
    assert sync_db.alerts.find_one({"_id": alert["_id"]})["status"] == "resolved"
    send(client, agent, report(core(), access()))  # unplugged: never auto-resolves anything
    assert sync_db.alerts.count_documents({"type": "new_mac", "status": "open"}) == 0


def test_new_mac_does_not_auto_resolve(client, sync_db):
    agent = seed_report(client, sync_db, core(), access())
    end_learning(sync_db)
    send(client, agent, report(core(), with_new_mac(access())))
    send(client, agent, report(core(), access()))  # the rogue device was unplugged again
    assert sync_db.alerts.find_one({"type": "new_mac"})["status"] == "open"


# ---- notifications ---------------------------------------------------------------------------

def _down_report(agent, client):
    return send(client, agent, report(core(), access(reachable=False),
                                      ping=[{"ip": "10.10.99.11", "up": False}]))


def test_telegram_sent_once_per_opening(make_client, sync_db, telegram, caplog):
    caplog.set_level(logging.DEBUG)
    client = make_client(**TELEGRAM)
    agent = seed_report(client, sync_db, core(), access())
    assert telegram == []
    _down_report(agent, client)
    assert len(telegram) == 1
    request = telegram[0]
    assert request.url.path == f"/bot{TOKEN}/sendMessage"
    body = httpx.Response(200, content=request.content).json()
    assert body["chat_id"] == "-100123" and "parse_mode" not in body  # plain text only
    assert body["text"].startswith("[NetMap] CRITICAL: Device down")
    assert "ACCESS-SW-1 (10.10.99.11) is down" in body["text"]

    _down_report(agent, client)  # same alert, still open: no second message
    assert len(telegram) == 1
    assert sync_db.notifications.count_documents({"status": "sent"}) == 1
    assert TOKEN not in caplog.text  # httpx logs URLs; the token is in Telegram's URL


def test_reopen_within_cooldown_is_suppressed(make_client, sync_db, telegram):
    client = make_client(**TELEGRAM)
    agent = seed_report(client, sync_db, core(), access())
    _down_report(agent, client)
    send(client, agent, report(core(), access()))  # back up: resolved
    _down_report(agent, client)  # down again within 30 minutes: reopened
    assert len(telegram) == 1
    assert sync_db.notifications.find_one({"status": "suppressed"})["reason"] == "cooldown"


def test_hourly_cap(make_client, sync_db, telegram):
    client = make_client(**TELEGRAM)
    agent = seed_report(client, sync_db, core(), access())
    now = datetime.now(timezone.utc)
    sync_db.notifications.insert_many([{"alert_key": f"k{i}", "status": "sent", "at": now}
                                       for i in range(notify.HOURLY_CAP)])
    _down_report(agent, client)
    assert telegram == []
    assert sync_db.notifications.find_one({"status": "suppressed"})["reason"] == "hourly_cap"


def test_min_severity(make_client, sync_db, telegram):
    client = make_client(**TELEGRAM, notify_min_severity="critical")
    agent = seed_report(client, sync_db, core(), access())
    send(client, agent, report(core(), access(reachable=False),
                               ping=[{"ip": "10.10.99.11", "up": True}]))  # warning only
    assert telegram == [] and sync_db.alerts.count_documents({"notify_pending": True}) == 0


def test_no_channel_configured_is_a_no_op(client, sync_db, telegram):
    agent = seed_report(client, sync_db, core(), access())
    _down_report(agent, client)
    assert telegram == [] and sync_db.notifications.count_documents({}) == 0
    assert sync_db.alerts.count_documents({"notify_pending": True}) == 0


def test_telegram_failure_is_recorded_without_secrets(make_client, sync_db, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    real = httpx.AsyncClient

    def refuse(request):
        raise httpx.ConnectError(f"cannot reach {request.url}")  # text contains the token

    monkeypatch.setattr(notify.httpx, "AsyncClient",
                        lambda **kw: real(transport=httpx.MockTransport(refuse), **kw))
    client = make_client(**TELEGRAM)
    agent = seed_report(client, sync_db, core(), access())
    _down_report(agent, client)
    record = sync_db.notifications.find_one()
    assert record["status"] == "failed" and record["channels"] == {
        "telegram": "failed: ConnectError"}
    assert TOKEN not in caplog.text and TOKEN not in str(record)


class FakeSMTP:
    instances: list = []

    def __init__(self, host, port, timeout):
        self.host, self.port, self.calls = host, port, []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self, context):
        self.calls.append("starttls")

    def login(self, user, password):
        self.calls.append(("login", user))

    def send_message(self, message):
        self.calls.append("send")
        self.message = message


def test_email_uses_starttls_and_plain_headers(make_client, sync_db, monkeypatch):
    FakeSMTP.instances = []
    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    client = make_client(smtp_host="smtp.example.org", smtp_from="netmap@example.org",
                         smtp_to="noc@example.org, oncall@example.org",
                         smtp_username="netmap", smtp_password="app-password")
    agent = seed_report(client, sync_db, core(), access())
    _down_report(agent, client)
    [smtp] = FakeSMTP.instances
    assert smtp.calls == ["starttls", ("login", "netmap"), "send"]  # TLS before the password
    assert smtp.message["Subject"] == "[NetMap] CRITICAL: Device down"  # no device text
    assert smtp.message["To"] == "noc@example.org, oncall@example.org"
    assert "ACCESS-SW-1" in smtp.message.get_content()


def test_format_alert_keeps_untrusted_text_out_of_the_subject():
    subject, body = notify.format_alert({"type": "new_mac", "severity": "warning",
                                         "message": "<b>evil</b>\r\nBcc: x@y" + "a" * 2000,
                                         "occurrences": 3,
                                         "opened_at": datetime(2026, 11, 7, 10, 0)})
    assert subject == "[NetMap] WARNING: New unknown device"
    assert len(body) < 1200 and "occurrence 3" in body


# ---- admin test endpoint ---------------------------------------------------------------------

def test_notify_test_endpoint(make_client, sync_db, telegram):
    client = make_client(**TELEGRAM)
    admin = as_role(client, sync_db, "admin")
    status = client.get("/api/admin/notifications", headers=admin).json()
    assert status["channels"] == {"telegram": True, "email": False}
    assert TOKEN not in str(status)

    r = client.post("/api/admin/notifications/test", headers=admin)
    assert r.status_code == 200 and r.json() == {"channels": {"telegram": "sent"}}
    assert "Test notification" in httpx.Response(200, content=telegram[0].content).json()["text"]
    assert sync_db.audit_log.find_one({"action": "notify.test"})["result"] == "success"
    for _ in range(notify.TEST_CAP_PER_10_MIN - 1):
        client.post("/api/admin/notifications/test", headers=admin)
    assert client.post("/api/admin/notifications/test", headers=admin).status_code == 429


def test_notify_test_rbac_and_unconfigured(client, sync_db):
    for role in ("viewer", "engineer"):
        headers = as_role(client, sync_db, role)
        assert client.post("/api/admin/notifications/test", headers=headers).status_code == 403
        assert client.get("/api/admin/notifications", headers=headers).status_code == 403
    admin = as_role(client, sync_db, "admin")
    assert client.post("/api/admin/notifications/test", headers=admin).status_code == 409
    assert client.post("/api/admin/notifications/test").status_code == 403  # no CSRF token


@pytest.mark.parametrize("values", [
    {"telegram_api_base": "http://api.telegram.org"},
    {"telegram_api_base": "https://user@evil.example"},
    {"telegram_chat_id": "1; DROP"},
    {"smtp_to": "a@example.org\nBcc: b@example.org"},
    {"smtp_host": "smtp.example.org; rm"},
])
def test_notification_settings_validated(values):
    with pytest.raises(ValueError):
        Settings(_env_file=None, **values)


def test_empty_env_values_mean_unset(monkeypatch):
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "")
    assert Settings(_env_file=None).telegram_chat_id is None


# ---- rate maths ------------------------------------------------------------------------------

T0 = datetime(2026, 11, 7, 10, 0, tzinfo=timezone.utc)


def sample(octets, seconds=0, bits=64, uptime=1000, errors=0):
    return {"at": T0 + timedelta(seconds=seconds), "bits": bits, "uptime": uptime + seconds,
            "in_octets": octets, "out_octets": octets, "in_errors": errors, "out_errors": 0}


@pytest.mark.parametrize(("old", "new", "bits", "delta"), [
    (100, 250, 64, 150),
    (2**32 - 100, 50, 32, 150),   # 32-bit counter wrapped once
    (5_000, 10, 32, None),        # small drop: a reset, not a wrap
    (5_000, 10, 64, None),        # 64-bit counters don't wrap in practice: a reset
    (None, 10, 64, None),
])
def test_counter_delta(old, new, bits, delta):
    assert metrics.counter_delta(old, new, bits) == delta


def test_compute_rates():
    rates = metrics.compute_rates(sample(0), sample(37_500_000, 300, errors=0), 1000)
    assert rates["in_bps"] == 1_000_000 and rates["interval_s"] == 300
    wrapped = metrics.compute_rates(sample(2**32 - 1_000, bits=32), sample(36_499_000 + 0, 300,
                                                                            bits=32), 1000)
    assert wrapped["in_bps"] == round((36_499_000 + 1_000) * 8 / 300)
    errors = metrics.compute_rates(sample(0, errors=5), sample(10, 60, errors=12), None)
    assert errors["in_errors"] == 7


@pytest.mark.parametrize("current", [
    sample(10, 300, uptime=5),          # rebooted (uptime went down)
    sample(10, 0),                      # no time passed
    sample(10, 7 * 3600),               # too long a gap
    sample(10, 300, bits=32),           # counter type changed
    sample(10**12, 1),                  # faster than the 1 Gbit/s port: a missed wrap
])
def test_compute_rates_refuses_bad_intervals(current):
    assert metrics.compute_rates(sample(0), current, 1000) is None


def test_new_mac_reports_the_access_port_not_the_trunk(client, sync_db):
    agent = seed_report(client, sync_db, core(), access())
    end_learning(sync_db)
    # The core (trunk Gi1/0/2) and the access switch (port 1) both see the new laptop.
    send(client, agent, report(with_new_mac(core(), if_index=2),
                               with_new_mac(access(), if_index=1)))
    assert "ACCESS-SW-1 (10.10.99.11) port 1, VLAN 10" in sync_db.alerts.find_one(
        {"type": "new_mac"})["message"]


def test_new_mac_seen_only_on_a_trunk_says_so(client, sync_db):
    agent = seed_report(client, sync_db, core(), access())
    end_learning(sync_db)
    send(client, agent, report(with_new_mac(core(), if_index=2), access()))
    message = sync_db.alerts.find_one({"type": "new_mac"})["message"]
    assert "CORE-SW-1 (10.10.99.1) port Gi1/0/2 (an uplink: the exact access port is unknown)" \
        in message
