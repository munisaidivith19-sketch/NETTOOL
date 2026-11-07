"""Backups and the safe push flow, against the in-memory simulated IOS devices."""

import time
from contextlib import contextmanager
from datetime import timedelta

import pytest

from netmap_agent.config_mgmt import push as push_mod
from netmap_agent.config_mgmt.backup import config_hash, normalize, read_backup, upload_payload
from netmap_agent.config_mgmt.connection import SessionError
from netmap_agent.config_mgmt.jobsign import sign_job, verify_job
from netmap_agent.config_mgmt.push import PushOptions, check_job, push_job
from netmap_agent.credential_store import Profile
from simulation.ssh_sim import CORE_SWITCH, EDGE_ROUTER, NEW_SWITCH, FakeIOS
from tests.fake_devices import AGENT_KEY, IOSSession, ios_connect, make_job

PROFILE = Profile(name="sim", match="10.10.0.0/16", device_type="cisco_ios", username="netmap",
                  password="netmap-sim-ssh", secret="netmap-sim-enable")
FAST = PushOptions(revert_minutes=1, seconds_per_minute=1)


def backup_hash(ios: FakeIOS) -> str:
    return read_backup(IOSSession(ios), AGENT_KEY).hash


def run(ios: FakeIOS, job: dict, *, ping_ok: bool = True, fail_on: str | None = None,
        statuses: list | None = None):
    return push_job(job, PROFILE, AGENT_KEY, FAST, connect=ios_connect(ios, fail_on=fail_on),
                    ping_fn=lambda target: ping_ok,
                    report=(statuses.append if statuses is not None else lambda s: None),
                    sleep=lambda seconds: time.sleep(min(seconds, 0.3)))


# ------------------------------------------------------------------ backups

def test_normalize_drops_volatile_lines() -> None:
    a = FakeIOS(CORE_SWITCH)
    first = read_backup(IOSSession(a), AGENT_KEY)
    a.changed_at = "12:34:56 UTC"  # only the "Last configuration change" line differs
    assert read_backup(IOSSession(a), AGENT_KEY).hash == first.hash
    assert "Building configuration" not in first.raw and first.raw.startswith("!")


def test_hash_is_keyed_and_sees_password_only_changes() -> None:
    text = normalize("hostname R1\nenable secret 9 $9$aaa\n", "cisco_ios")
    changed = normalize("hostname R1\nenable secret 9 $9$bbb\n", "cisco_ios")
    assert config_hash(AGENT_KEY, text) != config_hash(AGENT_KEY, changed)
    assert config_hash(AGENT_KEY, text) != config_hash("another-agent-key", text)


def test_backup_is_masked_and_carries_facts() -> None:
    backup = read_backup(IOSSession(FakeIOS(EDGE_ROUTER)), AGENT_KEY)
    assert "public" not in backup.masked and "$9$" not in backup.masked
    assert backup.facts == {"snmp_default_community": True}
    assert "public" in backup.raw  # the raw text exists only in agent memory


def test_upload_only_sends_text_when_changed() -> None:
    backup = read_backup(IOSSession(FakeIOS(CORE_SWITCH)), AGENT_KEY)
    assert "text" in upload_payload("d1", backup, None, "scheduled")
    same = upload_payload("d1", backup, backup.hash, "scheduled")
    assert "text" not in same and same["hash"] == backup.hash
    failed = upload_payload("d1", None, None, "manual", error="auth_failed")
    assert failed == {"device_id": "d1", "source": "manual", "error": "auth_failed"}


# ------------------------------------------------------------------ job checks

def test_signature_covers_every_field() -> None:
    job = make_job("hostname X")
    assert verify_job(AGENT_KEY, job)
    for field, value in [("commands", "reload"), ("mgmt_ip", "10.0.0.9"),
                         ("protected_interfaces", []), ("before_hash", "x"),
                         ("expires_at", "2099-01-01T00:00:00+00:00")]:
        tampered = dict(job, **{field: value})
        if field == "protected_interfaces":
            tampered = dict(make_job("hostname X", protected=["Gi0/1"]), protected_interfaces=[])
        assert not verify_job(AGENT_KEY, tampered), field
    assert not verify_job("other-key", job)


@pytest.mark.parametrize(("job", "error"), [
    (dict(make_job("hostname X"), signature="0" * 64), "bad_signature"),
    (make_job("hostname X", key="a-different-agent-key"), "bad_signature"),
    (make_job("hostname X", expires_in=timedelta(minutes=-1)), "expired"),
    (make_job("hostname X", vendor="mikrotik_routeros"), "vendor_mismatch"),
    # Correctly signed by the backend, but the agent still refuses it.
    (make_job("reload"), "denylisted"),
    (make_job("interface Gi0/1\n shutdown", protected=["GigabitEthernet0/1"]), "denylisted"),
])
def test_refused_jobs_never_touch_the_device(job: dict, error: str) -> None:
    ios = FakeIOS(CORE_SWITCH)
    sessions: list = []
    result = push_job(job, PROFILE, AGENT_KEY, FAST, connect=ios_connect(ios, sessions),
                      ping_fn=lambda t: True)
    assert result.status == "failed" and result.error == error
    assert sessions == []


def test_tampered_commands_hash_is_refused() -> None:
    job = make_job("hostname X")
    job["commands"] = "hostname Y"
    job["signature"] = sign_job(AGENT_KEY, job)  # signature fine, but sha256 no longer matches
    assert check_job(job, AGENT_KEY, PROFILE) == "bad_signature"


def test_no_credentials() -> None:
    result = push_job(make_job("hostname X"), None, AGENT_KEY, FAST,
                      connect=ios_connect(FakeIOS(CORE_SWITCH)), ping_fn=lambda t: True)
    assert (result.status, result.error) == ("failed", "no_credentials")


# ------------------------------------------------------------------ push flow

def test_successful_push_is_confirmed_and_saved() -> None:
    ios = FakeIOS(CORE_SWITCH)
    before = backup_hash(ios)
    statuses: list = []
    job = make_job("interface GigabitEthernet1/0/4\n description AP-1 uplink (PoE)",
                   before_hash=before, protected=["GigabitEthernet1/0/2"])
    result = run(ios, job, statuses=statuses)
    assert result.status == "done", result.log
    assert statuses == ["verifying"]
    assert result.before_hash == before and result.after_hash != before
    assert " description AP-1 uplink (PoE)" in ios.running_config()
    assert ios._timer is None  # confirmed: the device won't revert it later
    assert any("write memory" in line for line in result.log)
    assert result.after_backup is not None and result.after_backup.hash == result.after_hash


def test_config_changed_since_approval_is_refused() -> None:
    ios = FakeIOS(CORE_SWITCH)
    result = run(ios, make_job("hostname X", before_hash="stale-hash"))
    assert (result.status, result.error) == ("failed", "config_changed")
    assert "hostname CORE-SW-1" in ios.running_config()


def test_management_interface_found_on_the_device_is_protected() -> None:
    # The backend didn't list Vlan99, but the agent sees it holds the IP it logs in to.
    ios = FakeIOS(CORE_SWITCH)
    result = run(ios, make_job("interface Vlan99\n shutdown", mgmt_ip="10.10.99.1"))
    assert (result.status, result.error) == ("failed", "denylisted")
    assert " shutdown" not in ios.running_config().split("interface Vlan99")[1].split("!")[0]


def test_without_archive_nothing_is_pushed() -> None:
    ios = FakeIOS(NEW_SWITCH)
    before = ios.running_config()
    result = run(ios, make_job("hostname ACCESS-SW-3"))
    assert (result.status, result.error) == ("failed", "archive_missing")
    assert ios.running_config() == before


def test_archive_block_first_then_timed_change() -> None:
    ios = FakeIOS(NEW_SWITCH)
    job = make_job("archive\n path flash:archive\n maximum 5\nhostname ACCESS-SW-3\n"
                   "interface GigabitEthernet1/0/2\n shutdown", before_hash=backup_hash(ios))
    result = run(ios, job)
    assert result.status == "done", result.log
    config = ios.running_config()
    assert "hostname ACCESS-SW-3" in config and " path flash:archive" in config


def test_lockout_is_rolled_back() -> None:
    ios = FakeIOS(CORE_SWITCH, break_after_push=True)
    before = backup_hash(ios)
    result = run(ios, make_job("hostname BROKEN", before_hash=before))
    assert (result.status, result.error) == ("rolled_back", "verify_failed"), result.log
    assert result.after_hash == before
    assert "hostname CORE-SW-1" in ios.running_config() and not ios.broken
    assert any("configure revert now" in line for line in result.log)


def test_ping_failure_is_rolled_back() -> None:
    ios = FakeIOS(CORE_SWITCH)
    before = backup_hash(ios)
    result = run(ios, make_job("hostname X", before_hash=before), ping_ok=False)
    assert result.status == "rolled_back" and result.after_hash == before


def test_rejected_command_is_rolled_back() -> None:
    ios = FakeIOS(CORE_SWITCH)
    before = backup_hash(ios)
    result = run(ios, make_job("hostname X\ninvalid-command here", before_hash=before))
    assert result.status == "rolled_back"
    assert "hostname CORE-SW-1" in ios.running_config()


def test_lost_session_waits_for_the_device_timer() -> None:
    ios = FakeIOS(CORE_SWITCH, break_after_push=True, seconds_per_minute=0.2)
    before = backup_hash(ios)
    result = run(ios, make_job("hostname X", before_hash=before),
                 fail_on="configure revert now")
    assert result.status == "rolled_back", result.log
    assert any("revert timer will undo" in line for line in result.log)


def test_secrets_in_command_echo_are_masked_in_the_log() -> None:
    ios = FakeIOS(CORE_SWITCH)
    job = make_job("username netops privilege 15 secret Very-Secret-Value",
                   before_hash=backup_hash(ios))
    result = run(ios, job)
    assert result.status == "done"
    assert "Very-Secret-Value" not in result.as_payload()["log"]


# ------------------------------------------------------------------ MikroTik safe mode

class FakeRouterOS:
    vendor = "mikrotik_routeros"

    def __init__(self, state: dict, reject: bool = False) -> None:
        self.state = state
        self.reject = reject

    def prompt(self) -> str:
        return "[netmap@ACCESS-SW-2] <SAFE>>" if self.state["safe"] else "[netmap@ACCESS-SW-2] >"

    def running_config(self) -> str:
        return "# 2026-11-07 10:00:00 by RouterOS 7.14\n/system identity\nset name=" + \
            self.state["name"] + "\n" + "\n".join(self.state["lines"]) + "\n"

    def run(self, command: str, prompt_may_change: bool = False) -> str:
        return ""

    def configure(self, lines, mode_command=None) -> str:
        self.state["lines"].extend(lines)
        return "failure: bad thing" if self.reject else ""

    def write_raw(self, data: str, expect: str) -> str:
        self.state["keys"].append(data)
        if data == "\x18":
            if self.state["safe"]:
                self.state["safe"] = False
                self.state["saved"] = list(self.state["lines"])
            else:
                self.state["safe"] = True
                self.state["saved"] = list(self.state["lines"])
        elif data == "\x04" and self.state["safe"]:
            self.state["lines"] = self.state["saved"]  # undo everything since safe mode began
            self.state["safe"] = False
        return self.prompt()

    def close(self) -> None:
        pass


def ros_connect(state: dict, reject: bool = False):
    @contextmanager
    def connect(ip, profile):
        if state.get("locked"):
            raise SessionError("auth_failed", "refused")
        yield FakeRouterOS(state, reject)

    return connect


ROS_PROFILE = Profile(name="ros", match="10.10.99.12/32", device_type="mikrotik_routeros",
                      username="netmap", password="netmap-sim-ssh")


@pytest.mark.parametrize(("reject", "ping_ok", "status"), [
    (False, True, "done"), (True, True, "rolled_back"), (False, False, "rolled_back"),
])
def test_routeros_safe_mode(reject: bool, ping_ok: bool, status: str) -> None:
    state = {"safe": False, "name": "ACCESS-SW-2", "lines": [], "keys": [], "saved": []}
    connect = ros_connect(state, reject)
    with connect("x", ROS_PROFILE) as session:
        before = read_backup(session, AGENT_KEY).hash
    job = make_job("/interface vlan add name=vlan40 vlan-id=40 interface=bridge",
                   vendor="mikrotik_routeros", before_hash=before, mgmt_ip="10.10.99.12")
    result = push_job(job, ROS_PROFILE, AGENT_KEY, FAST, connect=connect,
                      ping_fn=lambda t: ping_ok, sleep=lambda s: None)
    assert result.status == status, result.log
    assert state["keys"][0] == "\x18"  # safe mode on before any command
    if status == "done":
        assert state["keys"][-1] == "\x18" and state["lines"]
    else:
        assert state["keys"][-1] == "\x04" and state["lines"] == []


def test_interface_with_ip_parsing() -> None:
    ios_cfg = "interface Vlan99\n description mgmt\n ip address 10.10.99.1 255.255.255.0\n!"
    assert push_mod._interface_with_ip(ios_cfg, "10.10.99.1", "cisco_ios") == "Vlan99"
    assert push_mod._interface_with_ip(ios_cfg, "10.10.99.10", "cisco_ios") is None
    ros = "/ip address\nadd address=10.10.99.12/24 interface=bridge network=10.10.99.0\n"
    assert push_mod._interface_with_ip(ros, "10.10.99.12", "mikrotik_routeros") == "bridge"


def test_expired_revert_timer_counts_as_rolled_back() -> None:
    # Verification took longer than the timer: the device already undid the change, and
    # `configure confirm` says so. The agent must not report "done".
    ios = FakeIOS(CORE_SWITCH, seconds_per_minute=0.05)
    before = backup_hash(ios)

    def slow_ping(target: str) -> bool:
        time.sleep(0.3)
        return True

    result = push_job(make_job("hostname X", before_hash=before), PROFILE, AGENT_KEY, FAST,
                      connect=ios_connect(ios), ping_fn=slow_ping, sleep=lambda s: None)
    assert (result.status, result.error) == ("rolled_back", "revert_timer_expired"), result.log
    assert "hostname CORE-SW-1" in ios.running_config()
