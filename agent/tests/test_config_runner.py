"""ConfigManager with a fake backend, plus one real-SSH run against simulation/ssh_sim.py."""

import random

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from netmap_agent.config import AgentSettings
from netmap_agent.config_mgmt.backup import read_backup
from netmap_agent.config_mgmt.runner import ConfigManager
from netmap_agent.credential_store import CredentialStore, Profile
from simulation import ssh_sim
from simulation.ssh_sim import CORE_SWITCH, EDGE_ROUTER, NEW_SWITCH, FakeIOS
from tests.fake_devices import AGENT_KEY, IOSSession, ios_connect, make_job


class FakeBackend:
    def __init__(self, targets: list[dict], jobs: list[dict] | None = None) -> None:
        self.targets = targets
        self.jobs = list(jobs or [])
        self.configs: list[dict] = []
        self.statuses: list[tuple[str, dict]] = []

    def backup_targets(self) -> list[dict]:
        return self.targets

    def send_config(self, payload: dict) -> dict:
        self.configs.append(payload)
        return {}

    def claim_job(self) -> dict | None:
        return self.jobs.pop(0) if self.jobs else None

    def job_status(self, change_id: str, payload: dict) -> dict:
        self.statuses.append((change_id, payload))
        return {}


def settings(**extra) -> AgentSettings:
    values = {"agent_id": "agt_" + "0" * 16, "agent_key": SecretStr(AGENT_KEY),
              "change_revert_minutes": 1, "change_revert_seconds_per_minute": 1} | extra
    return AgentSettings(_env_file=None, **values)


def store_with(tmp_path, *profiles: Profile) -> CredentialStore:
    store = CredentialStore(tmp_path / "credentials.enc", Fernet.generate_key().decode())
    for item in profiles:
        store.add(item)
    return store


def cisco_profile(match: str, **extra) -> Profile:
    return Profile(name=match.replace("/", "_"), match=match, device_type="cisco_ios",
                   username="netmap", password=ssh_sim.SIM_SSH_PASSWORD,
                   secret=ssh_sim.SIM_ENABLE_SECRET, **extra)


def test_backup_uploads_masked_text_and_reports_failures(tmp_path) -> None:
    edge = FakeIOS(EDGE_ROUTER)
    backend = FakeBackend([
        {"device_id": "d-edge", "mgmt_ip": "127.0.0.11", "last_hash": None},
        {"device_id": "d-ap", "mgmt_ip": "127.0.0.15", "last_hash": None},
    ])
    manager = ConfigManager(settings(), backend,
                            store=store_with(tmp_path, cisco_profile("127.0.0.11/32")),
                            connect=ios_connect(edge), ping_fn=lambda t: True)
    counts = manager.backup()
    assert counts == {"devices": 2, "changed": 1, "unchanged": 0, "failed": 1}
    by_id = {c["device_id"]: c for c in backend.configs}
    assert by_id["d-ap"]["error"] == "no_credentials"
    text = by_id["d-edge"]["text"]
    assert "hostname EDGE-RTR-1" in text and "public" not in text and "$9$" not in text
    assert by_id["d-edge"]["facts"] == {"snmp_default_community": True}

    backend.targets[0]["last_hash"] = by_id["d-edge"]["hash"]
    backend.configs.clear()
    assert manager.backup()["unchanged"] == 1
    assert "text" not in backend.configs[0]


def test_only_requested_backups(tmp_path) -> None:
    backend = FakeBackend([{"device_id": "a", "mgmt_ip": "127.0.0.11", "requested": True},
                           {"device_id": "b", "mgmt_ip": "127.0.0.12"}])
    manager = ConfigManager(settings(), backend, store=store_with(tmp_path),
                            connect=ios_connect(FakeIOS(CORE_SWITCH)), ping_fn=lambda t: True)
    manager.backup(only_requested=True)
    assert [(c["device_id"], c["source"]) for c in backend.configs] == [("a", "manual")]


def test_run_jobs_reports_and_uploads_after_config(tmp_path) -> None:
    core = FakeIOS(CORE_SWITCH)
    job = make_job("vlan 40\n name GUESTS",
                   before_hash=read_backup(IOSSession(core), AGENT_KEY).hash)
    backend = FakeBackend([], jobs=[job])
    manager = ConfigManager(settings(), backend,
                            store=store_with(tmp_path, cisco_profile("10.10.99.1/32")),
                            connect=ios_connect(core), ping_fn=lambda t: True)
    assert manager.run_jobs() == 1
    assert [s[1]["status"] for s in backend.statuses] == ["verifying", "done"]
    assert backend.configs[0]["source"] == "post_change"
    assert backend.configs[0]["change_id"] == job["change_id"]
    assert "vlan 40" in backend.configs[0]["text"]


# ------------------------------------------------------------------ real SSH

@pytest.fixture(scope="module")
def ssh_lab(tmp_path_factory):
    port = random.randint(20000, 29000)  # noqa: S311 - just a test port
    known = tmp_path_factory.mktemp("ssh") / "known_hosts"
    # 20 s per revert minute: long enough for Netmiko to verify before confirming.
    devices = ssh_sim.start(seconds_per_minute=20, known_hosts=known, port=port)
    return {ios.device.slug: ios for ios in devices}, port, known


def test_netmiko_backup_and_push_over_ssh(ssh_lab, tmp_path) -> None:
    devices, port, known = ssh_lab
    new_switch = devices[NEW_SWITCH.slug]
    store = store_with(tmp_path, cisco_profile("127.0.0.16/32", ssh_port=port))
    backend = FakeBackend([{"device_id": "d-new", "mgmt_ip": "127.0.0.16"}])
    manager = ConfigManager(settings(ssh_known_hosts_file=str(known)), backend, store=store,
                            ping_fn=lambda t: True)
    manager.backup()
    upload = backend.configs[0]
    assert "error" not in upload, upload
    assert "hostname Switch" in upload["text"]

    job = make_job("archive\n path flash:archive\nhostname ACCESS-SW-3", mgmt_ip="127.0.0.16",
                   before_hash=upload["hash"])
    result = manager.run_job(job)
    assert result.status == "done", result.log
    assert new_switch.hostname == "ACCESS-SW-3"

    # Lock-out: the next push makes the device refuse new logins until it is reverted.
    new_switch.break_after_push = True
    job = make_job("hostname LOCKED-OUT", mgmt_ip="127.0.0.16", before_hash=result.after_hash)
    result = manager.run_job(job)
    assert result.status == "rolled_back", result.log
    assert new_switch.hostname == "ACCESS-SW-3"
    new_switch.break_after_push = False


def test_unknown_host_key_is_refused(ssh_lab, tmp_path) -> None:
    _, port, _ = ssh_lab
    other_known = tmp_path / "known_hosts"
    other_known.write_text("")
    backend = FakeBackend([{"device_id": "d-core", "mgmt_ip": "127.0.0.12"}])
    manager = ConfigManager(settings(ssh_known_hosts_file=str(other_known)), backend,
                            store=store_with(tmp_path, cisco_profile("127.0.0.12/32",
                                                                     ssh_port=port)),
                            ping_fn=lambda t: True)
    manager.backup()
    assert backend.configs[0]["error"] == "host_key_rejected"


def test_wrong_password_is_reported_without_details(ssh_lab, tmp_path) -> None:
    _, port, known = ssh_lab
    bad = Profile(name="bad", match="127.0.0.11/32", device_type="cisco_ios", username="netmap",
                  password="wrong-password-123", ssh_port=port)
    backend = FakeBackend([{"device_id": "d-edge", "mgmt_ip": "127.0.0.11"}])
    manager = ConfigManager(settings(ssh_known_hosts_file=str(known)), backend,
                            store=store_with(tmp_path, bad), ping_fn=lambda t: True)
    manager.backup()
    assert backend.configs[0] == {"device_id": "d-edge", "source": "scheduled",
                                  "error": "auth_failed"}
