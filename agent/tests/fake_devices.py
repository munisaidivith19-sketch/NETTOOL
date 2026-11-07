"""In-memory devices for config backup / push tests (no SSH, no threads beyond the timer)."""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from netmap_agent.config_mgmt.connection import SessionError
from netmap_agent.config_mgmt.jobsign import commands_sha256, sign_job
from simulation.ssh_sim import FakeIOS, _Shell

AGENT_KEY = "test-agent-key-" + "x" * 30


class _Chan:
    def __init__(self) -> None:
        self.out: list[bytes] = []

    def sendall(self, data: bytes) -> None:
        self.out.append(data)

    def take(self) -> str:
        text = b"".join(self.out).decode().replace("\r\n", "\n")
        self.out.clear()
        return text


class IOSSession:
    """Drives the simulator's CLI logic directly, like Netmiko would over SSH."""

    vendor = "cisco_ios"

    def __init__(self, ios: FakeIOS, fail_on: str | None = None) -> None:
        self.chan = _Chan()
        self.shell = _Shell(ios, self.chan)
        self.shell.privileged = True
        self.fail_on = fail_on
        self.commands: list[str] = []

    def prompt(self) -> str:
        return self.shell.prompt()

    def running_config(self) -> str:
        return self.run("show running-config")

    def run(self, command: str, prompt_may_change: bool = False) -> str:
        self.commands.append(command)
        if self.fail_on and command == self.fail_on:
            raise SessionError("ssh_error", "connection dropped")
        return self.shell.handle_exec(command) or ""

    def configure(self, lines: list[str], mode_command: str | None = None) -> str:
        self.commands.append(mode_command or "configure terminal")
        self.chan.out.clear()
        output = [self.shell.handle_exec(mode_command or "configure terminal") or ""]
        for line in [*lines, "end"]:
            self.chan.sendall(f"{line}\n".encode())  # the echo a real terminal shows
            self.shell.handle_config(line)
        return "\n".join([*output, self.chan.take()])

    def write_raw(self, data: str, expect: str) -> str:
        raise NotImplementedError

    def close(self) -> None:
        pass


def ios_connect(ios: FakeIOS, sessions: list | None = None, fail_on: str | None = None):
    """A `connect` function for push/backup code: refuses logins while the device is 'broken'."""

    @contextmanager
    def connect(ip, profile):
        if ios.broken:
            raise SessionError("auth_failed", "login refused")
        session = IOSSession(ios, fail_on=fail_on)
        if sessions is not None:
            sessions.append(session)
        yield session

    return connect


def make_job(commands: str, *, before_hash: str = "", vendor: str = "cisco_ios",
             protected: list[str] | None = None, expires_in: timedelta = timedelta(hours=1),
             key: str = AGENT_KEY, mgmt_ip: str = "10.10.99.1") -> dict:
    job = {
        "change_id": "c" * 24, "device_id": "d" * 24, "mgmt_ip": mgmt_ip, "vendor": vendor,
        "commands": commands, "commands_sha256": commands_sha256(commands),
        "before_hash": before_hash, "protected_interfaces": protected or [],
        "expires_at": (datetime.now(timezone.utc) + expires_in).isoformat(),
    }
    job["signature"] = sign_job(key, job)
    return job
