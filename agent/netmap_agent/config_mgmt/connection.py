"""SSH sessions to devices, through Netmiko.

Backup and push code only uses the small `Session` interface below, so tests can swap in a
fake device instead of a real SSH connection.

Secrets: Netmiko can write a session log with everything typed, including passwords. It is
never enabled here, and the netmiko / paramiko loggers are kept at WARNING so their debug
output (which may contain command text) never reaches our logs.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from typing import Protocol

from netmap_agent.credential_store import Profile

for _name in ("netmiko", "paramiko"):
    logging.getLogger(_name).setLevel(logging.WARNING)

CONNECT_TIMEOUT = 15
READ_TIMEOUT = 60


class SessionError(Exception):
    """A login or command failure, with a short code that is safe to show in the UI."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class Session(Protocol):
    vendor: str

    def prompt(self) -> str: ...
    def running_config(self) -> str: ...
    def run(self, command: str, prompt_may_change: bool = False) -> str: ...
    def configure(self, lines: list[str], mode_command: str | None = None) -> str: ...
    def write_raw(self, data: str, expect: str) -> str: ...
    def close(self) -> None: ...


def _wrapped(method):
    """Turn any failure inside a session (dropped connection, timeout) into a SessionError."""

    def call(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except SessionError:
            raise
        except Exception as exc:  # netmiko, paramiko and socket errors all end up here
            raise SessionError("ssh_error", f"SSH session failed ({type(exc).__name__})") from exc

    return call


class NetmikoSession:
    def __init__(self, conn, vendor: str) -> None:  # conn: netmiko BaseConnection
        self._conn = conn
        self.vendor = vendor

    @_wrapped
    def prompt(self) -> str:
        return self._conn.find_prompt()

    @_wrapped
    def running_config(self) -> str:
        command = "/export" if self.vendor == "mikrotik_routeros" else "show running-config"
        return self._conn.send_command(command, read_timeout=READ_TIMEOUT)

    @_wrapped
    def run(self, command: str, prompt_may_change: bool = False) -> str:
        if not prompt_may_change:
            return self._conn.send_command(command, read_timeout=READ_TIMEOUT)
        # A rollback can put an old hostname back: accept any "name#" prompt, then re-learn it.
        output = self._conn.send_command(command, read_timeout=READ_TIMEOUT,
                                         expect_string=r"\S+[>#]\s*$")
        self._conn.set_base_prompt()
        return output

    @_wrapped
    def configure(self, lines: list[str], mode_command: str | None = None) -> str:
        kwargs = {"config_mode_command": mode_command} if mode_command else {}
        output = self._conn.send_config_set(lines, read_timeout=READ_TIMEOUT, cmd_verify=False,
                                            **kwargs)
        # A `hostname` line changes the prompt that later commands wait for.
        self._conn.set_base_prompt()
        return output

    @_wrapped
    def write_raw(self, data: str, expect: str) -> str:
        """Send control keys (MikroTik safe mode is Ctrl+X) and wait for a pattern."""
        self._conn.write_channel(data)
        return self._conn.read_until_pattern(pattern=re.escape(expect), read_timeout=20)

    def close(self) -> None:
        self._conn.disconnect()


@contextmanager
def open_session(ip: str, profile: Profile, known_hosts: str = "") -> Iterator[Session]:
    """Log in to a device. Errors come back as SessionError with a short, secret-free code.

    With `known_hosts`, the device's SSH host key must already be in that file. Without it,
    Netmiko accepts whatever key the device presents (convenient in a lab, but a man in the
    middle could then capture the password) - see docs/known-limitations.md.
    """
    host_keys = (
        {"ssh_strict": True, "alt_host_keys": True, "alt_key_file": known_hosts}
        if known_hosts else {}
    )
    from netmiko import ConnectHandler  # imported lazily: it is slow to import
    from netmiko.exceptions import (
        NetmikoAuthenticationException,
        NetmikoTimeoutException,
        ReadTimeout,
    )

    try:
        conn = ConnectHandler(
            device_type=profile.device_type,
            host=profile.ssh_host or ip,
            port=profile.ssh_port,
            username=profile.username,
            password=profile.password,
            secret=profile.secret,
            conn_timeout=CONNECT_TIMEOUT,
            auth_timeout=CONNECT_TIMEOUT,
            session_log=None,
            # Never fall back to keys or an SSH agent on the agent PC: only the stored login.
            use_keys=False,
            allow_agent=False,
            **host_keys,
        )
        if profile.device_type == "cisco_ios" and not conn.check_enable_mode():
            conn.enable()
    except NetmikoAuthenticationException as exc:
        raise SessionError("auth_failed", "SSH login was rejected") from exc
    except (NetmikoTimeoutException, ReadTimeout) as exc:
        # Netmiko reports a rejected host key (paramiko SSHException) as a timeout too.
        text = str(exc).lower()
        if "known_hosts" in text or "host key" in text:
            raise SessionError("host_key_rejected", "Unknown or changed SSH host key") from exc
        raise SessionError("timeout", "Device did not answer on SSH") from exc
    except Exception as exc:  # paramiko raises SSHException for an unknown host key
        if "host key" in str(exc).lower() or type(exc).__name__ == "BadHostKeyException":
            raise SessionError("host_key_rejected", "Unknown or changed SSH host key") from exc
        raise SessionError("ssh_error", f"SSH connection failed ({type(exc).__name__})") from exc
    session = NetmikoSession(conn, profile.device_type)
    try:
        yield session
    finally:
        # The device may already have dropped us; closing must never hide the real error.
        with suppress(Exception):
            session.close()
