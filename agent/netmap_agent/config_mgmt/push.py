"""Push an approved change to a device safely, and roll it back if the device stops answering.

The steps (CLAUDE.md 7.5), in plain words:
1. Check the job really came from the backend unchanged (signature), hasn't expired, and
   that the commands still pass the denylist - the agent never trusts the backend blindly.
2. Log in and read the config. If it is different from the config the change was approved
   against, stop: someone changed the device in the meantime and the preview is stale.
3. Cisco: start `configure terminal revert timer N`. The device itself will undo the change
   after N minutes unless we confirm it. MikroTik: the same idea with safe mode (Ctrl+X).
4. Verify: ping the device and open a *second* SSH session. If we locked ourselves out,
   that second login fails.
5. Good -> confirm (and save). Bad -> undo now (`configure revert now`), or, if even our
   first session is gone, wait for the device's own timer; then check the config is back to
   what it was. Either way the result is reported, with config fingerprints before and after.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from netmap_agent.config_mgmt.backup import Backup, read_backup
from netmap_agent.config_mgmt.connection import Session, SessionError, open_session
from netmap_agent.config_mgmt.denylist import check_commands
from netmap_agent.config_mgmt.jobsign import commands_sha256, verify_job
from netmap_agent.config_mgmt.masking import mask_config
from netmap_agent.credential_store import Profile

logger = logging.getLogger("netmap_agent.push")

MAX_LOG_CHARS = 8000
_IOS_ERROR = re.compile(r"^\s*% ?(Invalid|Incomplete|Ambiguous|Unknown|Error|Bad|Unrecognized)",
                        re.MULTILINE | re.IGNORECASE)
_ROS_ERROR = re.compile(r"(failure:|syntax error|bad command name|expected end of command|"
                        r"input does not match|no such item|invalid value)", re.IGNORECASE)


@dataclass
class PushOptions:
    revert_minutes: int = 5
    save_config: bool = True
    # How long one "minute" of the revert timer lasts. 60 on real devices; the simulator
    # counts revert minutes as seconds so a rollback demo doesn't take five minutes.
    seconds_per_minute: int = 60


@dataclass
class PushResult:
    status: str  # done | rolled_back | failed
    error: str | None = None
    before_hash: str | None = None
    after_hash: str | None = None
    log: list[str] = field(default_factory=list)
    after_backup: Backup | None = None

    def as_payload(self) -> dict:
        text = "\n".join(self.log)
        return {"status": self.status, "error": self.error, "before_hash": self.before_hash,
                "after_hash": self.after_hash, "log": text[-MAX_LOG_CHARS:]}


Connect = Callable[[str, Profile], object]  # returns a context manager yielding a Session


class _Log(list):
    def __init__(self, vendor: str) -> None:
        super().__init__()
        self.vendor = vendor

    def add(self, message: str, output: str = "") -> None:
        self.append(message)
        if output.strip():
            # Command echoes can contain secrets (`username x secret y`): mask before keeping.
            self.append(mask_config(output.strip(), self.vendor)[:2000])


def _interface_with_ip(raw_config: str, ip: str, vendor: str) -> str | None:
    """The interface that holds the address we SSH to: it must never be shut by a change."""
    escaped = re.escape(ip)
    if vendor == "mikrotik_routeros":
        match = re.search(rf"address={escaped}/\d+\b.*?\binterface=(\S+)", raw_config)
        return match.group(1) if match else None
    current = None
    for line in raw_config.splitlines():
        if line.startswith("interface "):
            current = line.split(None, 1)[1].strip()
        elif not line.startswith(" "):
            current = None
        elif current and re.match(rf"^\s+ip(v6)? address {escaped}\b", line):
            return current
    return None


def _split_archive_block(lines: list[str]) -> tuple[list[str], list[str]]:
    """A leading `archive` block (from the baseline template) is applied before the timer."""
    if not lines or lines[0].strip() != "archive":
        return [], lines
    end = 1
    while end < len(lines) and lines[end].startswith(" "):
        end += 1
    return lines[:end], lines[end:]


def _has_archive(raw_config: str) -> bool:
    return bool(re.search(r"^archive\s*\n(?: .*\n)*? path \S+", raw_config, re.MULTILINE))


def verify_reachable(ip: str, profile: Profile, connect: Connect,
                     ping_fn: Callable[[str], bool]) -> tuple[bool, str]:
    target = profile.ssh_host or ip
    if not ping_fn(target):
        return False, "device stopped answering ping"
    try:
        with connect(ip, profile) as session:
            session.prompt()
            session.running_config()
    except SessionError as exc:
        return False, f"a new SSH login failed ({exc.code})"
    return True, "ping and a new SSH login both work"


def check_job(job: dict, agent_key: str, profile: Profile | None,
              now: datetime | None = None) -> str | None:
    """Return an error code if the job must not be run at all, else None."""
    if not verify_job(agent_key, job):
        return "bad_signature"
    if commands_sha256(job.get("commands", "")) != job.get("commands_sha256"):
        return "bad_signature"
    try:
        expires = datetime.fromisoformat(job["expires_at"])
    except (KeyError, TypeError, ValueError):
        return "bad_signature"
    if (now or datetime.now(timezone.utc)) > expires:
        return "expired"
    if profile is None:
        return "no_credentials"
    if profile.device_type != job.get("vendor"):
        return "vendor_mismatch"
    if check_commands(job["commands"], job["vendor"], job.get("protected_interfaces", [])):
        return "denylisted"
    return None


def push_job(
    job: dict,
    profile: Profile | None,
    agent_key: str,
    options: PushOptions,
    *,
    connect: Connect = open_session,
    ping_fn: Callable[[str], bool],
    report: Callable[[str], None] = lambda status: None,
    sleep: Callable[[float], None] = time.sleep,
) -> PushResult:
    vendor = job.get("vendor", "")
    log = _Log(vendor)
    error = check_job(job, agent_key, profile)
    if error or profile is None:
        log.add(f"Refused before connecting: {error or 'no_credentials'}.")
        return PushResult("failed", error or "no_credentials", log=log)
    ip = job["mgmt_ip"]
    try:
        with connect(ip, profile) as session:
            before = read_backup(session, agent_key)
            log.add("Read the current configuration.")
            if job.get("before_hash") and before.hash != job["before_hash"]:
                log.add("The device configuration changed after this change was approved. "
                        "Nothing was pushed; take a new backup and submit the change again.")
                return PushResult("failed", "config_changed", before.hash, log=log)
            protected = list(job.get("protected_interfaces", []))
            mgmt_if = _interface_with_ip(before.raw, ip, vendor)
            if mgmt_if:
                protected.append(mgmt_if)
            violations = check_commands(job["commands"], vendor, protected)
            if violations:
                log.add(f"Blocked by the denylist on the agent: {violations[0].reason}")
                return PushResult("failed", "denylisted", before.hash, log=log)
            lines = job["commands"].splitlines()
            if vendor == "cisco_ios":
                return _push_cisco(session, lines, before, ip, profile, agent_key, options,
                                   connect, ping_fn, report, sleep, log)
            return _push_routeros(session, lines, before, ip, profile, agent_key, connect,
                                  ping_fn, report, sleep, options, log)
    except SessionError as exc:
        log.add(f"Could not complete the change: {exc.code}.")
        return PushResult("failed", exc.code, log=log)


def _confirm_rolled_back(session: Session | None, base: Backup, ip: str, profile: Profile,
                         agent_key: str, connect: Connect, sleep: Callable[[float], None],
                         wait_seconds: float, log: _Log,
                         error: str = "verify_failed") -> PushResult:
    """After an undo, check (from a fresh read) that the config is what it was before."""
    deadline_tries = 6
    for attempt in range(deadline_tries):
        try:
            if session is not None:
                after = read_backup(session, agent_key)
            else:
                with connect(ip, profile) as fresh:
                    after = read_backup(fresh, agent_key)
        except SessionError:
            session = None
            log.add(f"Device not reachable yet (attempt {attempt + 1}); waiting for its own "
                    "revert timer.")
            sleep(wait_seconds / deadline_tries)
            continue
        if after.hash == base.hash:
            log.add("Configuration is back to what it was before the change.")
            return PushResult("rolled_back", error, base.hash, after.hash, log)
        log.add("Configuration is NOT back to its earlier state: check the device by hand.")
        return PushResult("failed", "rollback_mismatch", base.hash, after.hash, log)
    log.add("Device is still unreachable after the revert time: check it by hand.")
    return PushResult("failed", "unreachable_after_rollback", base.hash, None, log)


def _push_cisco(session: Session, lines: list[str], before: Backup, ip: str, profile: Profile,
                agent_key: str, options: PushOptions, connect: Connect,
                ping_fn: Callable[[str], bool], report: Callable[[str], None],
                sleep: Callable[[float], None], log: _Log) -> PushResult:
    base = before
    archive_block, change = _split_archive_block(lines)
    if not _has_archive(before.raw):
        if not archive_block:
            log.add("`archive` is not configured, so automatic rollback is impossible. Nothing "
                    "was pushed. Apply the baseline template (it adds `archive`) first.")
            return PushResult("failed", "archive_missing", before.hash, log=log)
        out = session.configure(archive_block)
        log.add("Applied the archive block (needed for automatic rollback).", out)
        if _IOS_ERROR.search(out):
            return PushResult("failed", "command_error", before.hash, log=log)
        base = read_backup(session, agent_key)
    if not change:
        log.add("Nothing else to push.")
        return _finish_cisco(session, base, before, agent_key, options, log)
    mode = f"configure terminal revert timer {options.revert_minutes}"
    out = session.configure(change, mode_command=mode)
    log.add(f"Pushed {len(change)} lines with `{mode}`.", out)
    report("verifying")
    if _IOS_ERROR.search(out):
        ok, why = False, "the device rejected a command"
    else:
        ok, why = verify_reachable(ip, profile, connect, ping_fn)
    log.add(f"Verify: {why}.")
    wait = options.revert_minutes * options.seconds_per_minute + 30
    if ok:
        out = session.run("configure confirm")
        # Any "%" message means there was nothing left to confirm.
        if not re.search(r"^\s*%", out, re.MULTILINE):
            log.add("Sent `configure confirm`: the change is kept.")
            return _finish_cisco(session, base, before, agent_key, options, log)
        # The timer already ran out (verification took too long): the device has undone it.
        log.add("`configure confirm` was refused: the revert timer had already expired.", out)
        return _confirm_rolled_back(session, base, ip, profile, agent_key, connect, sleep,
                                    wait, log, error="revert_timer_expired")
    alive: Session | None = session
    try:
        out = session.run("configure revert now", prompt_may_change=True)
        log.add("Sent `configure revert now`.", out)
    except (SessionError, OSError, EOFError):
        alive = None
        log.add("Our session was cut off; the device's revert timer will undo the change.")
    return _confirm_rolled_back(alive, base, ip, profile, agent_key, connect, sleep, wait, log)


def _finish_cisco(session: Session, base: Backup, before: Backup, agent_key: str,
                  options: PushOptions, log: _Log) -> PushResult:
    if options.save_config:
        out = session.run("write memory")
        log.add("Saved the configuration (`write memory`).", out)
    after = read_backup(session, agent_key)
    return PushResult("done", None, before.hash, after.hash, log, after_backup=after)


def _push_routeros(session: Session, lines: list[str], before: Backup, ip: str,
                   profile: Profile, agent_key: str, connect: Connect,
                   ping_fn: Callable[[str], bool], report: Callable[[str], None],
                   sleep: Callable[[float], None], options: PushOptions,
                   log: _Log) -> PushResult:
    # Ctrl+X turns safe mode on: if this session is lost, RouterOS undoes everything we did.
    session.write_raw("\x18", expect="<SAFE>")
    log.add("Entered safe mode (Ctrl+X).")
    out = session.configure(lines)
    log.add(f"Pushed {len(lines)} lines.", out)
    report("verifying")
    if _ROS_ERROR.search(out):
        ok, why = False, "the device rejected a command"
    else:
        ok, why = verify_reachable(ip, profile, connect, ping_fn)
    log.add(f"Verify: {why}.")
    if ok:
        session.write_raw("\x18", expect="] >")
        log.add("Left safe mode (Ctrl+X): the change is kept.")
        after = read_backup(session, agent_key)
        return PushResult("done", None, before.hash, after.hash, log, after_backup=after)
    try:
        # Ctrl+D while in safe mode quits and undoes every change made in safe mode.
        session.write_raw("\x04", expect="")
        log.add("Left safe mode with Ctrl+D: RouterOS undoes the change.")
    except (SessionError, OSError, EOFError):
        log.add("Our session was cut off; RouterOS safe mode undoes the change.")
    # The undo ends this session, so check from a fresh login.
    return _confirm_rolled_back(None, before, ip, profile, agent_key, connect, sleep,
                                options.seconds_per_minute, log)
