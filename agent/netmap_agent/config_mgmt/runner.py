"""Runs config backups and approved change jobs for the scheduler in main.py.

SSH work happens in worker threads (Netmiko is blocking); every upload to the backend
happens back on the calling thread, one at a time.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from functools import partial

from netmap_agent.config import AgentSettings
from netmap_agent.config_mgmt.backup import read_backup, upload_payload
from netmap_agent.config_mgmt.connection import SessionError, open_session
from netmap_agent.config_mgmt.push import Connect, PushOptions, PushResult, push_job
from netmap_agent.credential_store import CredentialError, CredentialStore, Profile
from netmap_agent.discovery import ping
from netmap_agent.uploader import Uploader, UploadError

logger = logging.getLogger("netmap_agent.config")

MAX_JOBS_PER_POLL = 5


def default_ping(settings: AgentSettings) -> Callable[[str], bool]:
    def ping_fn(target: str) -> bool:
        try:
            ipaddress.ip_address(target)
        except ValueError:
            return True  # a host name (simulation): the SSH login check still runs
        return ping.ping_one(ping.ping_binary(), target, settings.ping_timeout_ms)

    return ping_fn


class ConfigManager:
    def __init__(self, settings: AgentSettings, uploader: Uploader, *,
                 store: CredentialStore | None = None, connect: Connect = open_session,
                 ping_fn: Callable[[str], bool] | None = None) -> None:
        self.settings = settings
        self.uploader = uploader
        self.store = store or CredentialStore(settings.credential_store_path,
                                              settings.credential_store_key.get_secret_value())
        if connect is open_session and settings.ssh_known_hosts_file:
            connect = partial(open_session, known_hosts=settings.ssh_known_hosts_file)
        self.connect = connect
        self.ping_fn = ping_fn or default_ping(settings)

    @property
    def _key(self) -> str:
        return self.settings.agent_key.get_secret_value()

    def _profiles(self) -> list[Profile]:
        try:
            return self.store.load()
        except CredentialError as exc:
            logger.error("Credential store unavailable: %s", exc)
            return []

    def _backup_one(self, target: dict, profile: Profile | None, source: str) -> dict:
        device_id = target["device_id"]
        if profile is None:
            return upload_payload(device_id, None, None, source, error="no_credentials")
        try:
            with self.connect(target["mgmt_ip"], profile) as session:
                backup = read_backup(session, self._key)
        except SessionError as exc:
            # Log the device and the short code only: never the profile or command output.
            logger.warning("Backup of %s failed: %s", target["mgmt_ip"], exc.code)
            return upload_payload(device_id, None, None, source, error=exc.code)
        return upload_payload(device_id, backup, target.get("last_hash"), source)

    def backup(self, only_requested: bool = False) -> dict[str, int]:
        """Back up every known device (or only those an engineer asked for in the UI)."""
        targets = [t for t in self.uploader.backup_targets()
                   if not only_requested or t.get("requested")]
        if not targets:
            return {"devices": 0}
        profiles = self._profiles()
        jobs = [(t, self.store.for_ip(t["mgmt_ip"], profiles),
                 "manual" if t.get("requested") else "scheduled") for t in targets]
        with ThreadPoolExecutor(max_workers=self.settings.ssh_max_parallel) as pool:
            payloads = list(pool.map(lambda job: self._backup_one(*job), jobs))
        counts = {"devices": len(payloads), "changed": 0, "unchanged": 0, "failed": 0}
        for payload in payloads:
            counts["failed" if "error" in payload else
                   "changed" if "text" in payload else "unchanged"] += 1
            try:
                self.uploader.send_config(payload)
            except UploadError as exc:
                logger.error("Config upload failed: %s", exc)
        logger.info("Config backups: %s", counts)
        return counts

    def run_jobs(self) -> int:
        """Claim and push approved changes, one at a time."""
        done = 0
        for _ in range(MAX_JOBS_PER_POLL):
            job = self.uploader.claim_job()
            if not job:
                break
            self.run_job(job)
            done += 1
        return done

    def run_job(self, job: dict) -> PushResult:
        change_id = job.get("change_id", "")
        profile = self.store.for_ip(job.get("mgmt_ip", ""), self._profiles())
        options = PushOptions(revert_minutes=self.settings.change_revert_minutes,
                              save_config=self.settings.change_save_config,
                              seconds_per_minute=self.settings.change_revert_seconds_per_minute)

        def report(status: str) -> None:
            try:
                self.uploader.job_status(change_id, {"status": status})
            except UploadError as exc:
                logger.warning("Could not report %s for change %s: %s", status, change_id, exc)

        result = push_job(job, profile, self._key, options, connect=self.connect,
                          ping_fn=self.ping_fn, report=report)
        logger.info("Change %s finished: %s%s", change_id, result.status,
                    f" ({result.error})" if result.error else "")
        self.uploader.job_status(change_id, result.as_payload())
        if result.after_backup is not None:
            self.uploader.send_config(upload_payload(
                job["device_id"], result.after_backup, job.get("before_hash"), "post_change",
                change_id=change_id))
        return result
