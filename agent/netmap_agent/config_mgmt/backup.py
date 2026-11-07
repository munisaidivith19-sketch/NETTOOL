"""Configuration backups: read the running config, fingerprint it, mask it.

The fingerprint is HMAC-SHA256(agent key, config) over the *raw* config, so a change that
only touches a password still produces a new version. A plain SHA-256 would let anyone who
reads the database test password guesses against the hash offline; with the HMAC they would
also need the agent key, which never leaves the agent and the server's encrypted store.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field

from netmap_agent.config_mgmt.connection import Session, SessionError
from netmap_agent.config_mgmt.facts import config_facts
from netmap_agent.config_mgmt.masking import mask_config

MAX_CONFIG_BYTES = 1_000_000

# Lines that change on their own (timestamps, counters) and would create a new "version"
# every time even though nothing was configured.
_VOLATILE = {
    "cisco_ios": re.compile(
        r"^(Building configuration|Current configuration\s*:|! Last configuration change"
        r"|! NVRAM config last updated|! No configuration change since|ntp clock-period)",
        re.IGNORECASE,
    ),
    "mikrotik_routeros": re.compile(r"^#\s.*\bby RouterOS\b", re.IGNORECASE),
}


def normalize(text: str, vendor: str) -> str:
    volatile = _VOLATILE.get(vendor)
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    kept = [line for line in lines if not (volatile and volatile.match(line))]
    while kept and not kept[0].strip():
        kept.pop(0)
    while kept and not kept[-1].strip():
        kept.pop()
    return "\n".join(kept) + "\n"


def config_hash(agent_key: str, normalized: str) -> str:
    return hmac.new(agent_key.encode(), normalized.encode(), hashlib.sha256).hexdigest()


@dataclass
class Backup:
    vendor: str
    hash: str
    masked: str
    facts: dict[str, bool]
    raw: str = field(repr=False)  # stays in memory on the agent, never uploaded


def read_backup(session: Session, agent_key: str) -> Backup:
    text = session.running_config()
    if len(text.encode()) > MAX_CONFIG_BYTES:
        raise SessionError("too_large", "Configuration is larger than 1 MB")
    normalized = normalize(text, session.vendor)
    if len(normalized.strip()) < 10:
        raise SessionError("empty_config", "Device returned an empty configuration")
    return Backup(vendor=session.vendor, hash=config_hash(agent_key, normalized),
                  masked=mask_config(normalized, session.vendor),
                  facts=config_facts(normalized, session.vendor), raw=normalized)


def upload_payload(device_id: str, backup: Backup | None, last_hash: str | None, source: str,
                   *, error: str | None = None, change_id: str | None = None) -> dict:
    """What goes to the backend: masked text only when the fingerprint changed."""
    payload: dict = {"device_id": device_id, "source": source}
    if change_id:
        payload["change_id"] = change_id
    if error or backup is None:
        payload["error"] = error or "unknown"
        return payload
    payload |= {"vendor": backup.vendor, "hash": backup.hash, "facts": backup.facts}
    if backup.hash != last_hash:
        payload["text"] = backup.masked
    return payload
