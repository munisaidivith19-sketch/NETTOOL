"""Change requests: the safe auto-configuration flow from CLAUDE.md 7.5.

    draft -> pending_approval -> approved -> pushing -> verifying -> done
                     |               |                         \\-> rolled_back | failed
                     v               v
                 rejected      expired (not picked up within 24 h)
    (cancelled: by the creator or an admin, any time before the agent picks it up)

Safety rules enforced here, on the server:
- The commands are fixed when the change is submitted; editing sends it back to draft.
- The denylist runs on preview, on submit and again on approval (and the agent runs it once
  more before pushing).
- Commands may not contain secrets: they are stored unmasked, because the agent must push them
  exactly, and passwords must never be stored in the database (CLAUDE.md 7.6).
- Four-eyes: the approver must be someone else. An admin may override with a written reason,
  which is audit-logged.
- On approval the job is signed with the agent's key (app/config_mgmt/jobsign.py) and bound to
  the config version it was reviewed against.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from bson import ObjectId
from pymongo import ReturnDocument
from pymongo.asynchronous.database import AsyncDatabase

from app.config_mgmt.denylist import Violation, check_commands
from app.config_mgmt.jobsign import commands_sha256, sign_job
from app.config_mgmt.masking import mask_config
from app.services.alerts import upsert_alert
from app.services.configs import latest_version

JOB_LIFETIME = timedelta(hours=24)
# An agent that claimed a job and went silent: after this the change is marked failed.
CLAIM_TIMEOUT = timedelta(minutes=30)
EDITABLE = ("draft", "rejected")
CANCELLABLE = ("draft", "pending_approval", "approved", "rejected")
FINAL = ("done", "rolled_back", "failed", "rejected", "cancelled", "expired")


class ChangeError(Exception):
    def __init__(self, status_code: int, message: str, violations: list | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.violations = violations or []


def secret_lines(commands: str, vendor: str) -> list[Violation]:
    """Lines that would put a password or key into the database. `no ...` removals are fine."""
    found = []
    for number, line in enumerate(commands.splitlines(), start=1):
        if line.strip().startswith("no "):
            continue
        if mask_config(line, vendor) != line:
            found.append(Violation(number, mask_config(line, vendor),
                                   "Contains a password, secret, community or key. Secrets "
                                   "can't be stored in a change request; set them on the "
                                   "device directly."))
    return found


async def protected_interfaces(db: AsyncDatabase, device: dict) -> list[str]:
    """The management interface and every port with an LLDP/CDP neighbour (uplinks)."""
    if_indexes: set[int] = set()
    async for address in db.ip_addresses.find({"device_id": device["_id"], "ip": device["mgmt_ip"]},
                                              {"if_index": 1}):
        if address.get("if_index") is not None:
            if_indexes.add(address["if_index"])
    async for link in db.links.find({"device_id": device["_id"]}, {"if_index": 1}).limit(500):
        if_indexes.add(link["if_index"])
    names: list[str] = []
    async for iface in db.interfaces.find({"device_id": device["_id"],
                                           "if_index": {"$in": sorted(if_indexes)}},
                                          {"name": 1, "descr": 1}):
        names += [n for n in (iface.get("descr"), iface.get("name")) if n]
    return sorted(set(names))


async def check(db: AsyncDatabase, device: dict, vendor: str, commands: str) -> dict:
    protected = await protected_interfaces(db, device)
    violations = [*secret_lines(commands, vendor), *check_commands(commands, vendor, protected)]
    return {"violations": [v.as_dict() for v in violations], "protected_interfaces": protected}


def timeline_entry(status: str, now: datetime, by: dict | None = None,
                   note: str | None = None) -> dict:
    return {"at": now, "status": status, "by": by, "note": note}


async def transition(db: AsyncDatabase, change_id: ObjectId, expected: tuple[str, ...],
                     new_status: str, now: datetime, by: dict | None = None,
                     note: str | None = None, extra: dict | None = None,
                     match: dict | None = None) -> dict | None:
    """Atomic state change: only succeeds if the change is still in an expected state."""
    return await db.change_requests.find_one_and_update(
        {"_id": change_id, "status": {"$in": list(expected)}, **(match or {})},
        {"$set": {"status": new_status, "updated_at": now, **(extra or {})},
         "$push": {"timeline": timeline_entry(new_status, now, by, note)}},
        return_document=ReturnDocument.AFTER,
    )


async def build_job(db: AsyncDatabase, vault, change: dict, device: dict,
                    protected: list[str], now: datetime) -> dict:
    agent = await db.agents.find_one({"_id": device.get("agent_id")})
    if agent is None or agent.get("revoked_at") is not None:
        raise ChangeError(409, "The agent that manages this device is missing or revoked.")
    job = {
        "change_id": str(change["_id"]), "device_id": str(device["_id"]),
        "mgmt_ip": device["mgmt_ip"], "vendor": change["vendor"],
        "commands": change["commands"], "commands_sha256": commands_sha256(change["commands"]),
        "before_hash": change["before_hash"], "protected_interfaces": protected,
        "expires_at": (now + JOB_LIFETIME).isoformat(),
    }
    job["signature"] = sign_job(vault.decrypt(agent["key_ciphertext"]), job)
    return job


async def ensure_current_backup(db: AsyncDatabase, change: dict) -> None:
    latest = await latest_version(db, change["device_id"])
    if latest is None or latest["hash"] != change["before_hash"]:
        raise ChangeError(409, "The device configuration changed since this change was "
                               "submitted. Review the new config, then submit it again.")


async def expire_and_time_out(db: AsyncDatabase, agent_id: str, now: datetime) -> None:
    async for change in db.change_requests.find(
            {"agent_id": agent_id, "status": "approved", "expires_at": {"$lt": now}},
            {"_id": 1}).limit(100):
        await transition(db, change["_id"], ("approved",), "expired", now,
                         note="Not picked up by the agent within 24 hours.")
    async for change in db.change_requests.find(
            {"agent_id": agent_id, "status": {"$in": ["pushing", "verifying"]},
             "claimed_at": {"$lt": now - CLAIM_TIMEOUT}}).limit(100):
        updated = await transition(
            db, change["_id"], ("pushing", "verifying"), "failed", now,
            note="The agent stopped reporting. Check the device by hand.",
            extra={"result": {"status": "failed", "error": "agent_timeout"},
                   "finished_at": now})
        if updated:
            await change_failed_alert(db, updated, now)


async def change_failed_alert(db: AsyncDatabase, change: dict, now: datetime) -> None:
    result = change.get("result") or {}
    status = change["status"]
    what = "was rolled back" if status == "rolled_back" else "FAILED"
    await upsert_alert(
        db, key=f"change_failed:{change['_id']}", type_="change_failed", severity="critical",
        message=f"Change \"{change['title']}\" on {change.get('device_name') or change['mgmt_ip']} "
                f"{what} ({result.get('error') or 'unknown error'}).",
        target={"type": "change", "id": str(change["_id"]), "device_id": str(change["device_id"]),
                "mgmt_ip": change["mgmt_ip"]},
        details={"status": status, "error": result.get("error")}, now=now)
