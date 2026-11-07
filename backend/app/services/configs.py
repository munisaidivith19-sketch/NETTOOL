"""Config backups from agents: versioning, retention, diff, compliance and "unconfigured".

The agent uploads masked text only when the config fingerprint changed. The backend masks it
again (defence in depth), stores it as the next version of that device, keeps the last 50,
re-checks compliance and raises alerts:
- config_changed:<device>  (info)    a new version that no NetMap change request explains
- compliance:<device>      (warning) score below 70, or 10+ points lower than last time
"""

from __future__ import annotations

import difflib
import re
from datetime import datetime

from bson import ObjectId
from pymongo.asynchronous.database import AsyncDatabase
from pymongo.errors import DuplicateKeyError

from app.config_mgmt.masking import mask_config
from app.services import compliance
from app.services.alerts import upsert_alert

KEEP_VERSIONS = 50
COMPLIANCE_ALERT_BELOW = 70
COMPLIANCE_DROP_ALERT = 10
MAX_DIFF_ROWS = 4000
DEFAULT_HOSTNAMES = {"switch", "router", "mikrotik", "ap", ""}


def _label(device: dict) -> str:
    name = device.get("sys_name")
    return f"{name} ({device['mgmt_ip']})" if name else device["mgmt_ip"]


_SVI = re.compile(r"^(Vlan|Vl|Loopback|Lo|Null|NVI)\d", re.IGNORECASE)


def _routed_in_config(config: str) -> bool:
    """An IPv4 address on a physical/routed port (not a VLAN interface): the device routes."""
    interface = None
    for line in config.splitlines():
        if line.startswith("interface "):
            interface = line.split(maxsplit=1)[1]
        elif not line.startswith(" "):
            interface = None
        elif (interface and not _SVI.match(interface)
              and re.match(r"^ ip address \d+\.\d+\.\d+\.\d+ ", line)):
            return True
    return False


def unconfigured_reasons(device: dict, interfaces: list[dict], config: str | None,
                         seen: dict | None = None) -> list[str]:
    """Signs that a device is still at factory defaults (works from SNMP data alone, too).

    `seen` holds what discovery observed: "vlans" (from MAC tables) and "routed" (an address
    on a non-VLAN interface). Routers are not expected to have VLANs or a default gateway.
    """
    seen = seen or {}
    reasons = []
    hostname = (device.get("sys_name") or "").strip()
    if config:
        match = re.search(r"^hostname (\S+)|^/system identity\s*\n?set name=(\S+)", config,
                          re.MULTILINE)
        if match:
            hostname = match.group(1) or match.group(2)
    if hostname.lower() in DEFAULT_HOSTNAMES:
        reasons.append(f"Default host name ({hostname or 'none'})")
    routed = bool(seen.get("routed")) or (config is not None and _routed_in_config(config))
    vlan_ifs = [i for i in interfaces
                if re.match(r"^(Vlan|Vl)(\d+)$", i.get("descr") or i.get("name") or "")]
    vlan_numbers = {int(re.sub(r"\D", "", i.get("descr") or i.get("name"))) for i in vlan_ifs}
    vlan_numbers |= set(seen.get("vlans") or ())
    config_vlans = set(map(int, re.findall(r"^vlan (\d+)$", config or "", re.MULTILINE)))
    config_vlans |= set(map(int, re.findall(r"vlan-id=(\d+)", config or "")))
    if not routed and not (vlan_numbers | config_vlans) - {1}:
        reasons.append("No VLANs configured besides VLAN 1")
    if config is not None:
        static_ip = re.search(r"^ ip address \d+\.\d+\.\d+\.\d+ \d+\.", config, re.MULTILINE) or \
            re.search(r"^/ip address add address=", config, re.MULTILINE)
        gateway = re.search(r"^ip default-gateway |^ip route 0\.0\.0\.0 0\.0\.0\.0 |"
                            r"dst-address=0\.0\.0\.0/0", config, re.MULTILINE)
        if not static_ip:
            reasons.append("No static management IP address (DHCP or none)")
        elif (not gateway and not routed and not config.startswith("/")
              and "ip routing" not in config):
            reasons.append("No default gateway")
    return reasons


def is_unconfigured(reasons: list[str]) -> bool:
    return any(r.startswith("Default host name") for r in reasons) or len(reasons) >= 2


async def refresh_unconfigured(db: AsyncDatabase, agent_id: str, now: datetime) -> int:
    """For this agent's devices that have no config backup yet: SNMP-only detection."""
    flagged = 0
    async for device in db.devices.find(
            {"agent_id": agent_id, "config_backup.version": {"$exists": False}},
            {"sys_name": 1}).limit(2000):
        reasons = unconfigured_reasons(device, await _interfaces(db, device["_id"]), None,
                                       await _seen(db, device["_id"]))
        flag = is_unconfigured(reasons)
        flagged += flag
        await db.devices.update_one({"_id": device["_id"]}, {"$set": {"unconfigured": {
            "flag": flag, "reasons": reasons, "checked_at": now}}})
    return flagged


async def latest_version(db: AsyncDatabase, device_id: ObjectId) -> dict | None:
    return await db.configs.find_one({"device_id": device_id}, sort=[("version", -1)])


async def _interfaces(db: AsyncDatabase, device_id: ObjectId) -> list[dict]:
    return [i async for i in db.interfaces.find(
        {"device_id": device_id},
        {"_id": 0, "if_index": 1, "name": 1, "descr": 1, "admin_status": 1,
         "oper_status": 1}).limit(2000)]


async def _seen(db: AsyncDatabase, device_id: ObjectId) -> dict:
    """What discovery saw: VLANs in the MAC table, and addresses on routed (non-VLAN) ports."""
    vlans = await db.mac_entries.distinct("vlan", {"device_id": device_id, "vlan": {"$gt": 1}})
    names = {i["if_index"]: i.get("descr") or i.get("name") or ""
             async for i in db.interfaces.find({"device_id": device_id},
                                               {"if_index": 1, "descr": 1, "name": 1})}
    routed = False
    async for addr in db.ip_addresses.find(
            {"device_id": device_id, "sources": "interface", "version": 4},
            {"if_index": 1}).limit(500):
        name = names.get(addr.get("if_index"), "")
        if name and not _SVI.match(name):
            routed = True
            break
    return {"vlans": [v for v in vlans if isinstance(v, int)], "routed": routed}


async def refresh_assessment(db: AsyncDatabase, device: dict, now: datetime,
                             facts: dict | None = None) -> dict:
    """Re-run compliance + unconfigured detection on the newest stored config."""
    latest = await latest_version(db, device["_id"])
    interfaces = await _interfaces(db, device["_id"])
    update: dict = {}
    if latest is not None:
        facts = facts if facts is not None else latest.get("facts", {})
        report = compliance.evaluate(latest["text"], latest["vendor"], facts, interfaces)
        previous = (device.get("compliance") or {}).get("score")
        update["compliance"] = report.as_dict() | {"checked_at": now,
                                                   "version": latest["version"],
                                                   "previous_score": previous}
        await _compliance_alert(db, device, report.score, previous, now)
    reasons = unconfigured_reasons(device, interfaces, latest["text"] if latest else None,
                                   await _seen(db, device["_id"]))
    update["unconfigured"] = {"flag": is_unconfigured(reasons), "reasons": reasons,
                              "checked_at": now}
    await db.devices.update_one({"_id": device["_id"]}, {"$set": update})
    return update


async def _compliance_alert(db: AsyncDatabase, device: dict, score: int, previous: int | None,
                            now: datetime) -> None:
    key = f"compliance:{device['_id']}"
    dropped = previous is not None and previous - score >= COMPLIANCE_DROP_ALERT
    if score < COMPLIANCE_ALERT_BELOW or dropped:
        reason = (f"dropped from {previous} to {score}" if dropped
                  else f"is {score} (below {COMPLIANCE_ALERT_BELOW})")
        await upsert_alert(
            db, key=key, type_="compliance", severity="warning",
            message=f"Compliance score of {_label(device)} {reason}.",
            target={"type": "device", "id": str(device["_id"]), "mgmt_ip": device["mgmt_ip"]},
            details={"score": score, "previous_score": previous}, now=now)
    else:
        await db.alerts.update_one(
            {"key": key, "status": "open"},
            {"$set": {"status": "resolved", "resolved_at": now, "resolved_by": None}})


async def ingest_upload(db: AsyncDatabase, device: dict, upload, now: datetime) -> dict:
    """Store one agent upload (see models/configs.py ConfigUpload). Returns a small summary."""
    device_id = device["_id"]
    base = {"config_backup.checked_at": now, "config_backup.source": upload.source}
    if upload.error:
        await db.devices.update_one({"_id": device_id}, {
            "$set": base | {"config_backup.status": "failed", "config_backup.error": upload.error},
            "$unset": {"backup_requested_at": ""}})
        return {"stored": False, "error": upload.error}

    latest = await latest_version(db, device_id)
    stored = False
    version = latest["version"] if latest else 0
    if upload.text is not None and (latest is None or latest["hash"] != upload.hash):
        text = mask_config(upload.text, upload.vendor)  # again, in case the agent missed one
        doc = {"device_id": device_id, "taken_at": now, "hash": upload.hash, "text": text,
               "vendor": upload.vendor, "facts": upload.facts.model_dump(),
               "size": len(text.encode()), "lines": text.count("\n"),
               "source": upload.source, "agent_id": device.get("agent_id"),
               "change_id": ObjectId(upload.change_id) if upload.change_id else None}
        for _ in range(3):  # two uploads at once: the unique index picks one, retry the other
            version += 1
            try:
                await db.configs.insert_one(doc | {"version": version})
                stored = True
                break
            except DuplicateKeyError:
                latest = await latest_version(db, device_id)
                version = latest["version"] if latest else 0
        await db.configs.delete_many({"device_id": device_id,
                                      "version": {"$lte": version - KEEP_VERSIONS}})
        if stored and latest is not None and upload.source != "post_change":
            await upsert_alert(
                db, key=f"config_changed:{device_id}", type_="config_changed", severity="info",
                message=f"Configuration of {_label(device)} changed outside NetMap "
                        f"(version {version}). Review the diff.",
                target={"type": "device", "id": str(device_id), "mgmt_ip": device["mgmt_ip"]},
                details={"version": version, "previous_version": version - 1}, now=now)
    await db.devices.update_one({"_id": device_id}, {
        "$set": base | {"config_backup.status": "ok", "config_backup.error": None,
                        "config_backup.hash": upload.hash, "config_backup.version": version,
                        "config_vendor": upload.vendor}
        | ({"config_backup.changed_at": now} if stored else {}),
        "$unset": {"backup_requested_at": ""}})
    device = await db.devices.find_one({"_id": device_id})
    assessment = await refresh_assessment(db, device, now, upload.facts.model_dump())
    return {"stored": stored, "version": version,
            "score": (assessment.get("compliance") or {}).get("score")}


def diff_rows(old: str, new: str, context: int = 3) -> list[dict]:
    """Side-by-side rows. Long runs of unchanged lines collapse into one "skip" row."""
    a, b = old.splitlines(), new.splitlines()
    rows: list[dict] = []
    matcher = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            run = list(zip(range(i1, i2), range(j1, j2), strict=True))
            if len(run) > 2 * context + 1:
                keep_head = run[:context] if rows else []
                keep_tail = run[-context:] if i2 < len(a) or j2 < len(b) else []
                for i, j in keep_head:
                    rows.append({"kind": "same", "left_no": i + 1, "left": a[i],
                                 "right_no": j + 1, "right": b[j]})
                rows.append({"kind": "skip", "count": len(run) - len(keep_head) - len(keep_tail)})
                run = keep_tail
            for i, j in run:
                rows.append({"kind": "same", "left_no": i + 1, "left": a[i],
                             "right_no": j + 1, "right": b[j]})
        else:
            left, right = list(range(i1, i2)), list(range(j1, j2))
            for n in range(max(len(left), len(right))):
                i = left[n] if n < len(left) else None
                j = right[n] if n < len(right) else None
                kind = "changed" if i is not None and j is not None else \
                    "removed" if i is not None else "added"
                rows.append({"kind": kind,
                             "left_no": i + 1 if i is not None else None,
                             "left": a[i] if i is not None else None,
                             "right_no": j + 1 if j is not None else None,
                             "right": b[j] if j is not None else None})
        if len(rows) > MAX_DIFF_ROWS:
            rows = rows[:MAX_DIFF_ROWS] + [{"kind": "truncated"}]
            break
    return rows
