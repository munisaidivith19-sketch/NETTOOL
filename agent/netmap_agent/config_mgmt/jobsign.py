"""Signatures on approved change jobs.

SHARED FILE: identical copies live in agent/netmap_agent/config_mgmt/ and
backend/app/config_mgmt/ (a test checks).

When a change is approved, the backend signs the job with the agent's own key (the same key
that signs agent requests). The agent only pushes a job whose signature checks out. Someone
who can write to the database, but doesn't have the server's AGENT_KEY_ENCRYPTION_KEY, can
therefore not slip in a job or edit the commands of an approved one: they can't compute the
signature.
"""

import hashlib
import hmac
import json

SIGNED_FIELDS = (
    "change_id", "device_id", "mgmt_ip", "vendor", "commands", "commands_sha256",
    "before_hash", "protected_interfaces", "expires_at",
)


def commands_sha256(commands: str) -> str:
    return hashlib.sha256(commands.encode()).hexdigest()


def signing_bytes(job: dict) -> bytes:
    body = {name: job.get(name) for name in SIGNED_FIELDS}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sign_job(agent_key: str, job: dict) -> str:
    return hmac.new(agent_key.encode(), b"netmap-job-v1\n" + signing_bytes(job),
                    hashlib.sha256).hexdigest()


def verify_job(agent_key: str, job: dict) -> bool:
    signature = job.get("signature")
    if not isinstance(signature, str):
        return False
    return hmac.compare_digest(sign_job(agent_key, job), signature)
