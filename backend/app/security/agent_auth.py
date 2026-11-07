"""Agent API keys and HMAC request signing (CLAUDE.md 7.3).

Key storage: the server must know each agent's key to check its HMAC signatures, so the key
can't be stored as a one-way hash. It is stored **encrypted** with Fernet under
AGENT_KEY_ENCRYPTION_KEY, which lives only in the server environment. A copy of the database
alone is therefore not enough to impersonate an agent. A short SHA-256 fingerprint is kept so
admins can tell keys apart without ever seeing them again.

Signing: the key itself never travels over the network. For every request the agent sends
  X-Agent-Id, X-Timestamp (Unix seconds), X-Nonce (random, single use), X-Signature
where X-Signature = hex(HMAC-SHA256(key, canonical_request)) and canonical_request is
  METHOD \n PATH[?QUERY] \n TIMESTAMP \n NONCE \n hex(SHA-256(BODY))
The server rebuilds the same string, so any change to the method, path, body, time or nonce
breaks the signature. The timestamp window and the single-use nonce stop replays.
"""

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import timedelta

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from fastapi import HTTPException, Request, status
from pymongo.errors import DuplicateKeyError

from app.security.rbac import mark_access
from app.security.sessions import utcnow
from app.services import audit

MAX_CLOCK_SKEW = timedelta(minutes=5)
NONCE_TTL_SECONDS = 600  # longer than the full ±5 minute window, so a nonce can't be reused

AGENT_ID_RE = re.compile(r"^agt_[a-f0-9]{16}$")
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
SIGNATURE_RE = re.compile(r"^[a-f0-9]{64}$")
TIMESTAMP_RE = re.compile(r"^[0-9]{1,12}$")


def new_agent_id() -> str:
    return "agt_" + secrets.token_hex(8)


def new_agent_key() -> str:
    return secrets.token_urlsafe(32)  # 32 random bytes


def fingerprint(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()[:16]


class KeyVault:
    """Encrypts and decrypts agent keys. Several comma-separated Fernet keys allow rotation."""

    def __init__(self, keys_csv: str) -> None:
        keys = [k.strip() for k in keys_csv.split(",") if k.strip()]
        if not keys:
            raise ValueError("AGENT_KEY_ENCRYPTION_KEY is empty")
        try:
            self._fernet = MultiFernet([Fernet(k) for k in keys])
        except ValueError as exc:
            raise ValueError("AGENT_KEY_ENCRYPTION_KEY is not a valid Fernet key") from exc

    def encrypt(self, agent_key: str) -> str:
        return self._fernet.encrypt(agent_key.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        return self._fernet.decrypt(ciphertext.encode()).decode()


def canonical_request(method: str, path_qs: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    body_hash = hashlib.sha256(body).hexdigest()
    return "\n".join([method.upper(), path_qs, timestamp, nonce, body_hash]).encode()


def sign(key: str, message: bytes) -> str:
    return hmac.new(key.encode(), message, hashlib.sha256).hexdigest()


@dataclass
class CurrentAgent:
    id: str
    name: str


async def require_agent(request: Request) -> CurrentAgent:
    """Dependency for /api/agent/* routes. Session cookies are ignored here on purpose."""
    db = request.app.state.db
    headers = request.headers
    agent_id = headers.get("x-agent-id", "")
    timestamp = headers.get("x-timestamp", "")
    nonce = headers.get("x-nonce", "")
    signature = headers.get("x-signature", "").lower()

    async def reject(reason: str) -> HTTPException:
        # The reason goes to the audit log only. The client always gets the same answer, so
        # it learns nothing about which check failed.
        await audit.record(
            db,
            request,
            action="agent.auth",
            result="failure",
            actor={"type": "agent", "id": agent_id} if AGENT_ID_RE.match(agent_id) else None,
            details={"reason": reason, "path": request.url.path},
        )
        return HTTPException(status.HTTP_401_UNAUTHORIZED, "Agent authentication failed")

    if not (
        AGENT_ID_RE.match(agent_id)
        and TIMESTAMP_RE.match(timestamp)
        and NONCE_RE.match(nonce)
        and SIGNATURE_RE.match(signature)
    ):
        raise await reject("missing_or_malformed_headers")

    skew = abs(utcnow().timestamp() - int(timestamp))
    if skew > MAX_CLOCK_SKEW.total_seconds():
        raise await reject("timestamp_out_of_window")

    agent = await db.agents.find_one({"_id": agent_id})
    if agent is None or agent.get("revoked_at") is not None:
        raise await reject("unknown_or_revoked_agent")

    try:
        key = request.app.state.vault.decrypt(agent["key_ciphertext"])
    except InvalidToken:
        raise await reject("key_decrypt_failed") from None

    path_qs = request.url.path + (f"?{request.url.query}" if request.url.query else "")
    expected = sign(key, canonical_request(request.method, path_qs, timestamp, nonce,
                                           await request.body()))
    if not hmac.compare_digest(expected, signature):
        raise await reject("bad_signature")

    # Stored only after the signature is valid, so strangers can't fill the nonce table.
    try:
        await db.agent_nonces.insert_one(
            {"agent_id": agent_id, "nonce": nonce, "created_at": utcnow()}
        )
    except DuplicateKeyError:
        raise await reject("nonce_reused") from None

    request.state.agent = CurrentAgent(id=agent_id, name=agent["name"])
    return request.state.agent


mark_access(require_agent, "agent")
