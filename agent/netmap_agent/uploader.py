"""Signed HTTPS requests from the agent to the backend (CLAUDE.md 7.3).

Each request carries X-Agent-Id, X-Timestamp, X-Nonce and X-Signature, where
  X-Signature = hex(HMAC-SHA256(agent_key, METHOD \n PATH[?QUERY] \n TIMESTAMP \n NONCE \n
                                hex(SHA-256(BODY))))
The key itself is never sent. The backend checks the same string (backend/app/security/
agent_auth.py) and rejects old timestamps and reused nonces, so a captured request can't be
replayed.
"""

import hashlib
import hmac
import json
import logging
import secrets
import time
from collections.abc import Callable
from urllib.parse import urlsplit

import httpx

from netmap_agent.config import LOCAL_HOSTS, AgentSettings

logger = logging.getLogger("netmap_agent.uploader")

RETRY_STATUSES = {429, 500, 502, 503, 504}
MAX_ATTEMPTS = 8  # 1+2+4+8+16+32+60 s ≈ 2 minutes: enough for a Render free-tier cold start
MAX_BACKOFF_SECONDS = 60
_jitter = secrets.SystemRandom()


class UploadError(Exception):
    pass


def canonical_request(method: str, path_qs: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    body_hash = hashlib.sha256(body).hexdigest()
    return "\n".join([method.upper(), path_qs, timestamp, nonce, body_hash]).encode()


def sign_headers(agent_id: str, key: str, method: str, path_qs: str, body: bytes) -> dict:
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(18)
    signature = hmac.new(key.encode(), canonical_request(method, path_qs, timestamp, nonce, body),
                         hashlib.sha256).hexdigest()
    return {
        "X-Agent-Id": agent_id,
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-Signature": signature,
    }


class Uploader:
    def __init__(
        self,
        settings: AgentSettings,
        *,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        url = urlsplit(settings.api_url)
        # Checked again here (not only in settings) because this is where data leaves the host.
        if url.scheme != "https" and not (
            url.scheme == "http" and settings.allow_insecure_local and url.hostname in LOCAL_HOSTS
        ):
            raise UploadError("Refusing to send data over plain HTTP")
        if not settings.agent_id or not settings.agent_key.get_secret_value():
            raise UploadError("AGENT_ID and AGENT_KEY must be set")
        self.settings = settings
        self.sleep = sleep
        # verify=True is the default and is never turned off: the server's TLS certificate
        # proves we are talking to the real backend.
        self.client = httpx.Client(base_url=settings.api_url, timeout=30, transport=transport,
                                   headers={"User-Agent": "netmap-agent"})

    def close(self) -> None:
        self.client.close()

    def request(self, method: str, path: str, payload: dict | None = None) -> dict:
        body = b"" if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        for attempt in range(1, MAX_ATTEMPTS + 1):
            # Fresh timestamp and nonce on every attempt: a retry is a new request to the server.
            headers = sign_headers(self.settings.agent_id,
                                   self.settings.agent_key.get_secret_value(), method, path, body)
            if body:
                headers["Content-Type"] = "application/json"
            try:
                response = self.client.request(method, path, content=body, headers=headers)
            except httpx.TransportError as exc:
                error = f"{type(exc).__name__}"
            else:
                if response.status_code < 400:
                    return response.json() if response.content else {}
                if response.status_code not in RETRY_STATUSES:
                    # 401/403/413/422 won't fix themselves; retrying would only add noise.
                    raise UploadError(f"{method} {path} failed with HTTP {response.status_code}")
                error = f"HTTP {response.status_code}"
            if attempt == MAX_ATTEMPTS:
                raise UploadError(f"{method} {path} failed after {attempt} attempts ({error})")
            delay = min(MAX_BACKOFF_SECONDS, 2 ** (attempt - 1)) + _jitter.uniform(0, 1)
            logger.warning("%s %s: %s, retrying in %.1fs", method, path, error, delay)
            self.sleep(delay)
        raise UploadError("unreachable")  # pragma: no cover

    def known_devices(self) -> list[dict]:
        return self.request("GET", "/api/agent/known-devices").get("devices", [])

    def send_report(self, report: dict) -> dict:
        return self.request("POST", "/api/agent/report", report)

    def backup_targets(self) -> list[dict]:
        return self.request("GET", "/api/agent/backup-targets").get("devices", [])

    def send_config(self, payload: dict) -> dict:
        return self.request("POST", "/api/agent/configs", payload)

    def claim_job(self) -> dict | None:
        return self.request("POST", "/api/agent/jobs/claim", {}).get("job")

    def job_status(self, change_id: str, payload: dict) -> dict:
        return self.request("POST", f"/api/agent/jobs/{change_id}/status", payload)

    def ai_training_data(self) -> dict:
        return self.request("GET", "/api/agent/ai/training-data")

    def send_predictions(self, payload: dict) -> dict:
        return self.request("POST", "/api/agent/ai/predictions", payload)

    def send_anomalies(self, payload: dict) -> dict:
        return self.request("POST", "/api/agent/ai/anomalies", payload)

    def send_classifications(self, payload: dict) -> dict:
        return self.request("POST", "/api/agent/ai/classifications", payload)
