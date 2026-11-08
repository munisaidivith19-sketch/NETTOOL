"""DEMO: show that a captured agent request can't be replayed or changed (CLAUDE.md 7.3).

It sends four heartbeats to /api/agent/heartbeat and prints the answer to each:
  1. a correctly signed request                          -> 200
  2. exactly the same bytes and headers again (a replay) -> 401  (audit reason: nonce_reused)
  3. a fresh signature, but the body changed afterwards  -> 401  (bad_signature)
  4. a correct signature with a 10-minute-old timestamp  -> 401  (timestamp_out_of_window)
Then open Admin > Audit log and filter on "agent.auth" to see why each one was refused. The
client only ever gets "Agent authentication failed", so it learns nothing from the answer.

Create an agent in Admin > Agents first, then from the backend folder (PowerShell):
    $env:NETMAP_AGENT_KEY = "<the key shown once>"
    python scripts/demo_agent_request.py --url http://127.0.0.1:8000 --agent-id agt_...
The key is read from the environment, not the command line, so it stays out of shell history.
"""

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
import time

import httpx

PATH = "/api/agent/heartbeat"


def signed(agent_id: str, key: str, body: bytes, timestamp: int) -> dict:
    """The same signature the agent makes (agent/netmap_agent/uploader.py)."""
    ts, nonce = str(timestamp), secrets.token_urlsafe(18)
    message = "\n".join(["POST", PATH, ts, nonce, hashlib.sha256(body).hexdigest()]).encode()
    return {"X-Agent-Id": agent_id, "X-Timestamp": ts, "X-Nonce": nonce,
            "X-Signature": hmac.new(key.encode(), message, hashlib.sha256).hexdigest(),
            "Content-Type": "application/json"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--agent-id", required=True)
    args = parser.parse_args()
    key = os.environ.get("NETMAP_AGENT_KEY", "")
    if not key:
        print("Set NETMAP_AGENT_KEY to the agent's key first.", file=sys.stderr)
        return 2

    body = json.dumps({"agent_version": "demo"}).encode()
    good = signed(args.agent_id, key, body, int(time.time()))
    steps = [
        ("1. signed request", body, good),
        ("2. replay of request 1", body, good),
        ("3. body changed after signing", json.dumps({"agent_version": "evil"}).encode(),
         signed(args.agent_id, key, body, int(time.time()))),
        ("4. timestamp 10 minutes old", body,
         signed(args.agent_id, key, body, int(time.time()) - 600)),
    ]
    with httpx.Client(base_url=args.url, timeout=10) as client:
        for label, content, headers in steps:
            response = client.post(PATH, content=content, headers=headers)
            print(f"{label:34} -> {response.status_code} {response.text}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
