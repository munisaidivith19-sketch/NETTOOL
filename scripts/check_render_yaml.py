"""Pre-deployment check of render.yaml (Phase 9 checklist).

render.yaml is committed to a public repository, so it must never hold a secret value:
- Every variable whose name says it is secret (URI, KEY, PASSWORD, TOKEN, SECRET, USERNAME,
  CHAT_ID) must be `sync: false` with no value, so Render asks for it in the dashboard.
- `generateValue` is refused for the Fernet keys: Render's random value is not a valid
  Fernet key.
- ENV must be production, the service must stay on the free plan, and the uvicorn command
  must not trust the client's X-Forwarded-For.

From the project root:   python scripts/check_render_yaml.py   (exit code 0 = OK)
"""

import re
from pathlib import Path

import yaml

SECRET_NAME = re.compile(r"URI|KEY|PASSWORD|TOKEN|SECRET|USERNAME|CHAT_ID")
FERNET_KEYS = {"AGENT_KEY_ENCRYPTION_KEY", "MFA_ENCRYPTION_KEY"}


def problems(doc: dict) -> list[str]:
    found = []
    for service in doc.get("services", []):
        name = service.get("name", "?")
        env = {e["key"]: e for e in service.get("envVars", [])}
        if env.get("ENV", {}).get("value") != "production":
            found.append(f"{name}: ENV must be production")
        if service.get("plan") != "free":
            found.append(f"{name}: plan is not free (CLAUDE.md: free resources only)")
        start = service.get("startCommand", "")
        if "--no-proxy-headers" not in start or "forwarded-allow-ips" in start:
            found.append(f"{name}: startCommand must use --no-proxy-headers "
                         "(the app picks the client IP, see security/client_ip.py)")
        for key, entry in env.items():
            if SECRET_NAME.search(key) and key != "TRUSTED_PROXY_HOPS":
                if "value" in entry or entry.get("sync") is not False:
                    found.append(f"{name}: {key} looks secret; use `sync: false` and no value")
            if key in FERNET_KEYS and entry.get("generateValue"):
                found.append(f"{name}: {key} can't use generateValue (not a Fernet key)")
    return found


def main() -> int:
    path = Path(__file__).resolve().parents[1] / "render.yaml"
    found = problems(yaml.safe_load(path.read_text(encoding="utf-8")))
    for problem in found:
        print("render.yaml:", problem)
    if not found:
        print("render.yaml: OK (no literal secrets, production settings)")
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main())
