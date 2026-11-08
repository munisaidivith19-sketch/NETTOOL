# Security review: CLAUDE.md section 7, rule by rule (Phase 8)

Each rule was re-checked against the code. The second column shows what the review found
**before** Phase 8 and what it is now. Every FAIL and PARTIAL found was fixed in Phase 8.
The deployment rules (Atlas, TLS, HSTS behind the proxy, the real client IP) were completed
in Phase 9; see "Phase 9 additions". Rows marked "re-check on the live URL" were tested in a
local production rehearsal and are confirmed again after the real deploy. Paths are relative to the project root.

Status: **PASS** = done and tested. **PARTIAL** = only part of the rule was done. **FAIL** = not done.

## 7.1 Authentication and sessions

| Rule | Status | Where |
|---|---|---|
| bcrypt, cost ≥ 12 | PASS | `backend/app/security/passwords.py:44`, minimum in `backend/app/config.py:14` |
| Never store or log plain passwords | PASS | passwords exist only as bcrypt hashes; `agent/tests/test_logging_secrets.py`, `backend/tests/test_audit.py` |
| Minimum 12 characters, common passwords rejected | PASS | `backend/app/security/passwords.py:36`, list in `security/common_passwords.txt` |
| httpOnly + Secure + SameSite=Strict cookies, no tokens in localStorage | PASS | `backend/app/security/sessions.py:86-88`; the frontend has no `localStorage` token code |
| 8 h absolute, 30 min idle, server-side logout | PASS | `backend/app/security/sessions.py:16-17`, check at `:62`; logout deletes the session at `backend/app/api/auth.py:141` |
| Rate limit per IP and per username; lock for 15 min after 5 failures | PASS | `backend/app/security/rate_limit.py:16-19`; `backend/app/api/auth.py:96`, `:110`, `:116` |
| Generic error message | PASS | `backend/app/api/auth.py:36`; one message for unknown user, bad password, locked or disabled |
| **TOTP MFA required for admins** | FAIL → **PASS** | new: `backend/app/security/mfa.py`, `backend/app/api/mfa.py`; enforced in `backend/app/security/rbac.py:104`; `backend/tests/test_mfa.py` |
| MFA failures count toward the lockout | new → PASS | `backend/app/api/mfa.py:60`; the password-change form counts too (`backend/app/api/auth.py:166`) |
| First admin from env only when no users exist; forced password change | PASS | `backend/app/services/bootstrap.py:14`, `backend/app/services/users.py:35` |

## 7.2 Authorization (RBAC)

| Rule | Status | Where |
|---|---|---|
| Roles admin / engineer / viewer | PASS | `backend/app/security/rbac.py:23` |
| Roles checked on the server for every route | PASS | `require_role` in `backend/app/security/rbac.py:86` |
| Deny by default: a route without a role dependency fails tests | PASS | `backend/tests/test_rbac.py:58` (every route has a marker), `:45` (no unlisted routes), `:140` (the check itself is tested) |
| RBAC tested per role | PARTIAL → **PASS** | the hand-written admin-only list was replaced by a matrix built from each route's `roles:` marker, so a new route is tested for every role automatically (`backend/tests/test_rbac.py:122`) |

## 7.3 Agent ↔ backend

| Rule | Status | Where |
|---|---|---|
| Per-agent key, 32 random bytes, shown once, revocable | PASS | `backend/app/security/agent_auth.py:46`; `backend/tests/test_agents.py::test_key_shown_once_and_never_stored_in_plain` |
| Key stored Fernet-encrypted + SHA-256 fingerprint | PASS | `KeyVault` in `backend/app/security/agent_auth.py:53` |
| HMAC-SHA256 over method + path + timestamp + nonce + body | PASS | `backend/app/security/agent_auth.py:73`, agent side `agent/netmap_agent/uploader.py:41` |
| ±5 min timestamp, nonce used once | PASS | `backend/app/security/agent_auth.py:32-33`, `:120`, `:139-145` |
| Agent keys only on `/api/agent/*`; sessions can't call agent routes | PASS | `backend/tests/test_rbac.py:135`; agent routes ignore cookies (`agent_auth.py:89`) |
| HTTPS only, except `ALLOW_INSECURE_LOCAL` for localhost | PASS | `agent/netmap_agent/config.py:106`, `agent/netmap_agent/uploader.py:65` |
| **Bad agent signatures can't flood the audit log** | PARTIAL → **PASS** | every bad signature used to write one audit entry, so anyone could fill Atlas M0 (512 MB). Now counted per IP and 10-minute window: `backend/app/services/security_events.py`; `backend/tests/test_security_events.py:16` |

## 7.4 Input validation and injection

| Rule | Status | Where |
|---|---|---|
| Pydantic `extra="forbid"`, max lengths, max list sizes | PASS → **checked for every route** | `backend/app/models/common.py:14`. New meta-test walks every body model and query parameter: `backend/tests/test_input_limits.py:103`, `:110`. It found one unbounded field (`ChangeSource.variables` list values), fixed in `backend/app/models/configs.py:51` |
| 2 MB body limit, 10 MB for agent reports | PASS | `backend/app/security/http.py:16-19` |
| IP, CIDR and MAC validated | PASS | `ipaddress` in `backend/app/models/ipam.py:61`, `IpPath` in `backend/app/models/common.py:28`, MAC pattern `backend/app/models/ai.py:11` |
| NoSQL injection: no raw user JSON in queries; `$` keys and dotted keys rejected | PASS → **tested on every write route** | typed fields can't hold `{"$ne": …}` (`backend/app/models/common.py:10`); `backend/tests/test_input_limits.py:138` sends `$where`, `{"$ne": null}` and `a.b` keys to every POST/PUT/PATCH route |
| Command injection: no `shell=True`, targets validated as IPs | PASS | `agent/netmap_agent/discovery/ping.py:34`, `:63`, `:77` |
| Template injection: SandboxedEnvironment + StrictUndefined, variables validated | PASS | `backend/app/config_mgmt/templates.py:5`, `:183` |
| Frontend: no `dangerouslySetInnerHTML` | PASS | none in `frontend/src`; the MFA QR code is drawn as SVG squares, not an image or HTML |

## 7.5 Configuration-change safety

| Rule | Status | Where |
|---|---|---|
| draft → dry-run → approval → push → verify → done / rolled back | PASS | `backend/app/services/changes.py`, `agent/netmap_agent/config_mgmt/push.py` |
| Four-eyes rule, audited admin override | PASS | `backend/app/api/changes.py:220-224`, `:250` |
| Denylist before approval and again on the agent | PASS | `backend/app/services/changes.py:83`; `agent/netmap_agent/config_mgmt/push.py:143`, `:178` |
| Cisco revert timer, MikroTik safe mode, rollback if unreachable | PASS | `agent/netmap_agent/config_mgmt/push.py:8-9` |
| Before/after hashes in the audit log | PASS | `backend/app/api/agent_config.py:120` |

## 7.6 Secrets and credentials

| Rule | Status | Where |
|---|---|---|
| `.env` git-ignored, `.env.example` placeholders only | PASS | `.gitignore`; `backend/.env.example` gains `MFA_ENCRYPTION_KEY` (empty) |
| Device credentials only on the agent, Fernet + DPAPI | PASS | `agent/netmap_agent/credential_store.py:96`, atomic write at `:165` |
| SNMPv3 preferred; v2c warning in the UI; no Telnet | PASS | `frontend/src/pages/Devices.jsx:19`; compliance flags Telnet |
| No secrets in logs | PASS → **tested** | Netmiko/paramiko loggers at WARNING, `session_log=None` (`agent/netmap_agent/config_mgmt/connection.py:22`, `:133`); new `agent/tests/test_logging_secrets.py` and a caplog check in `agent/tests/test_simulation.py` |
| Secrets masked in stored backups | PASS | `agent/netmap_agent/config_mgmt/masking.py:101` |
| **TOTP secrets encrypted at rest** | new → PASS | Fernet under `MFA_ENCRYPTION_KEY`, separate from the agent key (`backend/app/main.py:78-84`); recovery codes stored as SHA-256 hashes |

## 7.7 HTTP security

| Rule | Status | Where |
|---|---|---|
| CSP self only, nosniff, X-Frame-Options DENY, frame-ancestors none, Referrer-Policy, Permissions-Policy | PASS | `backend/app/security/http.py:24`, `:64-68` |
| HSTS | PASS (production rehearsal 2026-11-08); re-check on the live URL | `backend/app/security/http.py:75` (production only) |
| CSRF for cookie-authenticated writes | PASS | token: `backend/app/security/csrf.py:25-29`; Origin and Content-Type checks: `:39-62` |
| CORS off (same origin) | PASS | no CORS middleware in `backend/app/main.py` |
| No stack traces to clients, request ID | PASS | `backend/app/main.py:125-130` |
| `/docs` and `/openapi.json` off in production | PASS | `backend/app/main.py:113-120` |

## Phase 9 additions

| Rule | Status | Where |
|---|---|---|
| 7.1: rate limiting uses the real client IP behind the proxy | FAIL → **PASS** | uvicorn's `--forwarded-allow-ips=*` would take the client-chosen leftmost `X-Forwarded-For` entry. The app counts trusted hops from the right instead (`backend/app/security/client_ip.py`); `tests/test_client_ip.py` shows that rotating forged entries still hit the 429 |
| 7.7: docs off in production | PARTIAL → **PASS** | with the dashboard served, `/docs` and `/openapi.json` returned 200 (the dashboard page, not the schema). They now return 404 (`backend/app/frontend.py`, `tests/test_health.py`) |
| 7.7: no internal details | PASS | `--no-server-header` in `render.yaml` |
| 7.6: no secrets in git | PASS | `scripts/scan_git_history.py` (every added line in history) and `scripts/check_render_yaml.py`, both in `security-check.ps1 -Release` |

## 7.8 Database

| Rule | Status | Where |
|---|---|---|
| Atlas least-privilege users, network access limited to Render | PASS (documented); confirmed when the cluster is created | `docs/DEPLOYMENT.md` §1 and §4: `netmap_app` readWrite@netmap, `netmap_ai_ro` read@netmap, Render Singapore ranges only |
| TLS to Atlas | PASS | `mongodb+srv://` is TLS by default; production refuses a non-TLS remote URI (`backend/app/config.py`, `uses_tls`; `tests/test_config.py`) |
| Local MongoDB on 127.0.0.1 only | PASS | `bindIp: 127.0.0.1` in the local `mongod.cfg` (checked 2026-11-08) |
| TTL indexes on metrics and sessions | PASS | `backend/app/db.py` (also new TTLs on `mfa_challenges` and `security_events`) |

## 7.9 AI safety

| Rule | Status | Where |
|---|---|---|
| Read-only DB user for natural-language search | PARTIAL → **PASS** | in production without `AI_MONGODB_URI`, Ask NetMap fell back to the read-write user. It now refuses with 503 (`backend/app/api/ai.py:55`) and logs a warning at startup (`backend/app/main.py:96`) |
| Operator / collection allowlist, result limit, timeout | PASS | `backend/app/ai/query_guard.py:26-37`, `backend/app/ai/nlsearch.py:202` |
| AI output never writes; AI config is a draft only | PASS | Ask NetMap runs `aggregate` only; AI drafts go through the 7.5 flow |
| Device data treated as untrusted; no secrets to the LLM | PASS | `backend/app/ai/explain.py` system prompt; masked configs only |

## 7.10 Audit logging and monitoring

| Rule | Status | Where |
|---|---|---|
| All listed events audited with who / what / target / when / IP / result | PASS | `backend/app/services/audit.py:38-45`. New MFA actions: `auth.mfa_challenge`, `auth.mfa_enable`, `auth.mfa_disable`, `auth.mfa_failure`, `auth.mfa_recovery_used`, `auth.mfa_recovery_regenerate`, `user.mfa_reset` |
| Append-only from the app | PASS | `backend/app/services/audit.py:48` is the only write; `backend/app/api/audit.py:35` is read-only |
| **Security alerts: repeated failed logins, unknown agent signature** | PARTIAL → **PASS** | they were audited but raised no alert. New alert type `security` (`backend/app/services/security_events.py`), opened on an account lockout, when an IP hits the login limit, or after 5 bad agent signatures from one IP in 10 minutes; notified like every other alert |
| New unknown MAC, compliance score drop | PASS | `backend/app/services/ingest.py:199`, `backend/app/services/compliance.py` |
| Rogue DHCP | not done (later phase) | `docs/known-limitations.md` |

## 7.11 Supply chain and code quality

| Rule | Status | Where |
|---|---|---|
| Pinned versions | PASS → **fixed** | `pyotp` and `segno` were installed but missing from `backend/requirements.txt`, so a clean install would have failed. They are now pinned |
| pip-audit, npm audit, Bandit before each release | PARTIAL → **PASS** | new `scripts/security-check.ps1` runs all of them plus ruff and every test suite |
| Dependabot | PASS | `.github/dependabot.yml` |
| ruff, pytest, vitest | PASS | see Phase 8 results in `README.md` |

## Scanner results (2026-11-08)

| Tool | Result |
|---|---|
| ruff (backend, agent) | clean, after two long lines were wrapped |
| Bandit (backend, agent) | clean. One Low finding (B311) in the dev-only `backend/scripts/seed_demo_history.py`, where a predictable random generator is intended for repeatable demo data; marked `# nosec B311` with that reason |
| pip-audit, backend runtime | dnspython CVE-2026-114605: accepted, see `docs/known-limitations.md` |
| pip-audit, agent runtime | dnspython (as above) and Pillow 12.3.0 (fix needs Python 3.11+): accepted, see `docs/known-limitations.md` |
| pip-audit, dev environment | filelock (accepted, dev only); setuptools 57.4.0 in the virtual environments, upgraded |
| npm audit | 0 vulnerabilities |
