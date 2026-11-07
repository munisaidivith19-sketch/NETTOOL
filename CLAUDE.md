# NetMap – AI-Assisted Network Mapping, IPAM and Monitoring Portal

> Project brief for Claude Code. Put this file in the project root as `CLAUDE.md`.
> Claude Code reads it automatically at the start of every session.

## 1. Problem statement
In organizations with many PCs, switches, routers and access points, network engineers have no
single real-time view of: where each device is connected, whether it is working, which IPv4/IPv6
ranges are in use, which IP is allocated to which device, whether any IP is duplicated, and how many
IPs are left. Unconfigured devices are set up by hand. Records live in spreadsheets that drift from
reality. NetMap discovers, maps, monitors and safely configures network devices, manages IPv4 and
IPv6 addresses without duplication, and uses AI to predict problems and answer questions in plain
language. Target users: small and medium organizations (colleges, hospitals, SMEs) that cannot
afford enterprise tools.

## 2. Architecture (do not change without asking)
```
 PRIVATE NETWORK (GNS3 lab / company LAN)            CLOUD (free tier)
 Devices ◄─ ping/SNMP/SSH ─ NetMap Agent ──HTTPS──►  FastAPI backend (Render web service)
                            (Python, runs inside      │  also serves the React build
                             the network)             ▼
                                                     MongoDB (local in dev, Atlas in prod)
```
- **Agent** (`agent/`): runs inside the private network. Discovers and polls devices, pushes
  approved configuration changes, trains AI models. Makes **outbound HTTPS connections only**.
  **Device credentials (SSH passwords, SNMPv3 keys) live only on the agent and are never sent
  to the cloud.**
- **Backend** (`backend/`): FastAPI. Receives agent reports, stores data, serves the dashboard API,
  handles logins, roles, approvals and IPAM logic. Must stay light (Render free: 512 MB RAM).
- **Frontend** (`frontend/`): React + Vite + plain CSS (no UI framework required).
  Preferred: built files served by FastAPI from the same origin (no CORS, httpOnly cookies work).
- **Database**: MongoDB. Same code for local MongoDB and MongoDB Atlas; only `MONGODB_URI` changes.

## 3. Tech stack and constraints
- Python **3.10** (owner's decision, 2026-11-07; EOL Oct 2026 - see docs/known-limitations.md).
  FastAPI, Pydantic v2, PyMongo **AsyncMongoClient** – not Motor, Uvicorn. Libraries that have
  dropped 3.10 stay pinned to their last 3.10 release (pymongo 4.18.3, pydantic-settings 2.15.0,
  scikit-learn 1.7.2, pytest 9.1.1). Check `requires_python` on PyPI before bumping any pin.
- Agent: pysnmp (v7 asyncio API), Netmiko, Jinja2 (sandboxed), ciscoconfparse2, APScheduler,
  httpx, scikit-learn, Prophet, Ollama (optional).
- Frontend: React 18+, Vite, React Router, plain CSS with CSS variables (light + dark theme),
  Cytoscape.js for topology, Chart.js or Recharts for charts.
- **No Docker.** Everything must run natively on Windows 11 and on Render's native Python runtime.
- **Free resources only.** No paid services or APIs.
- Lab: GNS3 (Cisco IOSv / MikroTik CHR / FRRouting / VPCS), Cisco CML-Free, Cisco DevNet Sandbox.
  Also provide a **simulation mode** using `snmpsim` data files so the project can be demoed
  without a lab.
- Deployment: Render free tier (sleeps after 15 min idle, 512 MB RAM, no persistent disk, no free
  background workers). All scheduled jobs run in the agent, never on Render.
- Python on Windows: use `py -3.10` / a `.venv` virtual environment per component.
- Project root is this folder (`NETWORKING`), its own git repo nested inside the Smart Campus
  repo folder (excluded there via `.git/info/exclude`). Local MongoDB is the Windows service on
  127.0.0.1:27017 (replica set `rs0`); tests use database `netmap_test`.

## 4. Folder structure
```
netmap/
├── CLAUDE.md
├── backend/
│   ├── app/
│   │   ├── main.py            # app factory, lifespan, security headers, static files
│   │   ├── config.py          # settings from environment (pydantic-settings)
│   │   ├── db.py              # AsyncMongoClient, indexes
│   │   ├── security/          # passwords, sessions/JWT, CSRF, rate limiting, RBAC, agent auth
│   │   ├── models/            # Pydantic request/response schemas
│   │   ├── services/          # ipam.py, alerts.py, audit.py, ingest.py
│   │   ├── api/               # routers: auth, users, devices, subnets, ips, alerts,
│   │   │                      # topology, configs, changes, agents, ai, agent_ingest
│   │   └── ai/                # natural-language search (read-only)
│   ├── tests/
│   ├── requirements.txt
│   └── .env.example
├── agent/
│   ├── netmap_agent/
│   │   ├── main.py            # scheduler
│   │   ├── discovery/         # ping sweep, snmp, lldp/cdp, mac tables, oid parsers
│   │   ├── config.py          # agent settings from env
│   │   ├── config_mgmt/       # backup, templates, compliance, push, rollback
│   │   ├── ai_training/       # forecasting, anomaly detection, classification
│   │   ├── uploader.py        # signed HTTPS requests to backend, retries
│   │   └── credential_store.py # encrypted local credential store (not `secrets.py`: it
│   │                          # would shadow the stdlib `secrets` module)
│   ├── simulation/            # snmpsim data files + start script
│   ├── tests/
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/ (pages, components, api, styles)
│   └── package.json
├── lab/                       # GNS3 topology notes, sample device configs
├── templates/                 # Jinja2 device config templates
├── docs/                      # architecture, security, API, user guide
├── render.yaml
└── .gitignore
```

## 5. Features (built in phases – see PHASE_PROMPTS.md)
1. **Discovery**: ping sweep of configured ranges, SNMP v2c/v3 polling, seed targets
   (`host:port`), vendor detection from sysObjectID, unreachable-device detection.
2. **IPAM**: IPv4 + IPv6 subnets (from device interfaces and manual entry), IP → MAC → device →
   switch port mapping, used / free / percent per subnet, next free IP, **duplicate IP detection**
   (same IP seen with different MACs), prevention of duplicate manual allocation.
3. **Topology & location**: LLDP/CDP neighbors, MAC address tables (BRIDGE-MIB, Q-BRIDGE-MIB),
   "which switch port is this PC on", sysLocation, interactive map with live status colours.
4. **Monitoring & alerts**: up/down, interface status, alerts (device down, duplicate IP, new
   unknown MAC, subnet > 80% full), Telegram/email notifications.
5. **Configuration**: scheduled backups with version diff, compliance checks (Telnet enabled,
   weak SNMP, no password encryption, etc.), **safe auto-configuration** of unconfigured devices.
6. **AI**: IP exhaustion forecast, traffic anomaly detection, device-type classification,
   natural-language search, plain-language explanations of alerts and config changes.

### Key SNMP sources
| Data | MIB / OID |
|---|---|
| name, description, location, vendor | SNMPv2-MIB sysName, sysDescr, sysLocation, sysObjectID |
| interfaces | IF-MIB |
| interface IPv4/IPv6 addresses + prefixes | IP-MIB ipAddressTable (1.3.6.1.2.1.4.34), fallback ipAddrTable |
| ARP + IPv6 neighbors | IP-MIB ipNetToPhysicalTable (1.3.6.1.2.1.4.35), fallback ipNetToMediaTable |
| neighbors | LLDP-MIB, CISCO-CDP-MIB |
| MAC → port | BRIDGE-MIB, Q-BRIDGE-MIB |

### IP storage rule (MongoDB has no IP type)
Store every address with a sortable key: `ip_key = f"{version}:{int(addr):032x}"`.
Subnet membership = `{"ip_key": {"$gte": key(network), "$lte": key(broadcast)}}`.
Unique index on `ip_addresses.ip_key`. Send IPv6 sizes to the browser as strings
(they exceed JavaScript's safe integer range).

## 6. MongoDB collections
`users, sessions, agents, devices, interfaces, subnets, ip_addresses, arp_entries, mac_entries,
links, configs, change_requests, alerts, metrics, predictions, audit_log`
- Indexes: `devices.mgmt_ip` unique, `ip_addresses.ip_key` unique, `subnets.network` unique,
  `alerts.key` unique, `users.username` unique, TTL on `metrics.ts` (7 days) and `sessions.expires_at`.
- Use `tz_aware=True` and store all times in UTC.

## 7. SECURITY REQUIREMENTS (mandatory in every phase)
This is a network *security* project. Every feature must follow these rules. If a request
conflicts with them, stop and ask.

### 7.1 Authentication and sessions
- Passwords hashed with **bcrypt** (cost ≥ 12) or Argon2id. Never store or log plain passwords.
- Password policy: minimum 12 characters; reject the most common passwords.
- Sessions: **httpOnly, Secure, SameSite=Strict cookies** (same origin). Never put tokens in
  `localStorage`. If two origins are unavoidable, use short-lived (15 min) access tokens kept in
  memory plus a refresh cookie, and document why.
- Session expiry: 8 hours absolute, 30 minutes idle. Logout invalidates the session server-side.
- **Brute-force protection**: rate-limit login per IP and per username; lock account for
  15 minutes after 5 failed attempts. Generic error message ("Invalid username or password").
- **TOTP MFA** (pyotp) required for admin accounts (phase 8).
- First admin created from `ADMIN_USERNAME` / `ADMIN_PASSWORD` env vars only when no users exist;
  force password change on first login.

### 7.2 Authorization (RBAC)
- Roles: `admin` (users, agents, settings), `engineer` (create change requests, manage subnets),
  `viewer` (read only).
- Check roles **on the server for every route**. Hiding buttons in React is not security.
- Deny by default: a route without an explicit role dependency must fail tests.

### 7.3 Agent ↔ backend security
- Each agent has its own API key: 32 random bytes (`secrets.token_urlsafe`), shown **once**,
  stored only as a SHA-256 hash, revocable from the admin UI.
- Every agent request is **HMAC-SHA256 signed** over `method + path + timestamp + nonce + body`
  with headers `X-Agent-Id`, `X-Timestamp`, `X-Nonce`, `X-Signature`. Reject if the timestamp is
  more than 5 minutes off or the nonce was used before (replay protection).
- Agent keys can only call `/api/agent/*` routes. User sessions cannot call agent routes.
- HTTPS only in production (agent refuses `http://` unless `ALLOW_INSECURE_LOCAL=true` for localhost).

### 7.4 Input validation and injection
- All request bodies are Pydantic models with `extra="forbid"`, max string lengths and max list
  sizes. Request body limit: 2 MB (agent reports may be larger – set a specific limit, e.g. 10 MB).
- Validate every IP, CIDR and MAC with `ipaddress` / regex before use.
- **NoSQL injection**: never pass user JSON directly into a query; build filters from validated
  fields only; reject keys starting with `$` or containing `.`.
- **Command injection**: `subprocess` only with argument lists, never `shell=True`; validate
  targets as IP addresses first.
- **Template injection**: Jinja2 `SandboxedEnvironment` with `StrictUndefined`; template variables
  validated against a schema.
- Frontend: never use `dangerouslySetInnerHTML`; treat device names, sysDescr, logs and config
  text as untrusted.

### 7.5 Configuration-change safety (auto-configuration)
- Flow: draft → **dry-run preview** → **approval** → agent pushes → verify → done / rolled back.
- **Four-eyes rule**: the approver must be a different user from the creator (admin may override,
  and the override is audit-logged).
- Command **denylist** (e.g. `erase`, `reload`, `write erase`, `delete`, `format`,
  `no ip address` on the management interface, `shutdown` on uplink/management ports,
  `no username`, `crypto key zeroize`), checked with ciscoconfparse2 before approval and again on
  the agent before pushing.
- Device rollback: Cisco `configure terminal revert timer` (requires `archive`), MikroTik safe mode.
  After pushing, the agent pings and re-polls the device; if unreachable → rollback + critical alert.
- Changes are idempotent and every push is recorded in `audit_log` with before/after config hashes.

### 7.6 Secrets and credentials
- `.env` files are git-ignored; commit `.env.example` with placeholders only.
- Device credentials stay on the agent, encrypted at rest (cryptography Fernet, key from env or
  Windows DPAPI). They are never sent to the backend, the database, the logs or the LLM.
- Prefer **SNMPv3 authPriv (SHA + AES)** and SSH. Telnet is not supported. SNMPv2c is allowed only
  in the lab and shows a warning in the UI.
- Never log secrets, tokens, cookies, passwords, community strings or full config files with secrets.
  Mask secrets in stored config backups (`password`, `secret`, `community`, `key` lines).

### 7.7 HTTP security
- Security headers on every response: `Content-Security-Policy` (self only, no inline scripts),
  `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`
  (`frame-ancestors 'none'`), `Referrer-Policy: no-referrer`, `Permissions-Policy`.
- CSRF protection for cookie-authenticated state-changing requests (double-submit token or
  required custom header + SameSite=Strict).
- CORS: disabled when same origin; otherwise an explicit allowlist from env, never `*`.
- Errors: no stack traces or internal details to clients; log them server-side with a request ID.
- Disable FastAPI `/docs` and `/openapi.json` in production (`ENV=production`).

### 7.8 Database
- Atlas: separate least-privilege users (`netmap_app` readWrite on `netmap` only,
  `netmap_ai_ro` read only). Network Access: Render's outbound IPs only, never `0.0.0.0/0`.
- TLS to Atlas (default). Local MongoDB bound to `127.0.0.1` only.
- TTL indexes for metrics and sessions to limit data kept.

### 7.9 AI safety
- Natural-language search uses a **read-only DB user**, an allowlist of collections and query
  operators (`$match`, `$project`, `$sort`, `$limit`, `$count`, `$group` only), a result limit,
  and a timeout. Never execute AI output that writes data.
- AI-generated configuration is only a **draft** that must pass all checks in 7.5 and human approval.
- Treat device data and logs as untrusted input to the LLM (prompt-injection risk); never send
  secrets or credentials to the LLM. LLM provider and key come from env (Gemini/Groq free tier
  in the cloud, Ollama locally).

### 7.10 Audit logging and monitoring
- `audit_log` records: logins (success/failure), logouts, user/role changes, agent key create/revoke,
  subnet changes, change-request create/approve/reject/push/rollback, settings changes.
  Fields: who, what, target, when, source IP, result. Append-only from the app.
- Security alerts: repeated failed logins, unknown agent signature, new unknown MAC, rogue DHCP
  (later phase), compliance score drop.

### 7.11 Supply chain and code quality
- Pin dependency versions. Run `pip-audit`, `npm audit`, and **Bandit** before each release.
- Enable GitHub Dependabot. No unmaintained packages for security functions.
- Type hints everywhere; `ruff` for linting; tests with `pytest` and `vitest`.

## 8. Testing rules
- Every phase ends with passing tests. Backend tests use a separate database (`netmap_test`).
- Required security tests: unauthenticated access is rejected on every route, RBAC per role,
  login lockout, CSRF rejection, agent signature/replay rejection, NoSQL-injection payloads
  rejected, denylisted commands blocked, secrets masked in stored configs.
- Agent tests: OID parsers (IPv4 + IPv6), vendor detection, MAC formatting, ping target validation.
- Provide `snmpsim` simulation so discovery can be tested end to end without real devices.

## 9. Working rules for Claude Code
- Work **one phase at a time**. Start each phase in plan mode, show the plan, then implement.
- After each phase: run all tests, run the app, update `README.md` and `docs/`, and give me a
  short summary of what was built, how to run it, and what is not done yet.
- Explain important code in simple language — I am a 3rd-year cybersecurity student and will
  present this project in interviews.
- Do not add paid services, Docker, or new major libraries without asking.
- Never commit secrets. Never weaken a security rule to make a test pass.
