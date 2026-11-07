# NetMap

AI-assisted network mapping, IP address management and monitoring for small and medium
organizations (colleges, hospitals, SMEs). See `CLAUDE.md` for the full brief and security rules,
and `PHASE_PROMPTS.md` for the build plan.

**Status: Phase 7 done.** The backend has accounts, roles, sessions, CSRF protection, an audit
log and HMAC-signed agent authentication (see `docs/auth-design.md`). The agent discovers the
network: it pings ranges, polls devices over SNMPv3 (system info, interfaces, IPv4/IPv6
addresses, ARP and IPv6 neighbours), detects the vendor and sends a signed report that the
backend stores. On top of that data the backend does IP address management: subnet usage for
IPv4 and IPv6, next free IP, reservations that can never collide, IP → MAC → device lookup,
duplicate-IP and "subnet over 80 % full" alerts. The React dashboard covers all of it: sign-in
(with the forced first password change), dashboard, devices, IP management, alerts with
acknowledge/resolve, and admin pages for users, agents and the audit log. Phase 5 adds the
network map: LLDP/CDP neighbours become links on an interactive topology page, switch MAC
tables answer "which switch port is this PC on?", interface counters become traffic rates,
and the backend raises device-down, uplink-down and new-unknown-device alerts and sends them
by Telegram or e-mail. Phase 6 adds configuration management. The agent backs up Cisco IOS
and MikroTik configs over SSH. Its SSH logins sit in an encrypted file that never leaves the
agent. Passwords and keys are masked before upload. The dashboard shows version history with a
side-by-side diff, a compliance score with a suggested fix for each finding, and a flag for
devices still at factory settings. Changes follow a safe path: template or own commands →
dry-run preview → denylist check → approval by a second person → the agent pushes with an
automatic rollback timer → verify → done or rolled back. Phase 7 adds AI. The agent forecasts
when each subnet runs out of addresses and when uplinks get busy (Prophet, or a straight line
when history is short). It flags unusual interface traffic (IsolationForest) with a plain
explanation, and guesses what each endpoint is (PC, printer, phone, camera, AP, VM...) and why.
**Ask NetMap** answers plain-English questions with a read-only, allowlisted database query
that is shown to you, and **Explain** buttons describe alerts, compliance findings and config
diffs in plain language. Both work without any API key; a free Gemini/Groq key or a local
Ollama model is optional. A simulated six-device campus (SNMP plus a fake Cisco SSH server)
lets you run everything without any hardware.

```
agent/     runs inside the private network; discovers and polls devices (Python)
backend/   FastAPI API + serves the built React app (deployed to Render)
frontend/  React + Vite dashboard
docs/      architecture, known limitations (security docs arrive in Phase 8)
lab/       GNS3 notes and sample device configs (later phases)
templates/ Jinja2 device config templates (cisco_ios/, mikrotik_routeros/)
```

## Requirements (Windows 11, no Docker)
- **Python 3.10** (`py -3.10`). See `docs/known-limitations.md` for why this matters.
- **Node.js 20.19+** (tested on 24.15) and npm.
- **MongoDB**, either the local Community Server or a free MongoDB Atlas cluster.

## 1. MongoDB

**Local (development).** Install MongoDB Community Server as a Windows service. By default it
listens on `127.0.0.1:27017` only, which is what we want: never bind it to `0.0.0.0`.
Use `MONGODB_URI=mongodb://127.0.0.1:27017`.

**MongoDB Atlas (production).** Create a free M0 cluster and a database user, then use its
`mongodb+srv://...` connection string as `MONGODB_URI`. Nothing else changes. Least-privilege
users and network access rules are covered in Phase 9 (`docs/DEPLOYMENT.md`).

## 2. Backend
```powershell
cd backend
py -3.10 -m venv .venv
.venv\Scripts\activate
pip install -r requirements-dev.txt     # Render installs requirements.txt only
copy .env.example .env                  # then edit .env (see below)
uvicorn app.main:app --reload
```
In `.env`, set at least:
- `AGENT_KEY_ENCRYPTION_KEY`. Required; the backend refuses to start without it. Generate one
  with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.
- `ADMIN_USERNAME` and `ADMIN_PASSWORD`. These create the first admin when the database has no
  users. Log in with them, change the password when asked, then delete both lines.

Main API routes:
- `/api/auth/login`, `/logout`, `/me`, `/change-password`
- `/api/users` and `/api/agents` (admin)
- `/api/audit` (admin)
- `/api/agent/heartbeat`, `/api/agent/report`, `/api/agent/known-devices` (signed agent
  requests only; a user session is not accepted there)
- IPAM (read: any role; change: engineer or admin):
  - `GET/POST /api/subnets`, `GET/PATCH/DELETE /api/subnets/{id}`: usage, manual subnets,
    overlap check
  - `GET /api/subnets/{id}/ips?limit=&after=` (IP table, paged) and `/next-free`
  - `GET /api/ips/search?q=` (IP, CIDR, MAC in any common format, or host name),
    `GET /api/ips/{ip}` (IP → MAC → device → interface)
  - `POST /api/ips/reservations`, `DELETE /api/ips/reservations/{ip}`
- `GET /api/alerts?status=open|resolved|all&type=` (any role);
  `POST /api/alerts/{id}/acknowledge` and `/resolve` (engineer or admin)
- `GET /api/devices?q=&status=`, `GET /api/devices/{id}` (any role)
- `GET /api/dashboard/summary` (any role): device counts, fullest subnets, open alerts, last
  agent check-in
- `GET /api/topology` (any role): devices, external neighbours and links for the map
- `GET /api/topology/locate?q=` (any role): which switch port an IP, MAC or host name is on
- `GET /api/devices/{id}/metrics?if_index=&hours=` (any role): traffic history of an uplink or
  IP interface (7 days kept)
- `GET /api/admin/notifications`, `POST /api/admin/notifications/test` (admin)
- Configuration (Phase 6):
  - `GET /api/configs` and `GET /api/devices/{id}/compliance` (any role): last backup,
    compliance score and findings, "unconfigured" flag. No config text.
  - `GET /api/devices/{id}/configs`, `/configs/{version}`, `/configs/diff?from=&to=`
    (engineer or admin): version list, masked config text, side-by-side diff
  - `POST /api/devices/{id}/configs/backup-now` (engineer or admin)
- Change requests (read: any role; write: engineer or admin):
  - `GET /api/templates`: templates with the JSON schema of their variables
  - `POST /api/changes/preview` (dry run), `POST /api/changes`, `PUT /api/changes/{id}`,
    `GET /api/changes`, `GET /api/changes/{id}`
  - `POST /api/changes/{id}/submit`, `/approve`, `/reject`, `/cancel`
- `/api/agent/backup-targets`, `/api/agent/configs`, `/api/agent/jobs/claim`,
  `/api/agent/jobs/{id}/status` (signed agent requests only)

IPAM settings in `.env` (all optional): `IP_STALE_DAYS=30` (an address not seen for this long
counts as free again, unless reserved), `DUPLICATE_IP_WINDOW_MINUTES=60` (two MACs for one IP
inside this window = duplicate IP), `SUBNET_USAGE_ALERT_PERCENT=80`.

Monitoring: `NEW_MAC_LEARNING_HOURS=24`. For the first 24 hours after NetMap first sees a
switch MAC table, every MAC counts as part of the existing network. After that, a MAC no
switch has reported before raises a "new unknown device" alert.

### Notifications (optional)
Alerts are sent when they open or reopen and are at least `NOTIFY_MIN_SEVERITY` (default
`warning`). One message per alert per 30 minutes, at most 20 per hour in total. Every send,
failure and suppression is listed on **Admin → Notifications**, which also has a "Send test
notification" button. Tokens and passwords go in the server's environment only, never in the UI.

- **Telegram:** talk to [@BotFather](https://t.me/BotFather) and send `/newbot` to get a
  token. Add the bot to your group, send it a message, then open
  `https://api.telegram.org/bot<token>/getUpdates` to find the chat id. Set
  `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`.
- **E-mail:** set `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY` (`starttls` or `ssl`; plain SMTP
  is not offered), `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM` and `SMTP_TO` (comma-separated).
  With Gmail, use an app password. Render's free tier may block outgoing SMTP ports; Telegram
  works there.

### AI: Ask NetMap and explanations (optional language model)
Ask NetMap and the Explain buttons work without any key: a built-in parser understands common
questions ("Which switch port is 10.10.10.20 on?", "Show down devices", "Which subnets will be
full within 90 days?", "Show all printers", "Devices made by Cisco"...), and explanations come
from built-in text. To let a language model handle other questions, set in `.env`:

| `LLM_PROVIDER` | Key | Notes |
|---|---|---|
| `none` (default) | – | built-in parser and texts only |
| `gemini` | `LLM_API_KEY` from Google AI Studio | free tier |
| `groq` | `LLM_API_KEY` from console.groq.com | free tier |
| `ollama` | – | a model on this machine (`ollama pull llama3.2`), `http://127.0.0.1:11434` |

The model only ever sees your question and a fixed list of collections and fields, never your
network data. Its answer must pass an allowlist (read-only stages, no users, sessions, audit
log or configs) and runs with a 3-second limit and at most 100 rows. The page always shows the
query that ran. In production set `AI_MONGODB_URI` to a read-only Atlas user (`netmap_ai_ro`);
without it the page says it is in development mode. Each user gets `AI_CALLS_PER_10_MINUTES`
(default 20) questions and explanations. Routes: `POST /api/ai/ask`, `POST /api/ai/explain`,
`GET /api/ai/status`, `GET /api/predictions`, `GET /api/subnets/{id}/forecast`,
`GET /api/devices/{id}/forecast`, `PUT|DELETE /api/macs/{mac}/classification` (engineer).

Open http://127.0.0.1:8000/health. It returns `{"status":"ok","database":"ok"}`, or HTTP 503
with `"database":"unavailable"` if MongoDB is not reachable. API docs are at `/docs` in
development and switched off when `ENV=production`.

On startup the backend creates all MongoDB indexes (unique keys, TTL expiry). Doing that again
on each restart is safe.

## 3. Agent
```powershell
cd agent
py -3.10 -m venv .venv
.venv\Scripts\activate
pip install -r requirements-dev.txt
copy .env.example .env                  # then edit .env
python -m netmap_agent.main --once      # one discovery cycle, then exit
python -m netmap_agent.main             # repeat every POLL_INTERVAL_SECONDS
```
Always start it from the `agent` folder. Before the first run:
1. In the backend, an admin creates an agent: `POST /api/agents` with `{"name": "..."}`. The
   response contains the agent's `id` and `key`. The key is shown **only once**.
2. Put them in the agent's `.env` as `AGENT_ID` and `AGENT_KEY`.
3. Set `SCAN_RANGES`, `SNMP_TARGETS` and the SNMPv3 user and keys.

Each cycle the agent:
1. asks the backend which devices it already knows
2. pings the scan ranges and those devices
3. polls every SNMP target
4. uploads one signed report

The SNMP credentials stay in the agent's `.env` and are never sent to the backend. The agent
only talks HTTPS; `http://` is accepted only for `127.0.0.1`/`localhost` when
`ALLOW_INSECURE_LOCAL=true`.

### SSH logins, config backups and changes
SSH usernames and passwords are kept in an encrypted file on the agent machine
(`credentials.enc`, Fernet). They are never sent to the backend, the database or the logs.
```powershell
python -m netmap_agent.credential_store init      # creates the file + its key
python -m netmap_agent.credential_store add --name core --match 10.0.10.0/24 --device-type cisco_ios --username netmap
python -m netmap_agent.credential_store list      # never prints passwords
python -m netmap_agent.credential_store test 10.0.10.2   # log in once and report the result
```
`add` asks for the password and enable secret without echoing them. `--match` takes an IP or
a CIDR; the most specific match wins. The file's key is `CREDENTIAL_STORE_KEY` from `.env`. If
that is empty, the key goes in a `.key` file next to it, protected with Windows DPAPI, so only
this Windows user can unlock it. Set `SSH_KNOWN_HOSTS_FILE` to an OpenSSH known_hosts file so
the agent refuses a device whose SSH host key changed.

Besides discovery, the agent now:
- backs up every device it has a login for, once a day (`CONFIG_BACKUP_INTERVAL_SECONDS`).
  Secrets are masked before upload. A version is uploaded only when its fingerprint changed.
- every minute (`JOB_POLL_INTERVAL_SECONDS`), handles "Back up now" requests and picks up
  approved changes. Each change is checked again on the agent (signature, expiry, denylist,
  device unchanged since approval). It is pushed with `configure terminal revert timer 5`
  (Cisco) or safe mode (MikroTik), then verified with a ping and a new SSH login. If the check
  passes the agent confirms and saves; if not, it rolls back.

**Change flow:** an engineer creates a change from a template (baseline, VLAN, access port)
or from their own commands. **Preview** shows exactly what will be pushed and any blocked
lines. They submit it, and **a different** engineer or admin approves it. An admin can approve
their own change only with a written reason, which is audit-logged. The agent pushes it within
a minute. The change page shows each step on a timeline, plus the agent's log. A rollback
raises a critical alert. A change may not contain passwords or keys, because it would be
stored; set those on the device directly.

### AI: forecasts, anomalies and device types
The agent's AI step runs every `AI_INTERVAL_SECONDS` (default 6 hours), on the agent machine
(Render's 512 MB couldn't hold Prophet). `python -m netmap_agent.main --ai-only` runs it once.
Each run:
1. fetches its own training data from the backend (`GET /api/agent/ai/training-data`): daily
   subnet usage, 7 days of uplink traffic, and the MACs its switches saw
2. forecasts subnet exhaustion (Prophet with ≥14 days of history, a straight line with
   3–13 days, nothing with less) and uplink bandwidth for the next 7 days
3. checks every uplink's newest 2 hours for unusual traffic (IsolationForest, ≥1 day of history)
4. classifies endpoints from the MAC vendor (OUI), SNMP data and network names; optionally
   also from open ports (`CLASSIFY_PORT_PROBE=true`: TCP connect to 8 ports, only inside
   `SCAN_RANGES`, off by default because it is active scanning)
5. uploads the results; an unusual interface opens a `traffic_anomaly` alert

An engineer can correct a device type on the IP detail page; a correction always wins over the
classifier. For more vendors, `python -m netmap_agent.ai_training.oui update` downloads the
IEEE list (saved as `agent/oui.csv`, git-ignored).

**Demo history.** The simulator has no past, so forecasts would show "not enough data". In
development, fill the database with 60 days of synthetic subnet usage and 7 days of uplink
traffic (with one traffic spike), then run the AI step:
```powershell
cd backend; python scripts\seed_demo_history.py     # refuses to run when ENV=production
cd ..\agent; python -m netmap_agent.main --ai-only
```
The seeded history is invented, so the forecast will not match the live "used" count of the
simulator.

### Simulated network (no lab needed)
`agent/simulation/` describes a small campus. Each device listens on its own loopback address,
port 1161:

| Device | Address | Vendor |
|---|---|---|
| EDGE-RTR-1 | 127.0.0.11 | Cisco router |
| CORE-SW-1 | 127.0.0.12 | Cisco layer-3 switch |
| ACCESS-SW-1 | 127.0.0.13 | HP switch |
| ACCESS-SW-2 | 127.0.0.14 | MikroTik switch |
| AP-1-LIBRARY | 127.0.0.15 | Aruba access point |
| Switch | 127.0.0.16 | Cisco switch, still at factory settings |

It has staff, lab and printer VLANs, IPv6 on two of them, and about 30 ARP/neighbour entries.
The edge router and core switch see each other with CDP; the core sees both access switches
and the AP with LLDP; the router sees an ISP router that NetMap doesn't manage. Staff PCs and
printers sit on ACCESS-SW-1 ports, lab VMs on ACCESS-SW-2, laptops on the AP's Wi-Fi, and the
core sees all of them on its trunks. Traffic counters grow at a fixed rate per port, so rates
appear from the second agent cycle. The AP has only 32-bit counters, like an older device.
The devices are [snmpsim](https://github.com/lextudio/snmpsim) responders speaking SNMPv3
authPriv (SHA + AES).
```powershell
cd agent
python -m simulation.run_simulation        # terminal 1: starts all six, Ctrl+C stops them
python -m netmap_agent.main --once         # terminal 2, with the simulation block of
                                           # .env.example copied into .env
```
For backups and changes, also start the fake Cisco SSH server. It serves EDGE-RTR-1 (with
deliberate weaknesses: Telnet, community `public`), CORE-SW-1 (hardened) and the factory-new
Switch, on port 2222:
```powershell
python -m simulation.ssh_sim               # terminal 3; writes simulation/ssh_known_hosts
python -m simulation.setup_credentials     # once: puts the lab logins in the encrypted store
```
Then set `SSH_KNOWN_HOSTS_FILE=simulation/ssh_known_hosts` and
`CHANGE_REVERT_SECONDS_PER_MINUTE=12` in `.env`. The simulator runs one revert-timer
"minute" in 12 seconds. Try it: open **Configuration → Switch → Create baseline change**,
preview it, submit, approve it as a second user, then run the agent. To watch a rollback,
start the SSH server with `--break-after-push`. It then refuses new logins after a push, the
agent's check fails, and the change is undone.
To run only some devices, name them: `python -m simulation.run_simulation core-switch ap-1`.
A device that stops answering SNMP shows as `snmp_error` on the next cycle, because its
loopback address still answers ping. On a real network a powered-off device shows as `down`.
The data files in `simulation/data/` are generated from `simulation/topology.py` by
`python -m simulation.build_snmprec`; a test checks that the committed files match.

## 4. Frontend
**Development** (hot reload):
```powershell
cd frontend
npm install
npm run dev        # http://localhost:5173, forwards /api and /health to the backend on :8000
```
Run the backend at the same time and sign in with the admin account.

**Like production** (one origin, the way Render runs it):
```powershell
cd frontend
npm run build      # writes frontend/dist
cd ..\backend
uvicorn app.main:app   # now http://127.0.0.1:8000 serves the app and the API
```
The backend serves `frontend/dist` when it exists (`FRONTEND_DIST` overrides the path). Any
non-API path returns the app, so links like `/ip/subnets/<id>` work after a reload; unknown
`/api/...` paths stay JSON 404s.

| Page | Who |
|---|---|
| Dashboard (auto-refresh 30 s), Devices, IP addresses, Alerts, Topology | everyone |
| Configuration (scores, findings, unconfigured devices), Changes (read) | everyone |
| Add/edit/delete subnets, reserve/release IPs, acknowledge/resolve alerts | engineer, admin |
| Config text and diffs, Back up now, create/approve/reject change requests | engineer, admin |
| Users, Agents (key shown once), Notifications, Audit log | admin |

On **Topology**, type an IP, MAC or host name into "Find which port a device is on": NetMap
shows the access switch and port and highlights the switch on the map. The table under the
map lists the same links as text.

Buttons a role can't use are hidden, but that is only convenience: the backend checks the
role on every request.

## Tests and checks
| Part | Command (inside the folder, venv active) |
|---|---|
| Backend | `pytest` · `ruff check .` · `bandit -r app` · `pip-audit -r requirements.txt` |
| Agent | `pytest` · `ruff check .` · `bandit -r netmap_agent simulation` · `pip-audit -r requirements.txt` |
| Frontend | `npm test` · `npm run build` · `npm audit` |

Backend tests need the local MongoDB running. They use a separate `netmap_test` database that
they wipe, never `netmap`. Point them elsewhere with the `NETMAP_TEST_MONGODB_URI` env var. The agent's simulation tests
start a real snmpsim responder on 127.0.0.21; they are skipped, with the reason shown, if
snmpsim is not installed.
