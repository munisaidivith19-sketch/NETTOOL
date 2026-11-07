# NetMap

AI-assisted network mapping, IP address management and monitoring for small and medium
organizations (colleges, hospitals, SMEs). See `CLAUDE.md` for the full brief and security rules,
and `PHASE_PROMPTS.md` for the build plan.

**Status: Phase 5 done.** The backend has accounts, roles, sessions, CSRF protection, an audit
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
by Telegram or e-mail. A simulated five-device campus lets you run everything without any
hardware.

```
agent/     runs inside the private network; discovers and polls devices (Python)
backend/   FastAPI API + serves the built React app (deployed to Render)
frontend/  React + Vite dashboard
docs/      architecture, known limitations (security docs arrive in Phase 8)
lab/       GNS3 notes and sample device configs (later phases)
templates/ Jinja2 device config templates (Phase 6)
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
python -m simulation.run_simulation        # terminal 1: starts all five, Ctrl+C stops them
python -m netmap_agent.main --once         # terminal 2, with the simulation block of
                                           # .env.example copied into .env
```
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
cd ..ackend
uvicorn app.main:app   # now http://127.0.0.1:8000 serves the app and the API
```
The backend serves `frontend/dist` when it exists (`FRONTEND_DIST` overrides the path). Any
non-API path returns the app, so links like `/ip/subnets/<id>` work after a reload; unknown
`/api/...` paths stay JSON 404s.

| Page | Who |
|---|---|
| Dashboard (auto-refresh 30 s), Devices, IP addresses, Alerts, Topology | everyone |
| Add/edit/delete subnets, reserve/release IPs, acknowledge/resolve alerts | engineer, admin |
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
