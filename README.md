# NetMap

AI-assisted network mapping, IP address management and monitoring for small and medium
organizations (colleges, hospitals, SMEs). See `CLAUDE.md` for the full brief and security rules,
and `PHASE_PROMPTS.md` for the build plan.

**Status: Phase 3 done.** The backend has accounts, roles, sessions, CSRF protection, an audit
log and HMAC-signed agent authentication (see `docs/auth-design.md`). The agent discovers the
network: it pings ranges, polls devices over SNMPv3 (system info, interfaces, IPv4/IPv6
addresses, ARP and IPv6 neighbours), detects the vendor and sends a signed report that the
backend stores. On top of that data the backend does IP address management: subnet usage for
IPv4 and IPv6, next free IP, reservations that can never collide, IP → MAC → device lookup,
duplicate-IP and "subnet over 80 % full" alerts. A simulated five-device campus lets you run
all of it without any hardware. The dashboard UI comes in Phase 4; until then use the API
(`/docs` in development).

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
- `GET /api/alerts?status=open|resolved&type=` (any role)

IPAM settings in `.env` (all optional): `IP_STALE_DAYS=30` (an address not seen for this long
counts as free again, unless reserved), `DUPLICATE_IP_WINDOW_MINUTES=60` (two MACs for one IP
inside this window = duplicate IP), `SUBNET_USAGE_ALERT_PERCENT=80`.

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
```powershell
cd frontend
npm install
npm run dev        # http://localhost:5173, forwards /api and /health to the backend on :8000
```
Run the backend at the same time. The Overview page shows backend and database status.

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
