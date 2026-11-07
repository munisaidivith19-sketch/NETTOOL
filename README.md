# NetMap

AI-assisted network mapping, IP address management and monitoring for small and medium
organizations (colleges, hospitals, SMEs). See `CLAUDE.md` for the full brief and security rules,
and `PHASE_PROMPTS.md` for the build plan.

**Status: Phase 1 done.** The backend has accounts, roles, sessions, CSRF protection, an audit
log and HMAC-signed agent authentication (see `docs/auth-design.md`). The dashboard UI comes in
Phase 4; until then use the API (`/docs` in development).

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
- `/api/agent/heartbeat` (signed agent requests)

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
copy .env.example .env
python -m netmap_agent.main
```
In Phase 0 this only loads and validates settings. Discovery arrives in Phase 2.
Always start it with `python -m netmap_agent.main` from the `agent` folder.

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
| Agent | `pytest` · `ruff check .` · `bandit -r netmap_agent` · `pip-audit -r requirements.txt` |
| Frontend | `npm test` · `npm run build` · `npm audit` |

Backend tests need the local MongoDB running. They use a separate `netmap_test` database that
they wipe, never `netmap`. Point them elsewhere with the `NETMAP_TEST_MONGODB_URI` env var.
