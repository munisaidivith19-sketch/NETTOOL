# Deploying NetMap: Render + MongoDB Atlas (free tiers)

Everything here is free:
- **one** Render web service (the API plus the React dashboard, same origin)
- **one** MongoDB Atlas M0 cluster
- the agent on your own laptop or a lab PC, inside the network it maps

Region: **Singapore** for both (Render `singapore`, Atlas AWS `ap-southeast-1`), so database
calls stay short.

```
 your laptop (agent) ──HTTPS, signed──► Cloudflare ─► Render proxy ─► NetMap (FastAPI + React)
 your browser ───────HTTPS, cookie────►                                    │ TLS
                                                                            ▼
                                                     MongoDB Atlas M0 (allowlist: Render IPs)
```

Steps 1 to 6 take about 30 minutes the first time. Run the
[pre-deployment checklist](#pre-deployment-checklist) before the first deploy and before each
later one.

## 1. MongoDB Atlas

1. Sign up at https://www.mongodb.com/cloud/atlas (free) and create a project `NetMap`.
2. **Create a cluster:** choose **M0 (Free)**, provider **AWS**, region **Singapore
   (ap-southeast-1)**, name `netmap`. If Atlas offers to "add your current IP address" or to
   create a first user, skip both. The users and the allowlist are set up below.
3. **Database users** (Security → Database Access → Add New Database User). Create two, both
   with *Password* authentication and **Autogenerate Secure Password**. Copy each password
   into a password manager now.

   | User | Database User Privileges → *Specific Privileges* | Used by |
   |---|---|---|
   | `netmap_app` | `readWrite` on database `netmap` | the backend (`MONGODB_URI`) |
   | `netmap_ai_ro` | `read` on database `netmap` | Ask NetMap only (`AI_MONGODB_URI`) |

   Don't give either user *Atlas admin* or *readWriteAnyDatabase*. If the app is broken
   into, `netmap_app` can still reach only the `netmap` database. Ask NetMap's queries run as
   `netmap_ai_ro`, which can't write at all (CLAUDE.md 7.8 and 7.9).
4. **Connection strings** (Database → Connect → Drivers → Python). Copy the
   `mongodb+srv://` string twice: once with `netmap_app` and its password, once with
   `netmap_ai_ro`.
   - `mongodb+srv://` uses TLS automatically. The backend refuses to start in production
     with an unencrypted connection string.
   - Don't add a database name to the string; `MONGODB_DB=netmap` sets it.
   - Generated passwords contain only letters and digits. If you chose your own, URL-encode
     `@ : / ? # %`.
5. **Network Access** comes in step 4, once Render shows its outbound addresses. Until then
   the allowlist is empty, so nobody can connect. **Never add `0.0.0.0/0`.**

## 2. Keys and the first admin password

In PowerShell, in the project folder (the backend venv has `cryptography`):
```powershell
backend\.venv\Scripts\python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
backend\.venv\Scripts\python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
backend\.venv\Scripts\python -c "import secrets; print(secrets.token_urlsafe(18))"
```
- The first line is `AGENT_KEY_ENCRYPTION_KEY`.
- The second is `MFA_ENCRYPTION_KEY`. It must be a different key.
- The third is `ADMIN_PASSWORD`, used once.

Put all three in your password manager. Losing a Fernet key means re-creating every agent
key, or resetting every user's MFA. They are never committed; `render.yaml` only lists their
names.

## 3. Render: create the service from the Blueprint

1. Push the code to GitHub. Run the [checklist](#pre-deployment-checklist) first, because
   the repository is public.
2. Sign up at https://render.com with GitHub. Then: **New → Blueprint** → choose the
   `NETTOOL` repository → Render reads `render.yaml` and shows one service, `netmap`.
3. Render asks for every `sync: false` value:

   | Variable | Value |
   |---|---|
   | `MONGODB_URI` | the `netmap_app` connection string |
   | `AI_MONGODB_URI` | the `netmap_ai_ro` connection string |
   | `AGENT_KEY_ENCRYPTION_KEY`, `MFA_ENCRYPTION_KEY` | the two keys from step 2 |
   | `ADMIN_USERNAME` | e.g. `admin` (lower case, 3–32 characters) |
   | `ADMIN_PASSWORD` | the password from step 2 |
   | `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | optional: leave empty, or see README "Notifications" |
   | `LLM_API_KEY` | optional: leave empty (`LLM_PROVIDER` is `none`) |

   Render asks for these **only when the Blueprint is first created**. To add or change one
   later, use the service's **Environment** page in the dashboard; saving there redeploys.
4. Click **Apply**. The first build runs:
   - `node --version` (should print v24.22.1)
   - `pip install`
   - `npm ci`
   - `vite build`

   The deploy will then **fail its health check**: `/health` answers 503 because Atlas
   doesn't allow Render in yet. That is expected; step 4 fixes it.

## 4. Allow Render into Atlas

1. In Render, open the `netmap` service → **Connect** (top right) → **Outbound**. It lists
   the address ranges this region uses for outgoing connections.
2. In Atlas, go to Security → Network Access → **Add IP Address**. Add each range exactly as
   shown, with the comment `Render singapore`.
3. In Render: **Manual Deploy → Deploy latest commit**. When it says *Live*, open
   `https://<service>.onrender.com/health`. Expected: `{"status":"ok","database":"ok"}`.

**Why this isn't `0.0.0.0/0`:** an open allowlist lets anyone on the internet try passwords
against your cluster. Render's ranges are shared by every Render service in Singapore, so the
database password is still what keeps other Render customers out. The allowlist cuts the
attack surface from the whole internet down to one cloud region.

## 5. First sign-in

1. Open `https://<service>.onrender.com` and sign in with `ADMIN_USERNAME` and
   `ADMIN_PASSWORD`.
2. Choose a new password of 12 characters or more.
3. Set up two-step sign-in: scan the QR code, type the code, and **save the 10 recovery
   codes**.
4. In Render → Environment, **delete `ADMIN_USERNAME` and `ADMIN_PASSWORD`**, then save; this
   redeploys. They are only read when the database has no users, but there is no reason to
   keep a password in the environment.
5. **Check that the real client IP is seen.**
   - Open `https://<service>.onrender.com/api/admin/request-info` while signed in as admin.
   - `client_ip` must be your own public IP (compare with https://ifconfig.me), and
     `chosen_by` must be `forwarded`.
   - If not, Render's proxy chain has changed: count the entries in `forwarded_for` and
     update `TRUSTED_PROXY_HOPS`.
   - Without this check, the sign-in rate limit and the audit log could use the wrong
     address. `docs/SECURITY.md` explains why we don't trust the leftmost entry.
6. Create the other users (Admin → Users), each with a temporary password.

## 6. Run the agent against the cloud

On the laptop or PC that can reach the lab (or runs the simulation):
1. In NetMap: **Admin → Agents → New agent**, then copy the key. It is shown once.
2. In `agent\.env`:
   ```
   API_URL=https://<service>.onrender.com
   AGENT_ID=agt_...
   AGENT_KEY=<the key>
   ALLOW_INSECURE_LOCAL=false
   ```
   The agent refuses `http://` for anything except localhost. Its device credentials stay
   in its encrypted store and are never sent to Render.
3. **With the simulation** (no lab), in two terminals in `agent`:
   ```powershell
   python -m simulation.run_simulation
   python -m netmap_agent.main            # keeps running; --once for a single cycle
   ```
   **With the GNS3 lab:** set `SCAN_RANGES`, `SNMP_TARGETS` and the SNMPv3 settings as in
   README §3.
4. Within a minute, the devices, subnets and topology appear in the dashboard.

## 7. Before a demo: the free tier sleeps

- Render stops a free service after **15 minutes without traffic**. The next request waits
  **about a minute** while it starts again.
- **2–3 minutes before a demo**, open `https://<service>.onrender.com/health` and wait for
  `ok`. Or simply start the agent: it reports every few minutes, which keeps the service
  awake. Its uploads retry for about 2 minutes, so a cold start doesn't lose a report.
- Render grants **750 free instance hours per month** per workspace. That is enough for
  this one service running all month, even if the agent keeps it awake.
- Render may restart a free service at any time. Sessions live in MongoDB, so users stay
  signed in.

## 8. Day-to-day

- **Updating:** push to `main`. Render rebuilds automatically when files under `backend/`,
  `frontend/`, `templates/` or `render.yaml` change (`buildFilter`). Changes to the agent or
  the docs don't redeploy.
- **Logs:** Render → service → Logs. Errors show a request ID; the user sees only that ID,
  never a stack trace.
- **Locked-out last admin:**
  1. In Atlas, add your own IP as a **temporary** Network Access entry (6 hours).
  2. In a PowerShell window, set the connection string for that session only, so it never
     lands in a file:
     ```powershell
     $env:MONGODB_URI = "<netmap_app connection string>"
     backend\.venv\Scripts\python backend\scripts\reset_mfa.py admin
     Remove-Item Env:MONGODB_URI
     ```
- **Backups:** Atlas M0 has no automatic backups. Before risky changes, export with
  `mongodump --uri "<connection string>" --out backup-YYYY-MM-DD` (MongoDB Database Tools,
  free), and keep the folder out of git.
- **Rotating a key:** set the variable to `new-key,old-key` (the first key encrypts, all of
  them decrypt). Once nothing uses the old key, remove it:
  - agent keys: after you re-create the agent keys
  - MFA: after users re-enrol

## 9. Troubleshooting

| What you see | Likely cause | Fix |
|---|---|---|
| Build fails in `npm ci` or `vite build` | Node too old | Check the `node --version` line; `NODE_VERSION` in render.yaml should be 24.22.1 |
| Build fails in `pip install` | Python version | `PYTHON_VERSION` must be a full version (3.10.22) |
| Deploy fails: `MONGODB_URI must be set` / `must use TLS` | A missing or plain `mongodb://` string | Paste the `mongodb+srv://` string in Environment |
| Deploy fails: `No frontend build` | `npm run build` was skipped or failed | Read the build log above that line |
| `/health` is 503 | Atlas doesn't allow Render, or a wrong password | Step 4; check the user and password in the string |
| Signing in loops back to the sign-in page | The site was opened over `http://` | Use `https://`: the cookie is `Secure` |
| E-mail alerts never arrive | Render's free plan blocks SMTP ports 25, 465 and 587 | Use Telegram (README "Notifications") |
| Ask NetMap says it is turned off | `AI_MONGODB_URI` missing | Add the `netmap_ai_ro` string (Atlas step 3) |
| Agent: `401` on every request | Wrong `AGENT_ID` or key, a revoked agent, or a PC clock more than 5 minutes off | Check the audit log, `agent.auth` entries (the reason is recorded) |

## Pre-deployment checklist

Run this before the first deployment and before each one after it:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\security-check.ps1 -Release
```

| Check | How it is checked |
|---|---|
| All tests pass (backend, agent, frontend) and the frontend builds | the script runs every suite |
| ruff and Bandit are clean (backend, agent, scripts) | the script |
| No new pip-audit or npm audit findings | the script. Only the findings accepted in `known-limitations.md` may appear (dnspython, Pillow) |
| No secret anywhere in git history (the repo is public) | `scripts/scan_git_history.py`: every line ever added, on every branch |
| `render.yaml` has no literal secret, `ENV=production`, free plan, safe proxy handling | `scripts/check_render_yaml.py` |
| Everything is committed | the clean-tree check |
| Debug off | `ENV=production` turns off `/docs` and `/openapi.json`, and the error pages show only a request ID |
| After the deploy | `/health` ok; `request-info` shows your IP; HSTS header present (`curl.exe -sI https://<service>.onrender.com/`); `/docs` → 404 |

Measured before the first deployment:
- **Memory:** about 80 MB after start-up and a full sign-in, and about 110 MB once the first
  configuration check has loaded ciscoconfparse2. The free plan has 512 MB. These are
  Windows numbers; Render's Linux will be similar.
