# NetMap – Claude Code prompts, phase by phase

## How to use these prompts
1. Create an empty folder, for example `D:\PROJECTS\netmap`, and open it in Claude Code.
2. Copy `CLAUDE.md` into that folder. Claude Code reads it automatically every session, so every
   prompt below already includes the full project brief and security rules.
3. Run `git init` (or ask Claude Code to do it) and create a private GitHub repository.
4. Paste **one phase prompt at a time**. Wait until the phase is finished and tested.
5. After each phase: test it yourself, read the summary, then commit:
   `git add . && git commit -m "Phase N: ..."`
6. Start a **new Claude Code session for each phase** to keep the context small. CLAUDE.md carries
   the project knowledge between sessions.
7. Run the review prompts at the end of this file after phases 3, 6 and 8.

---

## Phase 0 – Project setup
```
Read CLAUDE.md carefully. We are starting Phase 0: project setup.

Create the folder structure from CLAUDE.md section 4 with:
- backend: Python virtual environment instructions, requirements.txt with pinned versions
  (fastapi, uvicorn, pymongo>=4.13 with AsyncMongoClient, pydantic, pydantic-settings, bcrypt,
  pyjwt or itsdangerous for sessions, httpx, python-dotenv, pytest, ruff, bandit, pip-audit),
  app/main.py with a /health endpoint, app/config.py reading settings from environment,
  app/db.py connecting to MongoDB with tz_aware=True and creating the indexes from CLAUDE.md section 6.
- agent: its own requirements.txt and virtual environment, empty package skeleton.
- frontend: React + Vite project with React Router and plain CSS (CSS variables, light and dark theme).
- .gitignore (Python, Node, .env, .venv, dist, *.log), .env.example files with placeholders only.
- README.md with setup steps for Windows 11 (no Docker), local MongoDB and MongoDB Atlas.

MongoDB must work with both local MongoDB (mongodb://127.0.0.1:27017) and Atlas by changing only
MONGODB_URI. Show me the plan first.

Done when: backend starts with `uvicorn app.main:app --reload`, /health returns ok and confirms the
database connection, the frontend starts with `npm run dev`, and the first tests pass.
```

## Phase 1 – Backend core, authentication and security baseline
```
Read CLAUDE.md. Phase 1: backend core with the security baseline from section 7.

Build:
1. Users with roles admin / engineer / viewer. First admin created from ADMIN_USERNAME and
   ADMIN_PASSWORD env vars only when no users exist, with forced password change on first login.
2. Login / logout / "me" endpoints using httpOnly Secure SameSite=Strict session cookies, stored
   server-side in the sessions collection with TTL, 8h absolute and 30 min idle expiry.
3. bcrypt password hashing, password policy, login rate limiting and account lockout (7.1).
4. RBAC dependency used on every route, deny by default (7.2).
5. CSRF protection for state-changing requests (7.7).
6. Security headers middleware, safe error handler with request IDs, /docs disabled in production.
7. Audit log service and audit entries for auth events (7.10).
8. User management endpoints for admins (create, disable, change role, reset password).
9. Agent registration: admin creates an agent, the API key is shown once and stored as SHA-256 hash;
   revoke endpoint. HMAC request signing verification with timestamp + nonce replay protection (7.3).

Write tests for every security rule listed in CLAUDE.md section 8 that applies to this phase.
Explain the session, CSRF and HMAC design to me in simple words at the end.
```

## Phase 2 – Agent: discovery
```
Read CLAUDE.md. Phase 2: the network agent's discovery features.

Build in agent/:
1. Settings from .env: API_URL, AGENT_ID, AGENT_KEY, SCAN_RANGES (CIDR list), SNMP_TARGETS
   (host[:port] list), SNMP settings (v3 authPriv preferred, v2c allowed for lab with a warning),
   POLL_INTERVAL_SECONDS.
2. Ping sweep using subprocess with argument lists (Windows and Linux ping flags), concurrent with a
   thread pool, IP validation before running (7.4). Limit the sweep size (e.g. max /22 per range).
3. SNMP polling with pysnmp v7 asyncio API: sysName, sysDescr, sysLocation, sysObjectID, uptime,
   IF-MIB interfaces, interface IPv4/IPv6 addresses and prefixes (IP-MIB ipAddressTable with
   ipAddrTable fallback), ARP and IPv6 neighbors (ipNetToPhysicalTable with ipNetToMediaTable fallback).
   Put OID-index parsing in pure functions with unit tests for IPv4 and IPv6.
4. Vendor detection from sysObjectID enterprise numbers (Cisco 9, MikroTik 14988, Juniper 2636,
   Arista 30065, Fortinet 12356, Palo Alto 25461, Net-SNMP 8072, HP 11, Aruba 14823).
5. Uploader: HMAC-signed HTTPS requests (7.3), retries with exponential backoff (Render cold starts),
   refuses http:// except localhost when ALLOW_INSECURE_LOCAL=true.
6. Backend: POST /api/agent/report (agent auth only, strict Pydantic model, size limits) that upserts
   devices, interfaces, subnets, ip_addresses and arp_entries; GET /api/agent/known-devices so the
   agent can re-check known devices and report unreachable ones (device status up/down).
7. Simulation mode: agent/simulation/ with snmpsim data files for a small campus (edge router, core
   switch, two access switches, one AP) with realistic IPv4 + IPv6 interfaces and ARP/neighbor
   entries, plus a script that starts snmpsim on 127.0.0.x addresses. Document how to run it.

Done when: running the agent in simulation mode fills MongoDB with devices, subnets and IPs, and all
tests pass.
```

## Phase 3 – IP address management (IPv4 + IPv6)
```
Read CLAUDE.md. Phase 3: IPAM in the backend.

Build services/ipam.py and API routes:
1. ip_key storage rule from CLAUDE.md section 5, subnet range queries for IPv4 and IPv6.
2. Subnets: list with usage (size, used, free, percent; IPv6 sizes as strings), create/edit/delete
   manual subnets (engineer+), overlap detection when creating a subnet.
3. IP table per subnet and global search (IP, MAC, hostname), with IP → MAC → device → port.
4. Next free IP in a subnet (skip network, broadcast, gateway, reserved ranges).
5. Manual IP reservation that is rejected if the IP is already used or reserved (no duplicates).
6. Duplicate IP detection: same IP seen with different MACs within a configurable time window;
   create and auto-resolve alerts with a stable alert key.
7. "Subnet above 80% full" alerts.
8. Audit log entries for every IPAM change.

Write tests for IPv4 and IPv6 usage maths, overlap detection, duplicate detection, reservation
conflicts, RBAC, and NoSQL-injection attempts in search parameters.
```

## Phase 4 – React dashboard
```
Read CLAUDE.md. Phase 4: the React frontend.

Build with React, Vite, React Router and plain CSS (CSS variables, light and dark theme, responsive
down to phone width):
1. Login page (with forced password change screen), logout, session-expired handling.
2. Layout: sidebar navigation, top bar with user and role, alert counter.
3. Dashboard: device up/down counts, subnet usage summary, duplicate IPs, open alerts, last agent
   check-in; auto-refresh every 30 seconds.
4. Devices: searchable table, status badges, device detail page (interfaces, IPs, location).
5. IP Management: subnets with usage bars, subnet detail with IP table, next free IP button,
   reserve IP form, duplicate IP list.
6. Alerts page with filters and acknowledge/resolve actions.
7. Admin pages: users, agents (create key – show once with a copy button and a warning), audit log.
8. API client that sends the CSRF token, handles 401/403, and never stores tokens in localStorage.
9. Hide actions the user's role cannot perform (the backend still enforces it).
10. FastAPI serves the built frontend from the same origin in production; Vite proxies /api in dev.

Security: no dangerouslySetInnerHTML, all device/log text rendered as text, CSP-compatible
(no inline scripts). Add vitest tests for the API client and key components.
```

## Phase 5 – Topology, location and monitoring
```
Read CLAUDE.md. Phase 5: topology map, device location and monitoring.

1. Agent: collect LLDP-MIB and CISCO-CDP-MIB neighbors, BRIDGE-MIB / Q-BRIDGE-MIB MAC tables and
   interface status; upload links and mac_entries.
2. Backend: build the topology graph (devices = nodes, links = edges), endpoint location
   ("PC with MAC X is on ACCESS-SW1 Gi0/3, VLAN 10"), ignore uplink/trunk ports when locating
   endpoints.
3. Frontend: interactive topology page with Cytoscape.js — green up / red down / yellow warning,
   click a node for details, search a hostname/IP/MAC to highlight where it is connected.
4. Alerts: device down, interface down on uplinks, new unknown MAC (possible rogue device).
5. Notifications: Telegram bot and email (SMTP) with settings in env; never include secrets in
   messages; rate-limit notifications.
6. Metrics: interface traffic counters stored in metrics with a 7-day TTL.
Update the snmpsim data so the topology appears in simulation mode. Add tests.
```

## Phase 6 – Configuration backup, compliance and safe auto-configuration
```
Read CLAUDE.md, especially section 7.5 and 7.6. Phase 6: configuration management.

1. Agent: encrypted local credential store (Fernet) for SSH credentials; credentials never leave
   the agent.
2. Agent: scheduled config backups with Netmiko (Cisco IOS and MikroTik), mask secrets before upload,
   upload only when the config hash changes.
3. Backend + UI: config version history and side-by-side diff.
4. Compliance checks with ciscoconfparse2 (Telnet enabled, no service password-encryption, SNMP
   v1/v2c with public/private, no SSH v2, no login banner, no exec-timeout, unused ports not
   shut down, no port security on access ports), a score per device and a fix suggestion for each issue.
5. Unconfigured device detection (default hostname, no VLANs, no management IP config).
6. Safe auto-configuration flow from 7.5: Jinja2 SandboxedEnvironment + StrictUndefined templates in
   templates/, variables validated by schema, dry-run preview, denylist checks, four-eyes approval,
   agent pulls approved jobs, pushes with revert timer / safe mode, verifies reachability,
   rolls back on failure, full audit trail.
7. UI: change requests page (create, preview, approve/reject, status timeline).

Tests: denylisted commands are blocked on both backend and agent, the creator cannot approve their
own change, secrets are masked, templates with missing variables fail.
```

## Phase 7 – AI features
```
Read CLAUDE.md, especially section 7.9. Phase 7: AI features.

1. Agent: IP exhaustion forecasting per subnet (Prophet, fall back to linear regression when there
   is little data) and bandwidth forecasting per uplink; upload predictions.
2. Agent: traffic anomaly detection with scikit-learn IsolationForest on interface metrics;
   create alerts with an explanation.
3. Agent: device-type classification (PC, printer, phone, camera, AP, network device) using MAC
   vendor (OUI), open ports and SNMP data.
4. Backend: natural-language search ("which switch port is PC-HR-23 on?", "show down APs on floor 2")
   — the LLM produces a restricted query that is validated against an allowlist of collections and
   operators and run with the read-only DB user, with limits and timeout. Provider configurable:
   Gemini or Groq free tier in the cloud, Ollama locally.
5. Plain-language explanations of alerts, compliance issues and config diffs.
6. UI: predictions on subnet and dashboard pages, an "Ask NetMap" search box with the generated
   query visible to the user.

Security tests: prompt-injection text in a device name cannot make the AI run a write query or read
users/sessions/audit_log; secrets are never included in LLM prompts.
```

## Phase 8 – Security hardening and testing
```
Read CLAUDE.md. Phase 8: security hardening. Act as a security reviewer of the whole project.

1. Add TOTP MFA (pyotp) required for admins, with recovery codes stored hashed.
2. Go through every rule in CLAUDE.md section 7 and list each one as PASS / FAIL / PARTIAL with the
   file and line. Fix every FAIL and PARTIAL.
3. Run bandit, pip-audit, npm audit and ruff; fix findings or document why a finding is accepted.
4. Add missing security tests from section 8. Check that every API route has an auth test.
5. Check the agent for command injection, unsafe file handling, and secrets in logs.
6. Write docs/SECURITY.md: threat model (STRIDE) for agent, backend, database and browser, the
   controls used, and known limitations.
7. Write docs/SECURITY_TESTING.md describing how I can manually test login lockout, CSRF, RBAC,
   replay protection and NoSQL injection, so I can demonstrate them in interviews.
```

## Phase 9 – Deploy to Render with MongoDB Atlas
```
Read CLAUDE.md. Phase 9: deployment.

1. Check Render's current documentation for its native Python runtime: whether Node/npm is available
   during the build. If yes, build the React app and serve it from FastAPI in ONE web service
   (same origin). If not, propose the safest alternative and explain the trade-off before doing it.
2. Write render.yaml (free plan, healthCheckPath /health, secrets with sync: false, ENV=production,
   PYTHON_VERSION).
3. Production settings: Secure cookies, HSTS, docs disabled, trusted proxy headers handled correctly
   for client IPs (rate limiting must use the real client IP).
4. Write docs/DEPLOYMENT.md with step-by-step instructions for:
   - MongoDB Atlas free M0 cluster, least-privilege users (netmap_app, netmap_ai_ro), Network Access
     limited to Render's outbound IPs (not 0.0.0.0/0).
   - Render Blueprint deploy from GitHub, entering secrets, first admin login.
   - Creating an agent key and running the agent on my laptop against the GNS3 lab or simulation.
   - Handling the free-tier sleep (cold start) before a demo.
5. A pre-deployment checklist: no secrets in git history, debug off, dependency audits clean,
   all tests passing.
```

---

## Review and fix prompts (use any time)

### Security review
```
Review the code changed in this phase against every rule in CLAUDE.md section 7. List findings by
severity with file and line, explain the risk in simple words, and fix them after I confirm.
```
Claude Code also has a built-in `/security-review` command for the current branch.

### Bug fix
```
Bug: <what you did> → <what you expected> → <what happened>. Error message: <paste>.
Find the root cause first, explain it, then fix it and add a test that would have caught it.
```

### Explain for interviews
```
Explain how <feature> works in this project as if I am answering an interviewer: the problem,
the design, the security decisions, and one limitation. Keep it under 2 minutes of speaking.
```

### Project report
```
Using the code and docs in this repository, write docs/PROJECT_REPORT.md with: abstract, problem
statement with real-world incidents, literature review of existing tools (NetBox, phpIPAM, LibreNMS,
SolarWinds, Cisco Catalyst Center) and the gap, architecture, modules, security design, AI design,
testing results, limitations and future work.
```
