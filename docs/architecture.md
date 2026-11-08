# Architecture

```
 PRIVATE NETWORK (GNS3 lab / company LAN)            CLOUD (free tier)
 Devices ◄─ ping/SNMP/SSH ─ NetMap Agent ──HTTPS──►  FastAPI backend (Render web service)
                            (Python, runs inside      │  also serves the React build
                             the network)             ▼
                                                     MongoDB (local in dev, Atlas in prod)
```

## Why it is split this way
- **The agent sits inside the network** because SNMP, ping and SSH can only reach private
  addresses from inside. It makes **outbound** HTTPS connections only, so nobody has to open a
  firewall port into the company network.
- **Device credentials never leave the agent.** If the cloud backend or database leaked, an
  attacker would still not get SSH passwords or SNMPv3 keys.
- **The backend is light** (Render free tier: 512 MB RAM, sleeps when idle). Heavy or scheduled
  work (polling, AI training) runs on the agent.
- **Same origin:** in production FastAPI serves the built React app, so the browser only talks
  to one origin. Session cookies can then be `SameSite=Strict` and no CORS is needed. In
  development the Vite dev server proxies `/api` and `/health` to FastAPI to behave the same way.

## What exists after Phase 0
| Part | Built |
|---|---|
| `backend/app/main.py` | App factory, lifespan (connect + create indexes), `GET /health`, docs off in production |
| `backend/app/config.py` | Settings from env; the MongoDB URI is a `SecretStr` so it never prints |
| `backend/app/db.py` | `AsyncMongoClient` (`tz_aware=True`), all indexes from CLAUDE.md §6 |
| `agent/netmap_agent/config.py` | Agent settings; CIDR ranges validated; keys are `SecretStr` |
| `frontend/` | App shell, light/dark theme tokens, Overview page polling `/health` |

## Added in Phase 1
Accounts, roles, server-side sessions, CSRF protection, login rate limiting and lockout,
security headers, the audit log, admin user management, and agent keys with HMAC-signed
requests. Design and reasoning: `docs/auth-design.md`.

## Added in Phase 2: discovery
```
 agent cycle (every POLL_INTERVAL_SECONDS, never overlapping)
  1. GET  /api/agent/known-devices      which devices this agent already polls
  2. ping sweep                         OS ping, 32 at a time, IPs validated first
  3. SNMP poll                          pysnmp asyncio, 16 devices at a time, SNMPv3 authPriv
  4. POST /api/agent/report             one signed JSON report (max 10 MB)
                                        retried with backoff on 429/5xx/connection errors
 backend
  5. validate the whole report          strict models: list caps, IP/MAC/OID patterns
  6. bulk upserts                       devices, interfaces, subnets, ip_addresses, arp_entries
  7. audit "agent.report"               counts only, not the network's contents
```

**What the agent reads over SNMP** (numeric OIDs, no MIB files):
| Data | Table | Older fallback |
|---|---|---|
| name, description, location, vendor, uptime | SNMPv2-MIB system group | |
| interfaces | IF-MIB ifTable + ifXTable | |
| IPv4 + IPv6 addresses with prefix length | IP-MIB ipAddressTable | ipAddrTable (IPv4) |
| ARP + IPv6 neighbours | IP-MIB ipNetToPhysicalTable | ipNetToMediaTable (IPv4) |

The vendor comes from the IANA enterprise number inside `sysObjectID` (9 Cisco, 14988
MikroTik, ...).

**How the backend stores it.** Every write is an upsert on a unique key, so a repeated report
never creates duplicates:
| Collection | Key | Notes |
|---|---|---|
| devices | `mgmt_ip` | `status` is `up` (SNMP answered), `snmp_error` (ping only) or `down`; `status_changed_at`; `snmp_v2c` flags clear-text SNMP |
| interfaces | `(device_id, if_index)` | rows the device no longer reports are removed |
| subnets | `network` | created from interface prefixes with `$setOnInsert` only, so a subnet edited by hand is never overwritten; `/32` and `/128` are skipped |
| ip_addresses | `ip_key` | `sources`: `interface`, `arp`, `ping`; a silent ping never creates a record |
| arp_entries | `(ip_key, mac, device_id)` | one row per IP+MAC pair, so two MACs on one IP stay visible for duplicate-IP detection (Phase 3) |

Only things that answer SNMP become devices. A PC that only answers ping is an `ip_addresses`
record.

**Windows event loop.** The agent runs asyncio on the selector loop on Windows. With Python
3.10's default proactor loop, one target replying "port unreachable" stopped the shared SNMP
socket, and every other device in the cycle timed out. The end-to-end run found this, and a
regression test now covers it.

## Added in Phase 3: IP address management
Code: `services/ipam.py` (maths and rules), `services/alerts.py` (alert lifecycle),
`api/subnets.py`, `api/ips.py`, `api/alerts.py`, `models/ipam.py`.

**Storing addresses so MongoDB can sort and range-query them.** MongoDB has no IP type, so
every address is stored as `ip_key = "<version>:<32 hex digits>"`, e.g. `10.0.0.1` →
`4:0000…0a000001`. Fixed-width hex sorts as text in the same order as the numbers, so "every
IP in 10.10.10.0/24" is one index range scan (`ip_key` between the network key and the
broadcast key). It works the same for IPv6, and IPv4 always sorts before IPv6. Each subnet also
stores `start_key` / `end_key`.

**Usage maths.** All arithmetic uses Python integers, which are exact even for IPv6.
| Subnet | Usable addresses |
|---|---|
| IPv4 /0–/30 | all except the network and broadcast address |
| IPv4 /31, /32 | all (point-to-point, RFC 3021) |
| IPv6 | all except the subnet-router anycast address (`::0` of the prefix, RFC 4291); there is no broadcast |

An address counts as **used** if it is reserved or was seen (interface, ARP or ping) in the
last `IP_STALE_DAYS`. Older ones show as `stale` and count as free. Sizes go to the browser as
strings: a /64 holds 2^64 addresses, far beyond JavaScript's safe integer range (2^53).

**Overlap detection.** Two ranges overlap when `a.start <= b.end` and `a.end >= b.start`. With
the stored keys that is one indexed query (`version`, `start_key`, `end_key`). A new manual
subnet that overlaps any existing one (manual or discovered) is refused with 409. CIDR blocks
can't overlap partially: one either contains the other or they are disjoint.

**Next free IP.** Walk the sorted list of taken things (gateway, reserved ranges, used IPs)
and return the first gap. The cost depends on how many addresses are taken, not on the
subnet size, so a /64 answers instantly.

**Reservations can't be duplicated.** A reservation is refused when the IP is outside every
known subnet, is the network/broadcast/anycast address, is the gateway, is already reserved,
or was seen recently. Two requests racing for the same free IP can't both win: the unique
index on `ip_addresses.ip_key` lets only one insert succeed, and reserving a stale record is a
conditional update that matches nothing if the record changed in between. A test fires two
real app instances at the same IP at the same moment.

**Search.** `q` is classified by parsing: an IP, a CIDR, a MAC (colon, dash, Cisco dotted or
bare hex), or else a host-name fragment. The query is built from the parsed value, never from
the raw text. Host-name text is limited to safe characters and `re.escape`d, so `.*` or `$ne`
can't widen a query.

**Alerts with a stable key.** One problem = one alert document, guaranteed by the unique
`alerts.key` index:
| Alert | Key | Opens when | Resolves when |
|---|---|---|---|
| duplicate IP (critical) | `duplicate_ip:<ip_key>` | `arp_entries` shows 2+ different MACs for one IP within `DUPLICATE_IP_WINDOW_MINUTES` | only one MAC is left in the window |
| subnet usage (warning; critical at 95 %) | `subnet_usage:<network>` | used ≥ `SUBNET_USAGE_ALERT_PERCENT` | used < threshold − 5 (hysteresis, so it doesn't flap at 80 %) |

A problem that comes back reopens the same alert and counts `occurrences`. Point-to-point
subnets (fewer than 6 usable addresses) are full by design and never alert. Render has no
background scheduler, so the checks run whenever new data arrives: after every agent report
and after every IPAM change.

**Audit.** `subnet.create` / `subnet.update` / `subnet.delete`, `ip.reserve` and `ip.release`
are recorded, including refused attempts with the reason (`overlap`, `in_use`, `gateway`, ...).

## Added in Phase 4: the dashboard
Code: `frontend/src/` (React 19, React Router 7, plain CSS with the tokens in
`styles/tokens.css`), plus backend routes for devices, alert actions, the dashboard summary and
serving the build (`backend/app/frontend.py`).

```
 browser ──same origin──► FastAPI
   │  /assets/*   hashed JS/CSS/fonts (cached 1 year)
   │  /api/*      JSON API (session cookie + X-CSRF-Token on writes)
   │  /health
   └  anything else → index.html (React Router decides the page)
```

**How the browser side stays safe**
| Rule | Where |
|---|---|
| Session only in the httpOnly cookie; JavaScript can't read it | backend `security/sessions.py` |
| CSRF token kept in a module variable (memory), sent as `X-CSRF-Token` on POST/PATCH/DELETE; never in localStorage | `src/api/client.js` |
| 401 anywhere → token dropped, login page with "session expired" | `client.js` + `auth/AuthProvider.jsx` |
| 403 `password_change_required` → forced change screen, nothing else reachable | `App.jsx` |
| No `dangerouslySetInnerHTML`; device names, sysDescr, alert messages and audit details are plain text | all pages; a test renders `<img onerror>` text |
| Strict CSP (`'self'` only, no inline scripts or styles): usage bars are native `<meter>`, Vite never inlines assets as `data:` URIs | `components/ui.jsx`, `vite.config.js` |
| Role-based hiding is cosmetic; the server enforces | `auth/permissions.js` mirrors `require_role(...)` |
| IPv6 counts arrive as strings and are formatted with `BigInt`, never `Number` | `src/format.js` |

The agent key dialog can't be closed with Escape or a close button: the admin has to tick
"I have stored the key safely". The key exists only in React state while the dialog is open.

**New backend routes**: `GET /api/devices` (search by name, IP, subnet, vendor or location;
filters built from parsed values, text `re.escape`d), `GET /api/devices/{id}` (interfaces and
addresses), `POST /api/alerts/{id}/acknowledge|resolve` (engineer+, audit-logged, atomic
"only if still open" update), `GET /api/dashboard/summary` (one request feeds both the
dashboard and the top bar's alert counter). A manually resolved alert whose problem still
exists reopens at the next check, with the acknowledgement cleared.

**Browser check.** The built app was driven in headless Edge (DevTools protocol) through
login, every page, reserve, overlap error, agent key, user creation, forced password change,
dark mode and phone width, while recording console errors, exceptions and CSP violations. It
caught one real problem: Vite had inlined a small font as a `data:` URI, which the CSP
blocked. Fixed with `assetsInlineLimit: 0` instead of loosening the CSP.

## Added in Phase 5: topology, location and monitoring
```
 agent (each cycle)                                  backend (on each report)
  LLDP-MIB lldpRemTable ─┐                            links ──► topology graph, uplink set
  CISCO-CDP-MIB cache   ─┼─ links ──────────┐         mac_entries ─► "which port is this PC on"
  Q-BRIDGE / BRIDGE FDB ─── mac_table ──────┼─ report mac_addresses ─► new-unknown-MAC alert
  ifHC*Octets, errors   ─── counters ───────┘         interfaces.rates + metrics ─► traffic
                                                      alerts ─► notify (Telegram / e-mail)
```

**Agent** (`discovery/snmp.py`, parsers in `discovery/oids.py`):
- LLDP: `lldpRemTable` (neighbour name, chassis ID, port ID; their subtypes decide whether a
  value is a MAC, an address or text), `lldpRemManAddrTable` (management IP, encoded in the
  index) and `lldpLocPortTable`. LLDP numbers ports its own way, so the local port number is
  mapped to an ifIndex by matching names; ACCESS-SW-2 in the simulation uses different numbers
  on purpose.
- CDP: `cdpCacheTable` (index = ifIndex.deviceIndex; device ID, port, platform, IPv4 address).
- MAC tables: Q-BRIDGE `dot1qTpFdbTable` (VLAN-aware) first, BRIDGE-MIB `dot1dTpFdbTable` as
  the fallback; bridge port numbers are mapped through `dot1dBasePortIfIndex`. The switch's own
  MACs (`self`) and invalid rows are skipped.
- Counters: 64-bit `ifHCInOctets`/`ifHCOutOctets`, or 32-bit `ifInOctets`/`ifOutOctets` on old
  devices, plus error counters. The agent records the exact time it read them.

**Backend**
| Piece | File | What it does |
|---|---|---|
| Links | `services/links.py` | One row per (device, port, protocol, neighbour). The far end is matched to a known device by management IP, then any interface IP, then system name (domain suffix ignored), then chassis MAC. No match = an *external* neighbour, still drawn on the map. A link missing from a report becomes `lost` (a broken line, and its port still counts as an uplink); TTL deletes it after 7 days. |
| Rates | `services/metrics.py` | `(octets now − octets before) × 8 / seconds`. A single 32-bit wrap is corrected; resets (reboot, cleared counters), gaps over 6 h and rates faster than the port are dropped instead of shown as nonsense. History is kept only for uplinks and IP interfaces (7-day TTL), so a 48-port switch doesn't fill the free-tier database. |
| Graph | `services/topology.py` `build_graph` | Nodes = devices + external neighbours; one edge per cable even though both ends report it; edge is down if either port is down or the link is lost. |
| Locate | `services/topology.py` `locate` | IP → MAC (ARP) → MAC-table sightings. Sightings on **uplinks** are ignored: ports with an LLDP/CDP neighbour, more than one VLAN (a trunk), or more than 10 MACs. The newest remaining sighting is the access port. Network devices are located by their own LLDP/CDP link instead. |
| Alerts | `services/alerts.py` | `device_down` (critical if nothing answers, warning if only SNMP fails), `interface_down` (only uplinks that are enabled but down, so PCs switching off aren't noise), `new_mac` (after the learning window; never auto-resolves; resolving it records who approved the device). |
| Notify | `services/notify.py` | Runs as a FastAPI background task after the report response. Claims each pending alert atomically, sends plain text (Telegram without `parse_mode`; e-mail subject built from fixed words only), applies a 30-minute per-alert cooldown and a 20/hour cap, and records every decision in `notifications`. The bot token is in Telegram's URL, so the httpx loggers are raised to WARNING and errors are recorded by type only. |

**Frontend**: `pages/Topology.jsx` with `components/TopologyCanvas.jsx` (Cytoscape.js 3.34.4,
pinned, loaded only when the page opens). Labels are canvas text, never HTML. Node shapes
repeat status like `StatusMark`, and the same links are listed in a table for screen readers
and keyboard users. Device pages show traffic per interface and the neighbour table; the IP
page fills in the switch-port hop; Admin → Notifications shows channel status and the
delivery log.

**Browser check.** Headless Edge found that Cytoscape injects an inline `<style>` tag, which
the CSP blocked. Instead of allowing inline styles, `index.html` carries an element with the id
Cytoscape looks for (so it skips the injection), and its one rule (`position: relative`) lives
in `pages.css`. After that: no console errors or CSP violations in light, dark or phone layouts.

## Added in Phase 6: config backup, compliance and safe changes
```
 agent (inside the network)                         backend
  credentials.enc (Fernet) ── SSH (Netmiko) ──► device
  show running-config / export
     │ mask secrets, fingerprint ───── POST /api/agent/configs ──► configs (versions, diff)
     │                                                              compliance score + alerts
     │                                                              "unconfigured" flag
  every minute ─────────────────── POST /api/agent/jobs/claim ◄── change_requests (approved,
     │ check signature, expiry, denylist,                         signed at approval)
     │ device unchanged since approval
     │ push with revert timer / safe mode → ping + new SSH login
     │ confirm + save, or revert now ── POST /api/agent/jobs/{id}/status ──► timeline, audit,
                                                                            critical alert
```

**Agent** (`netmap_agent/config_mgmt/`):
| File | What it does |
|---|---|
| `../credential_store.py` | Encrypted login profiles (IP or CIDR match, most specific wins). Key from `CREDENTIAL_STORE_KEY` or a DPAPI-protected key file. Passwords never printed, logged or uploaded. |
| `connection.py` | Netmiko session with session logs off, no SSH agent/keys, optional strict known_hosts. Every library error is turned into a short code (`auth_failed`, `timeout`, `host_key_rejected`, `ssh_error`) so no device output leaks into logs. |
| `backup.py` | Reads the config (max 1 MB) and drops volatile lines (timestamps, byte counts). Fingerprint = **HMAC-SHA256(agent key, config)**. A plain SHA-256 of a config with a weak password could be brute-forced offline from the database; an HMAC can't without the agent key. It still changes when only a password changes. |
| `masking.py` | Replaces the value on every password / secret / community / key line with `<masked>` and keeps the type number (`secret 9 <masked>`) so compliance can still judge it. |
| `facts.py` | The one check that needs a secret (is the SNMP community `public`/`private`?) runs here, before masking, and is sent as `true`/`false`. |
| `denylist.py` | Blocks `reload`, `erase`, `write erase`, `delete`, `format`, `no username`, `crypto key zeroize`, RouterOS reset/remove commands, and anything but description/`no shutdown`/adding trunk VLANs on the management and uplink interfaces. Understands IOS abbreviations (`wr er`), `do`, `interface range` and indentation. Rejects control characters and RouterOS scripting. |
| `jobsign.py` | Verifies the backend's HMAC over the job (see below). |
| `push.py` | Cisco: `configure terminal revert timer 5` → commands → ping + new SSH login → `configure confirm` + `write memory`, or `configure revert now` and a check that the fingerprint is back to the original. MikroTik: the same idea with safe mode. |
| `runner.py` | Backup cycle (4 devices in parallel) and job cycle (one at a time). |

`masking.py`, `denylist.py` and `jobsign.py` are **byte-identical copies** in
`backend/app/config_mgmt/`; a backend test fails if they drift. So the backend and the agent
apply exactly the same rules, and the backend re-masks every upload (defence in depth).

**Backend**
| Piece | File | What it does |
|---|---|---|
| Versions | `services/configs.py` | Re-mask, store as the next version (unique `(device_id, version)`), keep 50, side-by-side diff rows from `difflib`. A new version not caused by a NetMap change raises `config_changed` (info). |
| Compliance | `services/compliance.py` | ciscoconfparse2 over the masked text (imported only when needed: about 38 MB). IOS: Telnet on vty, no password encryption, default SNMP community, SNMP v1/v2c, no SSH v2, no banner, no exec-timeout, unused ports not shut, access ports without port security. RouterOS: insecure services, default community, weak SSH crypto. Score = 100 − weights. Below 70, or 10 points lower than last time, opens a `compliance` warning. |
| Unconfigured | `services/configs.py` | Default host name, no VLANs besides 1, no static management IP, no default gateway. Routers (an IP on a routed port) are exempt from the VLAN and gateway checks. Works from SNMP data alone until the first backup. |
| Templates | `config_mgmt/templates.py` + `templates/*/*.j2` | Jinja2 `SandboxedEnvironment` + `StrictUndefined`. Each template has a Pydantic model (`extra="forbid"`, regex host names, VLAN 2–4094, IPs parsed with `ipaddress`, no newlines in text). The UI form is generated from the same model's JSON schema. |
| Changes | `services/changes.py`, `api/changes.py` | State machine with atomic transitions (`find_one_and_update` on the expected state). Four-eyes approval. The denylist runs at preview, submit and approve. Changes with secrets are refused. |

**Job signing.** At approval the backend decrypts the agent's key and signs the job:
HMAC-SHA256 over change id, device, management IP, vendor, the exact commands and their
SHA-256, the config fingerprint it was approved against, the protected interfaces and the
expiry time. The agent checks the signature first. An attacker who can only write to the
database (stolen Atlas password) can't change the commands of an approved job, or approve a
job themselves, without the agent key. The end-to-end run shows this: a job edited in MongoDB
was refused with `bad_signature` before the agent connected to anything.

**Frontend**: `Configuration` (scores, backups, unconfigured devices), `DeviceConfig`
(findings with "Create change from fix", version list, masked text, side-by-side diff that
scrolls inside its own box on phones), `Changes`, `ChangeNew` (template form generated from the
JSON schema, or raw commands; dry-run preview) and `ChangeDetail` (commands, approval, agent
log, timeline). Config text is always rendered as text, never HTML.

## Added in Phase 7: AI
```
 agent (every 6 h, or --ai-only)                         backend (light: stores and serves)
  GET /api/agent/ai/training-data ◄──────────────────── subnet_usage (1 point/subnet/day,
     │ subnet history, 7 d uplink metrics, endpoint MACs     written on every report),
     │                                                     metrics, mac_entries, devices
  forecast.py  Prophet / straight line ── POST /predictions ──► predictions (+ dashboard card)
  anomaly.py   IsolationForest ────────── POST /anomalies ───► traffic_anomaly alerts
  classify.py  OUI + SNMP + names (+ports)─ POST /classifications ► mac_addresses.classification

 browser ── POST /api/ai/ask ──► rules.py ──(no match)──► LLM (question + schema only)
                                     └──── proposal ────┘
                                               ▼
                                   query_guard.validate()  ── refused → 422 + the refused query
                                               ▼
                                   aggregate on the read-only client (AI_MONGODB_URI),
                                   $project allowlist first, $limit 100, maxTimeMS 3000
 browser ── POST /api/ai/explain ─► facts built by the server, secret lines dropped,
                                    fenced as untrusted ─► LLM or built-in template (cached)
```

**Why the heavy part is on the agent.** Prophet with its Stan backend and scikit-learn need a
few hundred MB and seconds of CPU per model; Render's free web service has 512 MB and no
scheduler. The agent already runs on a schedule inside the network, so it trains there and
uploads only small results. The backend never imports pandas, numpy, Prophet or scikit-learn.

**Agent** (`netmap_agent/ai_training/`):
| File | What it does |
|---|---|
| `forecast.py` | Subnet exhaustion from daily "used" counts: Prophet (weekly pattern, no yearly) with ≥14 days, linear regression with 3–13 days. Returns the day it reaches 80 % and 100 %, growth per day, and a 90-day series with an 80 % likely range. Uplinks: hourly mean of max(in, out), 7-day forecast, first hour above 80 % of port speed. Each fit has a 60 s cap and falls back to the straight line on any error. |
| `anomaly.py` | IsolationForest per interface on log(in), log(out), error rate and hour of day (sin/cos). Needs ≥288 points (a day). Fitted on all points with `max_samples=1.0`: with sub-sampling, a single outlier is missing from most trees and isn't isolated. A flag also needs a real difference (≥3× and ≥1 Mbit/s, or ≥1 error/s), so the model's "1 % contamination" can't raise alerts on a quiet network. The explanation compares the value with the median and 5–95 % range for the same hour. |
| `classify.py` | Weighted rules, each with a reason: MAC vendor (OUI), managed-device SNMP data, subnet/port names ("Printers", "Cameras"), Wi-Fi ports, randomised MACs, and (opt-in) open ports. Highest score wins if ≥1.5, else "unknown". Explainable, needs no training data. |
| `oui.py` | Built-in prefixes for common vendors; optional IEEE MA-L download over HTTPS (20 MB cap). |
| `probe.py` | Opt-in TCP connect to 8 ports, IPv4 inside `SCAN_RANGES` only, at most 256 hosts, 32 at a time. |
| `runner.py` | Fetch → the three steps, each independent (one failing doesn't stop the others) → upload. |

**Backend**
| Piece | File | What it does |
|---|---|---|
| Usage history | `services/alerts.py` `record_usage` | On every IPAM check: one `subnet_usage` row per subnet per day (`$max` of the day). /30s and /64s are skipped (full by design / never full). |
| Agent routes | `api/agent_ai.py` | Scoped to the agent: its devices, subnets holding its devices' addresses, MACs its switches saw. An upload replaces that agent's previous forecasts. Manual device types are never overwritten. |
| Query guard | `ai/query_guard.py` | Deny-by-default allowlist: 9 collections, a field list per collection, stages `$match $project $sort $limit $count $group`, a few operators, regex ≤64 chars without nested quantifiers, depth/size/stage limits. |
| Question parser | `ai/rules.py` | Regex rules for the common questions; its output goes through the same guard. |
| Ask NetMap | `ai/nlsearch.py` | Rules → (LLM) → guard → typed values (ISO text → dates, hex → ObjectId) → `aggregate` on `app.state.ai_db` → table. |
| LLM providers | `ai/llm.py` | Gemini, Groq, Ollama over plain httpx (no SDKs). Key in a header, never in a URL; response bodies never logged. |
| Explanations | `ai/explain.py` | Server-built facts, `secret_free()` drops every line with `<masked>` or a secret word, data fence, 1200-character cap, built-in templates, cache by input hash. |
| Routes | `api/ai.py`, `api/predictions.py` | Ask / explain / status, forecasts, type correction; per-user rate limit in `ai_calls`. |

**Frontend**: `ForecastChart` (plain SVG, CSS classes only, table fallback), forecast panels
on subnet and device pages, "Running out of addresses" on the dashboard, the Ask NetMap page
and top-bar box, Explain buttons on alerts, findings and diffs, and type badges with an
engineer-only "Correct type" control. AI text and query results are rendered as text only.

## Added in Phase 8: security hardening
```
 browser ── POST /api/auth/login ──► password OK + MFA on? ── no ──► session cookie
                                          │ yes
                                          ▼
                         mfa_challenges (5 min TTL) + cookie netmap_mfa (Path=/api/auth/mfa)
 browser ── POST /api/auth/mfa/verify {code | recovery_code}
              └► step newer than users.mfa.last_step (atomic) ──► challenge deleted, session

 failed agent signature / rate-limited login ─► security_events (kind, ip, 10-min window)
     count ≤ 20 → audit entry · 21 → one "suppressed" entry · threshold → `security` alert
```

| Part | Where | What |
|---|---|---|
| TOTP | `security/mfa.py` | secrets (Fernet, `MFA_ENCRYPTION_KEY`), codes with replay check, SHA-256 recovery codes, QR code as 0/1 rows (segno) |
| Routes | `api/mfa.py`, `api/auth.py`, `api/users.py` | code step, setup, enable, recovery codes, disable (not admins), admin reset |
| Enforcement | `security/rbac.py` | `mfa_setup_required` blocks admins without MFA on every role-checked route; `mfa_challenge` is a new access marker |
| Security alerts | `services/security_events.py` | bounded audit for unauthenticated failures, `security` alerts |
| Ask NetMap | `api/ai.py` | refuses in production without the read-only database user |
| Scripts | `backend/scripts/reset_mfa.py`, `backend/scripts/demo_agent_request.py`, `scripts/security-check.ps1` | last-admin recovery, replay demo, all scanners and tests |

**Frontend**: the sign-in code step (with a recovery-code option), the forced setup screen
for admins (QR drawn as SVG squares, recovery codes shown once), *Two-step* account page,
MFA column and *Reset MFA* on Admin → Users, a low-recovery-codes banner, and the *Security*
alert type.

## Added in Phase 9: deployment
```
 GitHub (public) ──push──► Render Blueprint (render.yaml): one free web service, Singapore
   build:  pip install backend/requirements.txt → npm ci → vite build (frontend/dist)
   start:  uvicorn --no-proxy-headers --no-server-header, ENV=production
 client ─► Cloudflare ─► Render proxy (10.x) ─► app: X-Forwarded-For "<forged…>, client, cf"
                                                    client_ip = 2nd entry from the right
 app ── mongodb+srv:// (TLS) ──► Atlas M0 Singapore: netmap_app (readWrite), netmap_ai_ro (read)
```

| Part | Where | What |
|---|---|---|
| Blueprint | `render.yaml` | one free service, `buildFilter`, secrets as `sync: false` |
| Client IP | `security/client_ip.py`, `services/audit.py` | `TRUSTED_PROXY_HOPS`, counted from the right, peer must be private |
| Diagnostics | `api/request_info.py` | `GET /api/admin/request-info` (admin) |
| Production checks | `config.py` | `MONGODB_URI` must be set and use TLS; the frontend build must exist |
| SPA fallback | `frontend.py` | `/docs`, `/redoc`, `/openapi.json` stay 404 |
| Release checks | `scripts/scan_git_history.py`, `scripts/check_render_yaml.py`, `security-check.ps1 -Release` | secrets in history, secrets in render.yaml |

## MongoDB indexes
| Collection | Index | Why |
|---|---|---|
| subnet_usage | `(subnet_id, day)` unique, `at` TTL (400 days) | one point per subnet per day; a year of history for forecasts |
| predictions | `(kind, target_key)` unique, `generated_at` TTL (14 days) | one forecast per subnet / uplink; forecasts from a stopped agent disappear |
| ai_explanations | `key` unique, `at` TTL (30 days) | cache: the same alert isn't sent to the model twice |
| ai_calls | `(user_id, at)`, `at` TTL (10 minutes) | per-user AI rate limit |
| mfa_challenges | `token_hash` unique, `expires_at` TTL | half-finished MFA sign-ins vanish after 5 minutes |
| security_events | `(kind, ip, window)` unique, `at` TTL (1 day) | one failure counter per source and 10-minute window |
| devices | `mgmt_ip` unique, `status`, `(agent_id, mgmt_ip_key)` | one record per managed device; status filters; known-devices list |
| interfaces | `(device_id, if_index)` unique, `mac` | one row per interface; LLDP chassis-ID matching and "is this MAC a known device?" |
| ip_addresses | `ip_key` unique, `mac`, `reservation.hostname` (sparse), `device_id` (sparse) | the database itself refuses a duplicate IP record or reservation; IP-by-MAC and host-name lookups |
| arp_entries | `(ip_key, mac, device_id)` unique, `mac`, `last_seen` | duplicate-IP detection, newest first |
| subnets | `network` unique, `(version, start_key, end_key)` | no duplicate subnets; overlap and "which subnet holds this IP" lookups |
| alerts | `key` unique, `(status, type, last_seen)`, `notify_pending` (sparse) | the same alert is updated, not re-created; open-alert lists; notification queue |
| users | `username` unique | |
| sessions | `token_hash` unique, `expires_at` TTL (0 s) | sessions vanish when they expire |
| metrics | `ts` TTL (7 days), `(device_id, if_index, ts)` | keeps the free-tier database small; per-interface history |
| links | `(device_id, protocol, if_index, remote_key)` unique, `remote_device_id`, `last_seen` TTL (7 days) | one row per neighbour per port; lost links expire |
| mac_entries | `(device_id, if_index, mac, vlan)` unique, `(mac, last_seen)`, `last_seen` TTL (7 days) | where a MAC is now; old sightings expire |
| mac_addresses | `mac` unique, `first_seen`, `pending_check` (sparse) | every MAC ever seen: "never seen before" means not in here |
| notifications | `(alert_key, at)`, `(status, at)`, `at` TTL (7 days) | cooldown, hourly cap, delivery log |
| configs | `(device_id, version)` unique | one row per version; the app prunes to 50 per device (no TTL: a device that never changes keeps its only backup) |
| change_requests | `(agent_id, status, approved_at)`, `(device_id, created_at)`, `(status, created_at)` | the agent's job queue, oldest approved first; per-device and per-status lists |
| login_attempts | `(ip, at)`, `at` TTL | per-IP login rate limit that survives restarts |
| agent_nonces | `(agent_id, nonce)` unique, TTL 10 min | replay protection: a nonce works once |
| audit_log | `at`, `(action, at)`, `(actor.username, at)` | fast newest-first and filtered reads |

## Frontend design notes
- Concept: a patch panel. Cool neutral surfaces, so status colours are the only loud thing.
- Status is shown by **shape and colour** (up = filled circle, down = hollow square,
  warning = triangle), so it never depends on colour alone.
- Fonts are bundled (Atkinson Hyperlegible Next for the UI, JetBrains Mono for addresses only)
  so a strict `Content-Security-Policy: default-src 'self'` works.
- Theme follows the OS until the user picks one. Only that preference is stored in
  localStorage, never tokens.
