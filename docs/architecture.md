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

## MongoDB indexes
| Collection | Index | Why |
|---|---|---|
| devices | `mgmt_ip` unique, `status`, `(agent_id, mgmt_ip_key)` | one record per managed device; status filters; known-devices list |
| interfaces | `(device_id, if_index)` unique | one row per interface |
| ip_addresses | `ip_key` unique, `mac`, `reservation.hostname` (sparse), `device_id` (sparse) | the database itself refuses a duplicate IP record or reservation; IP-by-MAC and host-name lookups |
| arp_entries | `(ip_key, mac, device_id)` unique, `mac`, `last_seen` | duplicate-IP detection, newest first |
| subnets | `network` unique, `(version, start_key, end_key)` | no duplicate subnets; overlap and "which subnet holds this IP" lookups |
| alerts | `key` unique, `(status, type, last_seen)` | the same alert is updated, not re-created; open-alert lists |
| users | `username` unique | |
| sessions | `token_hash` unique, `expires_at` TTL (0 s) | sessions vanish when they expire |
| metrics | `ts` TTL (7 days) | keeps the free-tier database small |
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
