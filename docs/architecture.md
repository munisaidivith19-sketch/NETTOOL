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

## MongoDB indexes
| Collection | Index | Why |
|---|---|---|
| devices | `mgmt_ip` unique, `status`, `(agent_id, mgmt_ip_key)` | one record per managed device; status filters; known-devices list |
| interfaces | `(device_id, if_index)` unique | one row per interface |
| ip_addresses | `ip_key` unique, `mac` | the database itself refuses a duplicate IP record; IP-by-MAC lookups |
| arp_entries | `(ip_key, mac, device_id)` unique, `mac`, `last_seen` | duplicate-IP detection, newest first |
| subnets | `network` unique | no duplicate subnets |
| alerts | `key` unique | the same alert is updated, not re-created |
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
