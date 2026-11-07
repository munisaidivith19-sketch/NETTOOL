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

## MongoDB indexes
| Collection | Index | Why |
|---|---|---|
| devices | `mgmt_ip` unique | one record per managed device |
| ip_addresses | `ip_key` unique | the database itself refuses a duplicate IP record |
| subnets | `network` unique | no duplicate subnets |
| alerts | `key` unique | the same alert is updated, not re-created |
| users | `username` unique | |
| sessions | `token_hash` unique, `expires_at` TTL (0 s) | sessions vanish when they expire |
| metrics | `ts` TTL (7 days) | keeps the free-tier database small |

## Frontend design notes
- Concept: a patch panel. Cool neutral surfaces, so status colours are the only loud thing.
- Status is shown by **shape and colour** (up = filled circle, down = hollow square,
  warning = triangle), so it never depends on colour alone.
- Fonts are bundled (Atkinson Hyperlegible Next for the UI, JetBrains Mono for addresses only)
  so a strict `Content-Security-Policy: default-src 'self'` works.
- Theme follows the OS until the user picks one. Only that preference is stored in
  localStorage, never tokens.
