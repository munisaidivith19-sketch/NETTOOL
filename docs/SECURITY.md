# NetMap security model

This document is for the reviewer, the interviewer and the future maintainer. It covers:
- what NetMap protects and from whom
- where the trust boundaries are
- a STRIDE threat model for each component
- the control that answers each threat, with links to the code
- what is still open

The rule-by-rule check of CLAUDE.md section 7 is in [SECURITY_REVIEW.md](SECURITY_REVIEW.md).
How to demonstrate the controls live is in [SECURITY_TESTING.md](SECURITY_TESTING.md).
The design behind sessions, CSRF and agent signing is in [auth-design.md](auth-design.md).

## 1. What we protect

| Asset | Why it matters | Where it lives |
|---|---|---|
| Device credentials (SSH passwords, SNMPv3 keys, communities) | Whoever has them controls the network | **Agent only**: Fernet-encrypted file, key protected by Windows DPAPI |
| Ability to change device configs | One bad command can cut off a site | Change-request flow: backend approval + agent push |
| Network inventory (IPs, MACs, topology, configs) | A map for an attacker; configs reveal weaknesses | MongoDB; configs are stored masked |
| User accounts and sessions | Access to all of the above | MongoDB: bcrypt hashes, SHA-256 session-token hashes |
| Agent API keys | Let someone forge discovery data or claim config jobs | MongoDB, Fernet-encrypted under `AGENT_KEY_ENCRYPTION_KEY` |
| TOTP secrets and recovery codes | The second factor for admins | MongoDB: secrets Fernet-encrypted under `MFA_ENCRYPTION_KEY`, codes as SHA-256 hashes |
| Audit log | Evidence after an incident | MongoDB, append-only from the app |

**Attackers considered:**
- an internet stranger who can reach the Render URL
- a logged-in user trying to do more than their role allows (a viewer acting as an admin)
- a malicious website open in an engineer's browser (CSRF, clickjacking)
- someone on the network path between the agent and the cloud
- a rogue or compromised device inside the LAN that sends crafted SNMP, LLDP or config text
- a prompt-injection attempt through device data
- someone who obtains a copy of the database

**Out of scope:**
- an attacker with admin rights on the agent's Windows machine. They can read what the agent
  can read.
- a compromised Render or Atlas platform

## 2. Trust boundaries

```
 ┌──────────── private network (trusted to run the agent) ────────────┐
 │  devices ◄── SNMPv3 / SSH ──  NetMap agent                           │
 │  (untrusted data: sysDescr,   - device credentials (encrypted)       │
 │   LLDP names, config text)    - outbound HTTPS only, HMAC-signed     │
 └───────────────────────────────────────┬─────────────────────────────┘
                                   B1    │ HTTPS, X-Signature, nonce
 ┌───────────── cloud (Render) ──────────▼─────────────────────────────┐
 │  FastAPI backend + React files (same origin)                         │
 │  - sessions, RBAC, CSRF, input limits, audit                         │
 │  B3 ─ TLS ─► MongoDB Atlas         B4 ─ HTTPS ─► LLM API (optional)  │
 └──────────────────────────────────────▲──────────────────────────────┘
                                   B2    │ HTTPS, session cookie + CSRF token
                               browser (engineer, viewer, admin)
```

- **B1, agent → backend:** the backend trusts nothing in a request until the HMAC signature,
  timestamp and nonce are checked. The agent trusts nothing in a job until its own denylist
  check and the job signature pass.
- **B2, browser → backend:** every request is checked server-side for session, role and CSRF
  token. Anything the React app hides is only for convenience.
- **B3, backend → database:** least-privilege database users. Ask NetMap uses a separate
  read-only user.
- **B4, backend → LLM:** only questions and masked, untrusted-labelled data are sent. The
  answer is never executed as a write.

## 3. STRIDE threat model

STRIDE = **S**poofing, **T**ampering, **R**epudiation, **I**nformation disclosure,
**D**enial of service, **E**levation of privilege.

### 3.1 Agent

| | Threat | Control | Code |
|---|---|---|---|
| S | Someone pretends to be the agent and sends fake devices or IPs | Per-agent key; HMAC-SHA256 over method, path, timestamp, nonce and body hash; the key itself is never sent | `backend/app/security/agent_auth.py`, `agent/netmap_agent/uploader.py` |
| S | A fake backend sends the agent config jobs | HTTPS only (no `http://` except for localhost in dev); jobs are signed by the backend and checked by the agent | `agent/netmap_agent/config.py:106`, `app/config_mgmt/jobsign.py` |
| T | A captured request is replayed or changed | ±5 min timestamp window; each nonce accepted once (unique index + TTL); the body hash is inside the signature | `agent_auth.py:120-145` |
| T | A malicious change slips through approval | The agent re-checks the denylist before pushing; Cisco revert timer or MikroTik safe mode; ping and re-poll after the push, rolling back if the device is unreachable | `agent/netmap_agent/config_mgmt/push.py` |
| T | Hostile device data (sysDescr, LLDP names, config text) | Parsed as data, never executed. Validated as IP or MAC before use. Escaped by React. Labelled as untrusted for the LLM | `agent/netmap_agent/discovery/`, `backend/app/ai/explain.py` |
| R | The agent denies having pushed a change | Each push is recorded with before/after config hashes in `audit_log` | `backend/app/api/agent_config.py:120` |
| I | Device credentials leak | Kept only on the agent. Fernet-encrypted at rest, key under DPAPI. Never sent to the backend, logs or LLM. Netmiko session logs are off. Config backups are masked | `agent/netmap_agent/credential_store.py`, `config_mgmt/masking.py`, `agent/tests/test_logging_secrets.py` |
| I | The OUI vendor file is swapped through an http redirect | The download refuses any non-HTTPS hop | `agent/netmap_agent/ai_training/oui.py:107` |
| D | A huge range or a slow device stalls discovery | Ping sweep capped (1,024 per range, 4,096 in total); SNMP timeouts; one bad device doesn't stop the others | `agent/netmap_agent/discovery/ping.py` |
| E | Command injection through a target address | `subprocess` with an argument list, never `shell=True`; every target goes through `ipaddress.ip_address` first | `agent/netmap_agent/discovery/ping.py:34`, `:63` |
| E | Template injection in auto-configuration | Jinja2 `SandboxedEnvironment` + `StrictUndefined`; each template's variables have a Pydantic schema | `backend/app/config_mgmt/templates.py` |

### 3.2 Backend (FastAPI)

| | Threat | Control | Code |
|---|---|---|---|
| S | Password guessing | bcrypt cost 12; 12-character minimum and a common-password list; per-IP limit (10 failures in 5 min); account lock (5 failures → 15 min); one generic error | `security/passwords.py`, `security/rate_limit.py`, `api/auth.py` |
| S | Stolen admin password | **TOTP MFA required for admins.** Codes are single-use (the time step must increase). Wrong codes count toward the lockout. Recovery codes are single-use | `security/mfa.py`, `api/mfa.py`, `security/rbac.py:104` |
| S | Session theft or fixation | Random 256-bit token; only its SHA-256 is stored; httpOnly, Secure, SameSite=Strict cookie; 8 h absolute and 30 min idle; a new session at every sign-in; sessions revoked on password change, MFA change and MFA reset | `security/sessions.py` |
| T | CSRF: another site makes the browser send a request | SameSite=Strict, plus a per-session CSRF token in `X-CSRF-Token`, plus an Origin check, plus JSON-only bodies (an HTML form can't send them) | `security/csrf.py` |
| T | NoSQL injection | Every body is a strict Pydantic model: typed fields can't hold `{"$ne": …}`, extra keys are refused, filters are built from validated fields. Tested on every write route | `models/common.py`, `tests/test_input_limits.py` |
| R | A user denies an action | `audit_log` records who, what, target, when, source IP, result and request ID for logins, MFA, users, agents, subnets and changes; the app only inserts | `services/audit.py` |
| I | Error details leak internals | Generic error bodies with a request ID; details stay in the server log; `/docs` and `/openapi.json` are off in production | `main.py`, `security/http.py` |
| I | A viewer reads admin data | RBAC on every route, deny by default, tested for every route × role | `security/rbac.py`, `tests/test_rbac.py` |
| D | Huge bodies or deep JSON | 2 MB body limit (10 MB for agent reports); every string and list has a maximum size | `security/http.py:16-19`, `tests/test_input_limits.py` |
| D | Audit-log flooding with bad signatures or logins | Failures are counted per IP and 10-minute window. Only the first 20 are audited in full, then one "suppressed" entry. A `security` alert opens | `services/security_events.py` |
| D | Ask NetMap used as a DoS amplifier | Per-user rate limit; at most 10 pipeline stages; 100 results; 4 KB query; server-side `maxTimeMS` | `api/ai.py`, `ai/query_guard.py` |
| E | A viewer or engineer acts as an admin | Server-side `require_role`; an admin without MFA is blocked from admin routes until it is set up; an admin can't reset their own MFA | `security/rbac.py`, `api/users.py` |
| E | The approver is the creator | Four-eyes rule; an admin override needs a reason and is audited | `api/changes.py:220` |

### 3.3 Database (MongoDB)

| | Threat | Control | Code / setting |
|---|---|---|---|
| S | Someone connects directly to the database | Local: `bindIp 127.0.0.1`. Atlas: Network Access limited to Render's outbound IPs, never `0.0.0.0/0` (Phase 9) | `mongod.cfg`, `docs/DEPLOYMENT.md` (Phase 9) |
| T | AI-generated queries write data | Ask NetMap uses the read-only user `netmap_ai_ro` and runs only allowlisted aggregate stages. In production it refuses to run without that user | `ai/query_guard.py`, `api/ai.py:55` |
| R | Audit entries are removed | The app has no update or delete path for `audit_log`. A database admin still could, which is accepted (see section 5) | `services/audit.py` |
| I | A database dump is stolen | No plain secrets in it: bcrypt password hashes; SHA-256 session-token and recovery-code hashes; agent keys and TOTP secrets Fernet-encrypted with keys kept **only in the Render environment**; device credentials never stored; configs masked | `security/agent_auth.py`, `security/mfa.py` |
| D | The database fills up (Atlas M0: 512 MB) | TTL indexes on metrics (7 d), sessions, login attempts, nonces, MFA challenges and security events; config history capped at 50 versions per device; bounded audit on floods | `db.py` |
| E | The app's DB user can do too much | `netmap_app` has `readWrite` on `netmap` only, no admin roles (Phase 9) | `docs/DEPLOYMENT.md` (Phase 9) |

### 3.4 Browser (React)

| | Threat | Control | Code |
|---|---|---|---|
| S | Phishing a session token out of the page | The token is in an httpOnly cookie that JavaScript can't read; nothing sensitive is in `localStorage` (only the theme choice) | `frontend/src/api/client.js` |
| T | XSS through device names, sysDescr, logs or config text | React escapes all text; no `dangerouslySetInnerHTML`; CSP `script-src 'self'` with no inline scripts; the MFA QR code is drawn as SVG squares, so no `data:` image or HTML is needed | `security/http.py:24`, `frontend/src/pages/MfaSetup.jsx` |
| T | Clickjacking (the app shown inside a hidden frame) | `X-Frame-Options: DENY` and `frame-ancestors 'none'` | `security/http.py:66` |
| I | Referrer or browser features leak data | `Referrer-Policy: no-referrer`; `Permissions-Policy` turns off camera, microphone, location and more | `security/http.py:67-68` |
| I | Recovery codes left on screen | Shown once, with a "Copy" button and an "I have saved these codes" confirmation; never fetched again | `frontend/src/pages/MfaSetup.jsx` |
| E | Hidden buttons used directly | Hiding a button is only for convenience: every route checks the role on the server | `tests/test_rbac.py` |

## 4. Two-step sign-in (MFA) in brief

1. **Password step.** The password is right and MFA is on, so NetMap creates a 5-minute
   *challenge* instead of a session. The browser gets an httpOnly cookie that is sent only to
   `/api/auth/mfa`. The failure counter is not reset yet.
2. **Code step.** The 6-digit code must match the current 30-second step (±1), and its step
   must be newer than the last accepted one. The update is atomic, so the same code can't
   be used twice, even by two parallel requests. Each challenge allows at most 5 attempts,
   and a wrong code counts toward the account lockout.
3. **Session.** On success, the challenge is deleted and a new session is created.
4. **Recovery codes.** There are 10 of them, 50 random bits each, and each works once. Only
   their SHA-256 hashes are stored. Using one is audited, and the UI warns when 2 or fewer
   are left.
5. **Admins must enrol.** Until MFA is on, an admin can only change their password and set up
   MFA. A user promoted to admin is stopped on their next request.
6. **Lost phone.** Another admin can press "Reset MFA". If the only admin is locked out,
   someone with database access runs `python backend/scripts/reset_mfa.py <username>`.

## 5. Residual risks and known limitations

See [known-limitations.md](known-limitations.md) for the full list. The security-relevant
ones:

- **First MFA enrolment is protected only by the password.** A new admin sets up MFA
  straight after the forced password change. Someone who has the initial password before
  the real admin signs in could enrol their own phone. Mitigation: give the initial password
  through a separate channel, and sign in at once.
- **Account lockout can be used to annoy.** Anyone who knows a username can lock it for
  15 minutes. MFA failures count too. Per-IP limits slow this down. It is the usual trade-off
  against password guessing.
- **The per-IP limit and the audit IP use the connecting address.** Behind Render's proxy,
  the real client IP needs trusted-proxy handling (Phase 9).
- **Encryption keys are single points of failure.** If `AGENT_KEY_ENCRYPTION_KEY` or
  `MFA_ENCRYPTION_KEY` leaks *together with* the database, those secrets can be decrypted.
  If a key is lost, every agent key must be re-created, or every MFA user reset. Both keys
  support rotation (new key first, then the old one).
- **TOTP is phishable.** A real-time phishing proxy can relay a code within its 30 seconds.
  WebAuthn / passkeys would stop that, but they are not implemented.
- **The audit log is append-only from the app, not tamper-proof.** A database administrator
  can still edit it. Shipping it to a write-once store is future work.
- **No rogue-DHCP or ARP-spoofing detection yet.** Duplicate-IP detection catches some ARP
  conflicts, not all.
- **Without `SSH_KNOWN_HOSTS_FILE`, the agent accepts new SSH host keys.** Set it in
  production.
- **Python 3.10 is past end of life**, and some dependency findings can only be fixed on
  Python 3.11+ (dnspython, Pillow). Each is assessed in known-limitations.md.
- **Distributed guessing is only partly bounded.** Each source IP's audit entries are
  bounded, but an attacker with many IPs can still create many entries. Each IP is limited
  separately, and the account lockout still applies.
