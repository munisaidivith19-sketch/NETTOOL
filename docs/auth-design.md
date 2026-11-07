# Authentication and request security (Phase 1)

How a person and an agent prove who they are, and what stops common attacks.
The code is in `backend/app/security/`.

## 1. People: server-side sessions in a cookie

**Login** (`POST /api/auth/login`):
1. The password is checked with bcrypt (cost 12). Unknown usernames still run one bcrypt check
   against a dummy hash, so response time doesn't reveal which usernames exist.
2. On success the server creates a random 256-bit token (`secrets.token_urlsafe(32)`). It stores
   only the token's **SHA-256 hash** in the `sessions` collection, and sends the token in a cookie:
   `netmap_session=<token>; HttpOnly; Secure; SameSite=Strict; Path=/`.
3. Any session cookie sent with the login request is deleted first. This stops *session fixation*,
   where an attacker plants a known session id and waits for the victim to log in with it.

| Cookie flag | What it stops |
|---|---|
| `HttpOnly` | JavaScript can't read the cookie, so an XSS bug can't steal it |
| `Secure` | the cookie never travels over plain HTTP |
| `SameSite=Strict` | the browser doesn't attach it to requests started by other websites |

**On every request** the cookie's hash is looked up. A session ends after:
- **8 hours** in total (`expires_at`; a MongoDB TTL index also deletes the document), or
- **30 minutes** without activity (`last_seen`, refreshed at most once a minute).

**Logout** deletes the session document, so a copied cookie stops working immediately. That is
the main reason for server-side sessions instead of JWTs: a JWT stays valid until it expires,
even after logout.

**Brute force**:
- **Per IP:** 10 failed logins in 5 minutes → HTTP 429 for that address.
- **Per account:** 5 failures in a row → the account is locked for 15 minutes.
- Every failure (wrong password, unknown user, disabled, locked) returns the same
  `401 Invalid username or password`.

**Forced password change**: the first admin, and any user whose password an admin set, must
change it before any route other than `me`, `logout` and `change-password` works. Changing the
password signs out every other device and issues a new session id.

**Password policy**:
- 12–64 characters, and at most 72 bytes (bcrypt's input limit).
- At least 5 different characters.
- Not on a list of 46,146 common passwords (SecLists).
- Must not contain the username.

## 2. Roles (RBAC), deny by default

| Role | Can |
|---|---|
| admin | manage users, agents, settings; read the audit log |
| engineer | (Phase 3+) manage subnets, create change requests |
| viewer | read only |

Every route declares its rule with a FastAPI dependency: `require_role(...)`, `require_user`,
`require_session`, `require_agent` or `public`. `tests/test_rbac.py` inspects every `/api`
route and **fails the build if one has no rule**. It also calls each route without credentials
and expects 401. Hiding buttons in the UI is convenience; this check is the security.

## 3. CSRF: why a stolen click can't change anything

CSRF is when another website makes *your* browser send a request to NetMap, with your cookie
attached. Three layers stop it:

1. **SameSite=Strict**: the browser doesn't send the cookie on cross-site requests at all.
2. **Origin and content type**: on POST, PUT, PATCH and DELETE to `/api`, a foreign `Origin`
   header gets 403, and a body that isn't `application/json` gets 415. A plain HTML form can't
   send JSON, and JavaScript on another site that sends JSON triggers a CORS "preflight" check,
   which NetMap never approves.
3. **Synchronizer token**: each session has its own random CSRF token, returned in the
   `login`/`me` response body. The frontend keeps it in memory and sends it back as
   `X-CSRF-Token`. Another site can't read our responses, so it can't know the token. The
   comparison uses `hmac.compare_digest` (constant time).

## 4. Agents: HMAC-signed requests

An agent gets an **API key** (32 random bytes) when an admin creates it. The key is shown
**once**.

**Why the key is encrypted, not hashed.** CLAUDE.md first asked for a SHA-256 hash, but checking
an HMAC needs the original key, and a hash can't be reversed. So the server stores the key
**encrypted with Fernet** (AES-128-CBC + HMAC-SHA256) under `AGENT_KEY_ENCRYPTION_KEY`, which
lives only in the server's environment. A stolen copy of the database is useless without that
env secret. A 16-hex-character SHA-256 *fingerprint* lets admins tell keys apart.

**Signing.** The key never travels over the network. For each request the agent sends:

```
X-Agent-Id:  agt_1a2b3c4d5e6f7a8b
X-Timestamp: 1762500000            (Unix seconds)
X-Nonce:     random, used once
X-Signature: hex( HMAC-SHA256( key, METHOD \n PATH?QUERY \n TIMESTAMP \n NONCE \n hex(SHA-256(BODY)) ) )
```

The server rebuilds the same string from what it received and computes the HMAC itself:

| Attack | Why it fails |
|---|---|
| Change the body or path in transit | the SHA-256 of the body or the path changes, so the signature no longer matches |
| Replay a captured request | its nonce is already stored (unique index), so it's refused |
| Replay it much later | the timestamp is more than 5 minutes off |
| Use a revoked agent | `revoked_at` is set, so it's refused |
| Steal a user's cookie and call agent routes | agent routes ignore cookies; only signatures count |

Every failure gets the same `401 Agent authentication failed`. The real reason is written to the
audit log. Nonces are kept for 10 minutes (TTL), longer than the ±5-minute window.

## 5. HTTP hardening
- **Security headers** on every response, including errors:
  - a strict CSP (`'self'` only, no inline scripts)
  - `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`
  - HSTS in production
- **`Cache-Control: no-store`** on API responses.
- **Request IDs:** every response has a random `X-Request-ID`. A crash returns only
  `Internal server error` plus that id, and the full error goes to the server log under the same
  id.
- **Validation errors** never echo the submitted values back (so a rejected password isn't
  reflected).
- **Size limits:** request bodies are capped at 2 MB (10 MB for agent reports), including
  chunked uploads without a `Content-Length`.
- **NoSQL injection:** every input is a typed field with `extra="forbid"`, so
  `{"username": {"$ne": null}}` is rejected with 422 before any query runs.

## 6. Audit log
Each entry in `audit_log` has `at, action, result, actor, target, ip, request_id, details`.
The app only ever inserts entries.

Recorded today:
- **Sign-in:** login success, failure and lockout; logout; password change; forced-change blocks
- **Users:** create, role change, enable/disable, password reset
- **Agents:** create, revoke, and every failed agent authentication

Admins read it with `GET /api/audit?action=auth&actor=alice&limit=50&before=<time>`.
