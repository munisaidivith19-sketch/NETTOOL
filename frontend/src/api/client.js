/*
 * The one place the frontend talks to the backend.
 *
 * - Same origin only. The session lives in an httpOnly cookie that JavaScript can't read;
 *   credentials: "same-origin" sends it to our own backend and never to another site.
 * - The CSRF token is kept in this module's memory only, never in localStorage or a cookie we
 *   can read. A reload loses it; the app gets it back from GET /api/auth/me.
 * - Every state-changing request (POST/PATCH/PUT/DELETE) carries it as X-CSRF-Token.
 * - 401 means the session is gone (expired, logged out elsewhere): the app is told so it can
 *   show the login page. 403 "password_change_required" sends the user to the change screen.
 */

export class ApiError extends Error {
  constructor(status, body) {
    super(errorMessage(status, body));
    this.status = status;
    this.body = body;
  }
}

let csrfToken = null;
const handlers = { unauthorized: () => {}, passwordChangeRequired: () => {} };

export function setCsrfToken(token) {
  csrfToken = token || null;
}

export function hasCsrfToken() {
  return csrfToken !== null;
}

/* The auth layer registers what to do on 401 / forced password change. */
export function setAuthHandlers({ unauthorized, passwordChangeRequired }) {
  if (unauthorized) handlers.unauthorized = unauthorized;
  if (passwordChangeRequired) handlers.passwordChangeRequired = passwordChangeRequired;
}

const WRITE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/*
 * FastAPI errors come as {"detail": "text"} or, for validation errors,
 * {"detail": [{"loc": [...], "msg": "..."}]}. Turn either into one readable sentence.
 */
export function errorMessage(status, body) {
  const detail = body?.detail;
  if (typeof detail === "string") {
    return detail === "password_change_required" ? "You need to change your password first." : detail;
  }
  // Some routes (Ask NetMap) send {"detail": {"message": "...", ...extra fields}}.
  if (detail && typeof detail === "object" && !Array.isArray(detail) && typeof detail.message === "string") {
    return detail.message;
  }
  if (Array.isArray(detail) && detail.length > 0) {
    return detail
      .map((err) => {
        const field = (err.loc ?? []).filter((part) => part !== "body" && part !== "query").join(".");
        const msg = String(err.msg ?? "is invalid").replace(/^Value error, /, "");
        return field ? `${field}: ${msg}` : msg;
      })
      .join("; ");
  }
  if (status === 429) return "Too many attempts. Wait a few minutes and try again.";
  if (status >= 500) return "The server had a problem. Try again in a moment.";
  return `Request failed (${status}).`;
}

/*
 * request("GET", "/api/subnets", { query: { version: 4 } })
 * request("POST", "/api/subnets", { body: {...} })
 * Options: auth: false skips the 401 handler (used by login and the first /me check).
 */
export async function request(method, path, { body, query, signal, auth = true } = {}) {
  method = method.toUpperCase();
  let url = path;
  if (query) {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== null && value !== "") params.set(key, String(value));
    }
    const text = params.toString();
    if (text) url += `?${text}`;
  }
  const headers = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (WRITE_METHODS.has(method) && csrfToken) headers["X-CSRF-Token"] = csrfToken;

  const response = await fetch(url, {
    method,
    credentials: "same-origin",
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal,
  });
  const data = response.status === 204 ? null : await response.json().catch(() => null);
  if (!response.ok) {
    if (response.status === 401 && auth) {
      setCsrfToken(null);
      handlers.unauthorized();
    } else if (response.status === 403 && data?.detail === "password_change_required") {
      handlers.passwordChangeRequired();
    }
    throw new ApiError(response.status, data);
  }
  return data;
}

export function apiGet(path, options) {
  return request("GET", path, options);
}

/*
 * /health answers 503 with a JSON body when the database is down, so the body is read
 * either way. A network error (backend not running) is reported as "unreachable".
 */
export async function getHealth({ signal } = {}) {
  try {
    const body = await apiGet("/health", { signal, auth: false });
    return { api: "up", database: body?.database === "ok" ? "up" : "down" };
  } catch (error) {
    if (error?.name === "AbortError") throw error;
    if (error instanceof ApiError && error.body?.database) {
      return { api: "up", database: error.body.database === "ok" ? "up" : "down" };
    }
    return { api: "down", database: "unknown" };
  }
}
