/*
 * The one place the frontend talks to the backend.
 * Same origin only: the session cookie (Phase 1) travels automatically with
 * credentials: "same-origin". No token is ever kept in localStorage.
 * Phase 1 adds the CSRF header and 401/403 handling here.
 */

export class ApiError extends Error {
  constructor(status, body) {
    super(`Request failed with status ${status}`);
    this.status = status;
    this.body = body;
  }
}

export async function apiGet(path, { signal } = {}) {
  const response = await fetch(path, {
    method: "GET",
    credentials: "same-origin",
    headers: { Accept: "application/json" },
    signal,
  });
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    throw new ApiError(response.status, body);
  }
  return body;
}

/*
 * /health answers 503 with a JSON body when the database is down, so the body is read
 * either way. A network error (backend not running) is reported as "unreachable".
 */
export async function getHealth({ signal } = {}) {
  try {
    const body = await apiGet("/health", { signal });
    return { api: "up", database: body?.database === "ok" ? "up" : "down" };
  } catch (error) {
    if (error?.name === "AbortError") throw error;
    if (error instanceof ApiError && error.body?.database) {
      return { api: "up", database: error.body.database === "ok" ? "up" : "down" };
    }
    return { api: "down", database: "unknown" };
  }
}
