import { vi } from "vitest";

/*
 * A fake backend for component tests: routes are "METHOD /path" -> response or a function
 * returning one. Responses are { status, body }; a plain object means 200 with that body.
 */
export function json(status, body) {
  if (status === 204) return new Response(null, { status });
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

export function mockApi(routes) {
  const fetchMock = vi.fn(async (url, init = {}) => {
    const method = init.method ?? "GET";
    const path = url.split("?")[0];
    const handler = routes[`${method} ${path}`];
    if (handler === undefined) return json(404, { detail: "Not found" });
    const result = typeof handler === "function" ? handler({ url, init, body: init.body && JSON.parse(init.body) }) : handler;
    if (result && "status" in result && ("body" in result || result.status === 204)) {
      return json(result.status, result.body);
    }
    return json(200, result);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

export const USERS = {
  admin: { id: "a".repeat(24), username: "alice", role: "admin", disabled: false, must_change_password: false },
  engineer: { id: "e".repeat(24), username: "erin", role: "engineer", disabled: false, must_change_password: false },
  viewer: { id: "v".repeat(24), username: "victor", role: "viewer", disabled: false, must_change_password: false },
};

export const SUMMARY = {
  devices: { total: 5, up: 4, snmp_error: 1, down: 0 },
  subnets: 3,
  fullest_subnets: [
    {
      id: "1".repeat(24),
      network: "10.10.20.0/24",
      name: "Labs",
      usage: { size: "256", usable: "254", used: "203", free: "51", percent: 79.92 },
    },
  ],
  alerts_open: 2,
  alerts_by_severity: { critical: 1, warning: 1 },
  alerts_by_type: { duplicate_ip: 1, subnet_usage: 1 },
  duplicate_ips: 1,
  last_agent_check_in: { name: "Campus agent", last_seen_at: new Date().toISOString() },
};

/* Routes every signed-in page needs: who am I, the shared summary, health. */
export function signedIn(role = "admin", extra = {}) {
  return {
    "GET /api/auth/me": { user: USERS[role], csrf_token: "csrf-from-me" },
    "GET /api/dashboard/summary": SUMMARY,
    "GET /api/alerts": [],
    "GET /health": { status: "ok", database: "ok" },
    "POST /api/auth/logout": { status: 204 },
    ...extra,
  };
}
