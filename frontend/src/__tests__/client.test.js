import { describe, expect, it, vi } from "vitest";
import {
  ApiError,
  errorMessage,
  getHealth,
  hasCsrfToken,
  request,
  setAuthHandlers,
  setCsrfToken,
} from "../api/client.js";
import { json } from "./fakeApi.js";

function mockFetch(status, body) {
  const fetchMock = vi.fn().mockImplementation(async () => json(status, body));
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("request", () => {
  it("sends the CSRF token on writes only, and only same-origin", async () => {
    const fetchMock = mockFetch(200, {});
    setCsrfToken("tok-123");
    await request("GET", "/api/subnets");
    await request("POST", "/api/subnets", { body: { network: "10.0.0.0/24" } });
    await request("DELETE", "/api/subnets/abc");

    const [getCall, postCall, deleteCall] = fetchMock.mock.calls.map(([, init]) => init);
    expect(getCall.headers["X-CSRF-Token"]).toBeUndefined();
    expect(postCall.headers["X-CSRF-Token"]).toBe("tok-123");
    expect(deleteCall.headers["X-CSRF-Token"]).toBe("tok-123");
    expect(postCall.headers["Content-Type"]).toBe("application/json");
    expect(postCall.body).toBe('{"network":"10.0.0.0/24"}');
    for (const init of [getCall, postCall, deleteCall]) expect(init.credentials).toBe("same-origin");
  });

  it("keeps the token in memory, never in browser storage", async () => {
    mockFetch(200, {});
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    setCsrfToken("tok-456");
    await request("POST", "/api/x", { body: {} });
    expect(setItem).not.toHaveBeenCalled();
    expect(JSON.stringify({ ...window.localStorage })).not.toContain("tok-456");
    expect(JSON.stringify({ ...window.sessionStorage })).not.toContain("tok-456");
    expect(document.cookie).not.toContain("tok-456");
  });

  it("builds query strings and skips empty values", async () => {
    const fetchMock = mockFetch(200, []);
    await request("GET", "/api/devices", { query: { q: "core sw", status: "", limit: 5, after: undefined } });
    expect(fetchMock.mock.calls[0][0]).toBe("/api/devices?q=core+sw&limit=5");
  });

  it("on 401 forgets the token and reports an expired session", async () => {
    mockFetch(401, { detail: "Not signed in or session expired" });
    const unauthorized = vi.fn();
    setAuthHandlers({ unauthorized });
    setCsrfToken("tok");
    await expect(request("GET", "/api/subnets")).rejects.toBeInstanceOf(ApiError);
    expect(unauthorized).toHaveBeenCalledOnce();
    expect(hasCsrfToken()).toBe(false);
  });

  it("does not treat a failed login as an expired session", async () => {
    mockFetch(401, { detail: "Invalid username or password" });
    const unauthorized = vi.fn();
    setAuthHandlers({ unauthorized });
    await expect(request("POST", "/api/auth/login", { body: {}, auth: false })).rejects.toThrow(
      "Invalid username or password",
    );
    expect(unauthorized).not.toHaveBeenCalled();
  });

  it("sends the user to the password screen on password_change_required", async () => {
    mockFetch(403, { detail: "password_change_required" });
    const passwordChangeRequired = vi.fn();
    setAuthHandlers({ passwordChangeRequired });
    await expect(request("GET", "/api/subnets")).rejects.toMatchObject({ status: 403 });
    expect(passwordChangeRequired).toHaveBeenCalledOnce();
  });

  it("handles 204 No Content", async () => {
    mockFetch(204);
    await expect(request("DELETE", "/api/ips/reservations/10.0.0.5")).resolves.toBeNull();
  });
});

describe("errorMessage", () => {
  it("reads FastAPI's string and list error shapes", () => {
    expect(errorMessage(409, { detail: "10.0.0.5 is already reserved" })).toBe("10.0.0.5 is already reserved");
    expect(
      errorMessage(422, {
        detail: [{ loc: ["body", "ip"], msg: "value is not a valid IPv4 or IPv6 address" }],
      }),
    ).toBe("ip: value is not a valid IPv4 or IPv6 address");
    expect(errorMessage(422, { detail: [{ loc: ["body"], msg: "Value error, network has host bits set" }] })).toBe(
      "network has host bits set",
    );
  });

  it("never shows raw server internals", () => {
    expect(errorMessage(500, null)).toBe("The server had a problem. Try again in a moment.");
    expect(errorMessage(429, null)).toMatch(/Too many attempts/);
  });
});

describe("getHealth", () => {
  it("reports both up when the backend and database are fine", async () => {
    const fetchMock = mockFetch(200, { status: "ok", database: "ok" });
    await expect(getHealth()).resolves.toEqual({ api: "up", database: "up" });
    expect(fetchMock).toHaveBeenCalledWith("/health", expect.objectContaining({ credentials: "same-origin" }));
  });

  it("reads the 503 body to report a database outage", async () => {
    mockFetch(503, { status: "degraded", database: "unavailable" });
    await expect(getHealth()).resolves.toEqual({ api: "up", database: "down" });
  });

  it("reports the API down when the backend cannot be reached", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    await expect(getHealth()).resolves.toEqual({ api: "down", database: "unknown" });
  });
});
