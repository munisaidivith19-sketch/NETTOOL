import { describe, expect, it, vi } from "vitest";
import { getHealth } from "../api/client.js";

function mockFetch(status, body) {
  const fetchMock = vi.fn().mockResolvedValue(
    new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }),
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("getHealth", () => {
  it("reports both up when the backend and database are fine", async () => {
    const fetchMock = mockFetch(200, { status: "ok", database: "ok" });
    await expect(getHealth()).resolves.toEqual({ api: "up", database: "up" });
    // Same-origin request: cookies go only to our own backend, never to another site.
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
