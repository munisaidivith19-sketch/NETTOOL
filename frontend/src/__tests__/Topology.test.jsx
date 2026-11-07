import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import App from "../App.jsx";
import { AuthProvider } from "../auth/AuthProvider.jsx";
import { toElements } from "../components/TopologyCanvas.jsx";
import { formatBps } from "../format.js";
import { mockApi, signedIn } from "./fakeApi.js";

/*
 * Cytoscape draws on a <canvas>, which jsdom can't do. The canvas component is replaced by a
 * stand-in that lists the nodes it was given as buttons and reports the highlighted node, so
 * the page logic (data, selection, search) is tested; the real map is checked in a browser.
 */
vi.mock("../components/TopologyCanvas.jsx", async (importOriginal) => {
  const real = await importOriginal();
  return {
    ...real,
    default: function FakeCanvas({ graph, selectedId, highlight, onSelect, label }) {
      return (
        <div role="img" aria-label={label}>
          {graph.nodes.map((n) => (
            <button key={n.id} type="button" aria-pressed={n.id === selectedId} onClick={() => onSelect(n.id)}>
              node {n.label}
            </button>
          ))}
          <output>highlight:{highlight ? `${highlight.nodeId}/${highlight.port}` : "none"}</output>
        </div>
      );
    },
  };
});

const CORE = "c".repeat(24);
const ACCESS = "d".repeat(24);
const EVIL = '<img src=x onerror="alert(1)">';
const GRAPH = {
  nodes: [
    { id: CORE, label: "CORE-SW-1", mgmt_ip: "10.10.99.1", vendor: "Cisco", status: "up", device_status: "up",
      external: false, open_alerts: 0, location: "Server room" },
    { id: ACCESS, label: "ACCESS-SW-1", mgmt_ip: "10.10.99.11", vendor: "HP", status: "down", device_status: "down",
      external: false, open_alerts: 2 },
    { id: "ext:00:00:0c:ee:00:01", label: EVIL, mgmt_ip: "203.0.113.1", status: "external", external: true,
      open_alerts: 0, platform: "Juniper MX" },
  ],
  edges: [
    { id: "e1", source: CORE, target: ACCESS, source_port: "Gi1/0/2", target_port: "9", protocols: ["lldp"],
      status: "down", lost: false },
    { id: "e2", source: CORE, target: "ext:00:00:0c:ee:00:01", source_port: "Gi1/0/1", target_port: "xe-0/0/7",
      protocols: ["lldp"], status: "up", lost: false },
  ],
  truncated: false,
};

const LOCATED = {
  query: "10.10.10.20", kind: "ip", ip: "10.10.10.20", mac: "00:14:22:1a:20:14", hostname: null, device: null,
  location: { device_id: ACCESS, device: "ACCESS-SW-1", if_index: 1, port: "1", vlan: 10,
    last_seen: new Date().toISOString(), via: "mac_table" },
  sightings: [
    { device_id: CORE, device: "CORE-SW-1", if_index: 2, port: "Gi1/0/2", vlan: 10, uplink: true,
      uplink_reason: "network device connected (LLDP/CDP)", last_seen: new Date().toISOString(), recent: true },
  ],
  message: "00:14:22:1a:20:14 is on ACCESS-SW-1 port 1, VLAN 10.",
};

function renderAt(path) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe("topology page", () => {
  it("lists every link as text and shows untrusted names as text", async () => {
    mockApi(signedIn("viewer", { "GET /api/topology": GRAPH }));
    renderAt("/topology");
    const table = await screen.findByRole("table");
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(3);
    expect(rows[1]).toHaveTextContent("CORE-SW-1Gi1/0/2ACCESS-SW-19LLDPDown");
    expect(screen.getByRole("img", { name: /2 devices and 2 links/ })).toBeInTheDocument();
    // The external neighbour's name is shown literally, never parsed as HTML.
    expect(screen.getAllByText(EVIL).length).toBeGreaterThan(0);
    expect(document.querySelector("img[src='x']")).toBeNull();
  });

  it("shows a device's details when it is selected on the map", async () => {
    mockApi(signedIn("viewer", { "GET /api/topology": GRAPH }));
    renderAt("/topology");
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "node ACCESS-SW-1" }));
    const side = screen.getByRole("heading", { name: "ACCESS-SW-1" }).closest("section");
    expect(within(side).getByText("10.10.99.11")).toBeInTheDocument();
    expect(within(side).getByText("Down")).toBeInTheDocument();
    expect(within(side).getByRole("link", { name: "2" })).toHaveAttribute("href", "/alerts");
    expect(within(side).getByText("Connections (1)")).toBeInTheDocument();
    expect(within(side).getByRole("link", { name: "Open device page" })).toHaveAttribute("href", `/devices/${ACCESS}`);
  });

  it("locates an endpoint and highlights the access switch, not the trunk", async () => {
    const fetchMock = mockApi(
      signedIn("viewer", { "GET /api/topology": GRAPH, "GET /api/topology/locate": LOCATED }),
    );
    renderAt("/topology");
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Find which port a device is on"), "10.10.10.20");
    await user.click(screen.getByRole("button", { name: "Locate" }));
    const result = await screen.findByText(/Found:/);
    expect(result.closest("[role=status]")).toHaveTextContent("ACCESS-SW-1 port 1, VLAN 10");
    expect(screen.getByText(/Also seen on 1 uplink port/)).toBeInTheDocument();
    expect(screen.getByText(`highlight:${ACCESS}/1`)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "node ACCESS-SW-1" })).toHaveAttribute("aria-pressed", "true");
    const call = fetchMock.mock.calls.find(([url]) => url.startsWith("/api/topology/locate"));
    expect(call[0]).toBe("/api/topology/locate?q=10.10.10.20");
  });

  it("explains a rejected search", async () => {
    mockApi(
      signedIn("viewer", {
        "GET /api/topology": GRAPH,
        "GET /api/topology/locate": { status: 422, body: { detail: [] } },
      }),
    );
    renderAt("/topology");
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Find which port a device is on"), "bad$query");
    await user.click(screen.getByRole("button", { name: "Locate" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Enter an IP address, a MAC address or a host name.");
  });

  it("shows an empty state before any agent report", async () => {
    mockApi(signedIn("viewer", { "GET /api/topology": { nodes: [], edges: [], truncated: false } }));
    renderAt("/topology");
    expect(await screen.findByText(/The map fills in after the first agent report/)).toBeInTheDocument();
  });

  it("builds Cytoscape elements as data only", () => {
    const elements = toElements(GRAPH);
    expect(elements.filter((e) => e.group === "nodes")).toHaveLength(3);
    expect(elements.find((e) => e.data.id === "e1").data).toMatchObject({ source: CORE, target: ACCESS, status: "down" });
    expect(elements.find((e) => e.data.id.startsWith("ext:")).data.label).toBe(EVIL);
  });
});

describe("device page (Phase 5)", () => {
  it("shows interface traffic and neighbours", async () => {
    mockApi(
      signedIn("viewer", {
        [`GET /api/devices/${ACCESS}`]: {
          id: ACCESS, mgmt_ip: "10.10.99.11", sys_name: "ACCESS-SW-1", status: "up", snmp_v2c: false,
          interfaces: [
            { if_index: 9, name: "9", oper_status: "up", admin_status: "up", speed_mbps: 1000,
              rates: { in_bps: 1_250_000, out_bps: 980, at: new Date().toISOString() } },
          ],
          addresses: [],
          links: [
            { protocol: "lldp", if_index: 9, local_port: "9", remote_name: "CORE-SW-1", remote_port: "Gi1/0/2",
              remote_mgmt_ip: "10.10.99.1", remote_device_id: CORE, status: "active", last_seen: new Date().toISOString() },
            { protocol: "cdp", if_index: 1, local_port: "1", remote_name: "SEP001122334455", remote_port: "Port 1",
              remote_platform: "Cisco IP Phone", remote_device_id: null, status: "lost",
              last_seen: new Date(Date.now() - 3_600_000).toISOString() },
          ],
        },
      }),
    );
    renderAt(`/devices/${ACCESS}`);
    expect(await screen.findByText("1.25 Mb/s / 980 b/s")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "CORE-SW-1" })).toHaveAttribute("href", `/devices/${CORE}`);
    expect(screen.getByText("Not managed")).toBeInTheDocument();
    expect(screen.getByText(/Lost, last seen/)).toBeInTheDocument();
  });
});

describe("notifications admin page", () => {
  it("sends a test message and shows the result", async () => {
    const fetchMock = mockApi(
      signedIn("admin", {
        "GET /api/admin/notifications": {
          channels: { telegram: true, email: false }, min_severity: "warning", cooldown_minutes: 30,
          hourly_cap: 20, recent: [],
        },
        "POST /api/admin/notifications/test": { channels: { telegram: "sent" } },
      }),
    );
    renderAt("/admin/notifications");
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Send test notification" }));
    expect(await screen.findByText("telegram: sent")).toBeInTheDocument();
    const post = fetchMock.mock.calls.find(([url, init]) => url === "/api/admin/notifications/test" && init.method === "POST");
    expect(post[1].headers["X-CSRF-Token"]).toBe("csrf-from-me");
  });

  it("is not offered to engineers", async () => {
    mockApi(signedIn("engineer"));
    renderAt("/admin/notifications");
    expect(await screen.findByRole("heading", { name: "No access" })).toBeInTheDocument();
  });
});

describe("formatBps", () => {
  it.each([
    [null, "–"],
    [0, "0 b/s"],
    [999, "999 b/s"],
    [1000, "1.00 kb/s"],
    [1_250_000, "1.25 Mb/s"],
    [25_600_000, "25.6 Mb/s"],
    [940_000_000, "940 Mb/s"],
    [10_000_000_000, "10.0 Gb/s"],
  ])("%s -> %s", (value, text) => {
    expect(formatBps(value)).toBe(text);
  });
});
