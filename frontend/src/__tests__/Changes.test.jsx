import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import App from "../App.jsx";
import { AuthProvider } from "../auth/AuthProvider.jsx";
import DiffView from "../components/DiffView.jsx";
import { mockApi, signedIn, USERS } from "./fakeApi.js";

function renderAt(entry) {
  return render(
    <MemoryRouter initialEntries={[entry]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  );
}

const DEVICE_ID = "d".repeat(24);
const CHANGE_ID = "c".repeat(24);

const DEVICES = [
  {
    id: DEVICE_ID,
    sys_name: "CORE-SW-1",
    mgmt_ip: "127.0.0.12",
    config_vendor: "cisco_ios",
    backup: { version: 3 },
    compliance: { score: 100 },
    unconfigured: { flag: false, reasons: [] },
  },
  // No SSH credentials yet, so it can't be changed and must not be offered.
  { id: "e".repeat(24), sys_name: "AP-1", mgmt_ip: "127.0.0.14", config_vendor: null, backup: {}, unconfigured: {} },
];

const VLAN_TEMPLATE = {
  id: "cisco_ios/vlan",
  vendor: "cisco_ios",
  title: "Add a VLAN",
  description: "Creates a VLAN and, optionally, its routed interface.",
  schema: {
    properties: {
      vlan_id: { maximum: 4094, minimum: 2, title: "Vlan Id", type: "integer" },
      name: { pattern: "^[A-Za-z0-9_-]{1,32}$", title: "Name", type: "string" },
      svi_ip: { anyOf: [{ type: "string" }, { type: "null" }], default: null, title: "Svi Ip" },
    },
    required: ["vlan_id", "name"],
  },
};

const TEMPLATES = [
  VLAN_TEMPLATE,
  { id: "mikrotik_routeros/baseline", vendor: "mikrotik_routeros", title: "MikroTik baseline", schema: {} },
];

function change(overrides = {}) {
  const at = "2026-11-07T10:00:00Z";
  return {
    id: CHANGE_ID,
    title: "Add VLAN 40",
    status: "pending_approval",
    device_id: DEVICE_ID,
    device_name: "CORE-SW-1",
    mgmt_ip: "127.0.0.12",
    vendor: "cisco_ios",
    source: { kind: "template", template: "cisco_ios/vlan" },
    commands: "vlan 40\n name LAB",
    violations: [],
    protected_interfaces: ["GigabitEthernet0/0"],
    before_version: 3,
    after_version: null,
    created_by: { id: USERS.engineer.id, username: "erin" },
    approved_by: null,
    override_reason: null,
    result: null,
    timeline: [
      { at, status: "draft", by: { id: USERS.engineer.id, username: "erin" }, note: null },
      { at, status: "pending_approval", by: { id: USERS.engineer.id, username: "erin" }, note: null },
    ],
    ...overrides,
  };
}

describe("side-by-side diff", () => {
  it("shows both sides as text with markers and collapsed unchanged runs", () => {
    render(
      <DiffView
        fromLabel="v1"
        toLabel="v2"
        rows={[
          { kind: "same", left_no: 1, right_no: 1, left: "hostname R1", right: "hostname R1" },
          { kind: "skip", count: 12 },
          { kind: "changed", left_no: 14, right_no: 14, left: " transport input telnet", right: " transport input ssh" },
          { kind: "added", left_no: null, right_no: 15, left: null, right: "<script>alert(1)</script>" },
        ]}
      />,
    );
    expect(screen.getByRole("table", { name: "Differences between v1 and v2" })).toBeInTheDocument();
    expect(screen.getByText("… 12 unchanged lines …")).toBeInTheDocument();
    const changed = screen.getByText("transport input telnet", { exact: false }).closest('[role="row"]');
    expect(changed).toHaveClass("diff-changed");
    expect(within(changed).getAllByText("~")).toHaveLength(2);
    // Device text is shown literally, never parsed as HTML.
    expect(screen.getByText("<script>alert(1)</script>")).toBeInTheDocument();
    expect(document.querySelector("script")).toBeNull();
  });
});

describe("new change form", () => {
  it("builds the form from the template schema and previews the rendered commands", async () => {
    let previewBody = null;
    mockApi({
      ...signedIn("engineer"),
      "GET /api/configs": DEVICES,
      "GET /api/templates": TEMPLATES,
      "POST /api/changes/preview": ({ body }) => {
        previewBody = body;
        return { commands: "vlan 40\n name LAB", violations: [], protected_interfaces: ["GigabitEthernet0/0"] };
      },
    });
    renderAt("/changes/new");
    const user = userEvent.setup();

    const device = await screen.findByLabelText("Device");
    expect(within(device).queryByText(/AP-1/)).toBeNull();
    await user.selectOptions(device, DEVICE_ID);
    const template = screen.getByLabelText("Template");
    // Only templates for the device's vendor are offered.
    expect(within(template).queryByText("MikroTik baseline")).toBeNull();
    await user.selectOptions(template, "cisco_ios/vlan");

    expect(screen.getByLabelText("VLAN ID")).toHaveAttribute("type", "number");
    expect(screen.getByLabelText("SVI IP (optional)")).toBeInTheDocument();
    await user.type(screen.getByLabelText("VLAN ID"), "40");
    await user.type(screen.getByLabelText("Name"), "LAB");
    await user.click(screen.getByRole("button", { name: "Preview (dry run)" }));

    expect(await screen.findByText("Passed the denylist check.")).toBeInTheDocument();
    expect(previewBody).toEqual({
      device_id: DEVICE_ID,
      template: "cisco_ios/vlan",
      variables: { vlan_id: 40, name: "LAB" },
    });
    expect(screen.getByText(/Protected \(management and uplink\) interfaces: GigabitEthernet0\/0/)).toBeInTheDocument();
  });

  it("shows blocked lines from the denylist", async () => {
    mockApi({
      ...signedIn("engineer"),
      "GET /api/configs": DEVICES,
      "GET /api/templates": TEMPLATES,
      "POST /api/changes/preview": {
        commands: "reload",
        violations: [{ line: 1, text: "reload", reason: "reloads the device" }],
        protected_interfaces: [],
      },
    });
    // Arrives prefilled, as from "Create change from fix".
    renderAt({ pathname: "/changes/new", state: { deviceId: DEVICE_ID, commands: "reload", title: "Bad idea" } });
    const user = userEvent.setup();

    expect(await screen.findByLabelText("Commands")).toHaveValue("reload");
    await user.click(screen.getByRole("button", { name: "Preview (dry run)" }));
    const blocked = await screen.findByText(/can't be submitted/);
    expect(blocked.closest("[role=alert]")).toHaveTextContent("Line 1: reload reloads the device");
    expect(screen.queryByText("Passed the denylist check.")).toBeNull();
  });

  it("is not offered to viewers", async () => {
    mockApi({ ...signedIn("viewer"), "GET /api/configs": DEVICES, "GET /api/templates": TEMPLATES });
    renderAt("/changes/new");
    expect(await screen.findByText("Only engineers and admins can create changes.")).toBeInTheDocument();
  });
});

describe("change detail and approval", () => {
  it("does not let the creator approve their own change (four-eyes rule)", async () => {
    mockApi({ ...signedIn("engineer"), [`GET /api/changes/${CHANGE_ID}`]: change() });
    renderAt(`/changes/${CHANGE_ID}`);

    expect(await screen.findByText(/someone else must review and approve it/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
    // Timeline: one entry per status change, with who did it.
    const timeline = screen.getByRole("heading", { name: "Timeline" }).closest("section");
    expect(within(timeline).getAllByRole("listitem")).toHaveLength(2);
    expect(within(timeline).getByText("Waiting for approval")).toBeInTheDocument();
  });

  it("lets a second engineer approve", async () => {
    let approved = null;
    const other = { ...USERS.engineer, id: "f".repeat(24), username: "frank" };
    mockApi({
      ...signedIn("engineer"),
      "GET /api/auth/me": { user: other, csrf_token: "csrf" },
      [`GET /api/changes/${CHANGE_ID}`]: change(),
      [`POST /api/changes/${CHANGE_ID}/approve`]: ({ body }) => {
        approved = body;
        return change({ status: "approved" });
      },
    });
    renderAt(`/changes/${CHANGE_ID}`);
    const user = userEvent.setup();

    await user.type(await screen.findByLabelText("Comment (optional)"), "Looks right");
    await user.click(screen.getByRole("button", { name: "Approve" }));
    expect(approved).toEqual({ comment: "Looks right" });
  });

  it("makes an admin creator give an override reason", async () => {
    let approved = null;
    mockApi({
      ...signedIn("admin"),
      [`GET /api/changes/${CHANGE_ID}`]: change({ created_by: { id: USERS.admin.id, username: "alice" } }),
      [`POST /api/changes/${CHANGE_ID}/approve`]: ({ body }) => {
        approved = body;
        return change({ status: "approved" });
      },
    });
    renderAt(`/changes/${CHANGE_ID}`);
    const user = userEvent.setup();

    const reason = await screen.findByLabelText("Override reason (required)");
    const approve = screen.getByRole("button", { name: "Approve" });
    expect(approve).toBeDisabled();
    await user.type(reason, "Night outage, no second engineer on call");
    expect(approve).toBeEnabled();
    await user.click(approve);
    expect(approved).toEqual({ override_reason: "Night outage, no second engineer on call" });
  });

  it("shows the agent's result after a rollback", async () => {
    mockApi({
      ...signedIn("viewer"),
      [`GET /api/changes/${CHANGE_ID}`]: change({
        status: "rolled_back",
        result: { status: "rolled_back", error: "verify_failed", log: "configure confirm skipped" },
      }),
    });
    renderAt(`/changes/${CHANGE_ID}`);

    const panel = (await screen.findByRole("heading", { name: "Agent result" })).closest("section");
    expect(within(panel).getByText("verify_failed")).toBeInTheDocument();
    expect(within(panel).getByText("configure confirm skipped")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Review" })).toBeNull();
  });
});

describe("protected interface names", () => {
  it("shows each interface once, in its long form", async () => {
    const { interfaceNames } = await import("../pages/configParts.jsx");
    expect(interfaceNames(["Gi1/0/1", "Gi1/0/2", "GigabitEthernet1/0/1", "GigabitEthernet1/0/2", "Vlan99"])).toBe(
      "GigabitEthernet1/0/1, GigabitEthernet1/0/2, Vlan99",
    );
  });
});
