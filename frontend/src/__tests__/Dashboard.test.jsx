import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import App from "../App.jsx";
import { AuthProvider } from "../auth/AuthProvider.jsx";
import { mockApi, signedIn, SUMMARY } from "./fakeApi.js";

function renderAt(path = "/") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  );
}

const ALERTS = [
  {
    id: "1".repeat(24),
    key: "dup:10.10.20.5",
    type: "duplicate_ip",
    severity: "critical",
    status: "open",
    message: '<img src=x onerror="alert(1)"> uses 10.10.20.5',
    target: {},
    details: {},
    opened_at: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    occurrences: 3,
  },
  {
    id: "2".repeat(24),
    key: "usage:labs",
    type: "subnet_usage",
    severity: "warning",
    status: "open",
    message: "10.10.20.0/24 is 80% full",
    target: {},
    details: {},
    opened_at: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    occurrences: 1,
  },
];

describe("dashboard widgets", () => {
  it("shows device, alert, IP and agent cards from the summary", async () => {
    mockApi(signedIn("viewer"));
    renderAt("/");
    const devices = await screen.findByRole("region", { name: "Devices" });
    expect(within(devices).getByRole("link", { name: /SNMP error/ })).toHaveAttribute(
      "href",
      "/devices?status=snmp_error",
    );
    // The status bar is an image with a text alternative, not colour alone.
    expect(within(devices).getByRole("img", { name: "4 up, 1 with SNMP errors, 0 down" })).toBeInTheDocument();

    const alerts = screen.getByRole("region", { name: "Alerts" });
    expect(within(alerts).getByText("1 critical")).toBeInTheDocument();
    expect(within(alerts).getByText("1 warning")).toBeInTheDocument();

    const ip = screen.getByRole("region", { name: "IP space" });
    expect(within(ip).getByRole("link", { name: "1 duplicate IP" })).toHaveAttribute("href", "/ip#duplicates");

    expect(screen.getByRole("region", { name: "Agent" })).toHaveTextContent("Reporting");
  });

  it("warns when no agent has reported", async () => {
    mockApi(signedIn("viewer", { "GET /api/dashboard/summary": { ...SUMMARY, last_agent_check_in: null } }));
    renderAt("/");
    expect(await screen.findByText("No agent has reported yet")).toBeInTheDocument();
  });
});

describe("open alerts board", () => {
  it("sorts alerts into severity columns and switches to a list with the keyboard", async () => {
    mockApi(signedIn("viewer", { "GET /api/alerts": ALERTS }));
    renderAt("/");
    const critical = await screen.findByRole("group", { name: "Critical alerts" });
    // Device-supplied text stays text.
    expect(await within(critical).findByText('<img src=x onerror="alert(1)"> uses 10.10.20.5')).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
    expect(within(critical).getByText("Seen 3×")).toBeInTheDocument();
    expect(within(screen.getByRole("group", { name: "Warning alerts" })).getByText("10.10.20.0/24 is 80% full"))
      .toBeInTheDocument();

    const user = userEvent.setup();
    const board = screen.getByRole("tab", { name: "Board" });
    expect(board).toHaveAttribute("aria-selected", "true");
    board.focus();
    await user.keyboard("{ArrowRight}");
    const list = screen.getByRole("tab", { name: "List" });
    expect(list).toHaveAttribute("aria-selected", "true");
    expect(list).toHaveFocus();
    expect(screen.queryByRole("group", { name: "Critical alerts" })).toBeNull();
    expect(screen.getByRole("tabpanel")).toHaveTextContent("10.10.20.0/24 is 80% full");
  });
});

describe("shell", () => {
  it("badges the Alerts link with the open count and shows breadcrumbs", async () => {
    mockApi(signedIn("viewer"));
    renderAt("/devices");
    const nav = await screen.findByRole("navigation", { name: "Main" });
    expect(await within(nav).findByRole("link", { name: "Alerts, 2 open" })).toBeInTheDocument();
    const crumbs = screen.getByRole("navigation", { name: "Breadcrumb" });
    expect(within(crumbs).getByRole("link", { name: "NetMap" })).toHaveAttribute("href", "/");
    expect(within(crumbs).getByText("Devices")).toHaveAttribute("aria-current", "page");
  });

  it("focuses the Ask box when / is pressed outside a text field", async () => {
    mockApi(signedIn("viewer"));
    renderAt("/");
    const box = await screen.findByRole("textbox", { name: "Ask NetMap" });
    await userEvent.setup().keyboard("/");
    expect(box).toHaveFocus();
    expect(box).toHaveValue("");
  });
});
