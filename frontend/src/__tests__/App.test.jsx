import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import App from "../App.jsx";
import { AuthProvider } from "../auth/AuthProvider.jsx";
import StatusMark from "../components/StatusMark.jsx";
import { mockApi, signedIn, USERS } from "./fakeApi.js";

function renderAt(path = "/") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  );
}

const SUBNET = {
  id: "5".repeat(24),
  network: "2001:db8:10:10::/64",
  version: 6,
  prefixlen: 64,
  source: "discovered",
  name: "Staff v6",
  vlan: 10,
  gateway: null,
  reserved_ranges: [],
  usage: {
    size: "18446744073709551616",
    usable: "18446744073709551615",
    used: "3",
    free: "18446744073709551612",
    percent: 0,
  },
};

describe("signing in", () => {
  it("shows the login page when there is no session, then the dashboard", async () => {
    const fetchMock = mockApi({
      ...signedIn("engineer"),
      "GET /api/auth/me": { status: 401, body: { detail: "Not signed in or session expired" } },
      "POST /api/auth/login": ({ body }) =>
        body.password === "right-password-123"
          ? { user: USERS.engineer, csrf_token: "csrf-from-login" }
          : { status: 401, body: { detail: "Invalid username or password" } },
    });
    renderAt("/");
    const user = userEvent.setup();

    await user.type(await screen.findByLabelText("Username"), "erin");
    await user.type(screen.getByLabelText("Password"), "wrong-password");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid username or password");
    expect(screen.getByLabelText("Password")).toHaveValue(""); // cleared after a failure

    await user.type(screen.getByLabelText("Password"), "right-password-123");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("heading", { name: "Dashboard" })).toBeInTheDocument();
    expect(screen.getByText("erin")).toBeInTheDocument();
    expect(screen.getByText("Engineer")).toBeInTheDocument();

    // The login's CSRF token is what later writes send.
    await user.click(screen.getByRole("button", { name: "Sign out" }));
    const logout = fetchMock.mock.calls.find(([url]) => url === "/api/auth/logout");
    expect(logout[1].headers["X-CSRF-Token"]).toBe("csrf-from-login");
    expect(await screen.findByText("You are signed out.")).toBeInTheDocument();
  });

  it("returns to the login page with a notice when the session expires", async () => {
    let expired = false;
    mockApi({
      ...signedIn("viewer"),
      "GET /api/devices": () => (expired ? { status: 401, body: { detail: "expired" } } : []),
    });
    renderAt("/devices");
    expect(await screen.findByRole("heading", { name: "Devices" })).toBeInTheDocument();
    expired = true;
    const user = userEvent.setup();
    await user.type(screen.getByRole("searchbox"), "core");
    await user.click(screen.getByRole("button", { name: "Search" }));
    expect(await screen.findByText("Your session has expired. Sign in again.")).toBeInTheDocument();
  });

  it("forces a password change before anything else", async () => {
    mockApi({
      ...signedIn("admin"),
      "GET /api/auth/me": { user: { ...USERS.admin, must_change_password: true }, csrf_token: "c" },
      "POST /api/auth/change-password": ({ body }) => {
        expect(body).toEqual({ current_password: "Temp-password-1", new_password: "My-own-long-pass-2" });
        return { user: USERS.admin, csrf_token: "c2" };
      },
    });
    renderAt("/admin/users");
    const user = userEvent.setup();
    expect(await screen.findByRole("heading", { name: "Choose a new password" })).toBeInTheDocument();
    expect(screen.queryByRole("navigation")).toBeNull();

    await user.type(screen.getByLabelText("Current password"), "Temp-password-1");
    await user.type(screen.getByLabelText("New password"), "My-own-long-pass-2");
    await user.type(screen.getByLabelText("Repeat new password"), "My-own-long-pass-X");
    expect(screen.getByText("The passwords don’t match.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Change password" })).toBeDisabled();

    await user.clear(screen.getByLabelText("Repeat new password"));
    await user.type(screen.getByLabelText("Repeat new password"), "My-own-long-pass-2");
    await user.click(screen.getByRole("button", { name: "Change password" }));
    expect(await screen.findByRole("heading", { name: "Dashboard" })).toBeInTheDocument();
  });
});

describe("role-aware UI", () => {
  const routes = (role) =>
    signedIn(role, {
      "GET /api/subnets": [SUBNET],
      [`GET /api/subnets/${SUBNET.id}`]: SUBNET,
      [`GET /api/subnets/${SUBNET.id}/ips`]: { items: [], next_after: null },
    });

  it("viewers see no write actions and no admin menu", async () => {
    mockApi(routes("viewer"));
    renderAt("/ip");
    expect(await screen.findByText("2001:db8:10:10::/64")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add subnet" })).toBeNull();
    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(within(nav).queryByRole("link", { name: "Users" })).toBeNull();
  });

  it("viewers get no reserve form or edit buttons on a subnet", async () => {
    mockApi(routes("viewer"));
    renderAt(`/ip/subnets/${SUBNET.id}`);
    expect(await screen.findByRole("button", { name: "Find next free IP" })).toBeInTheDocument();
    expect(screen.queryByRole("form", { name: "Reserve an IP address" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Edit" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Delete" })).toBeNull();
  });

  it("engineers can add subnets and reserve, but see no admin menu", async () => {
    mockApi(routes("engineer"));
    renderAt(`/ip/subnets/${SUBNET.id}`);
    expect(await screen.findByRole("form", { name: "Reserve an IP address" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Edit" })).toBeInTheDocument();
    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(within(nav).queryByText("Admin")).toBeNull();
  });

  it("an admin page opened by a non-admin shows no access", async () => {
    mockApi(routes("engineer"));
    renderAt("/admin/agents");
    expect(await screen.findByRole("heading", { name: "No access" })).toBeInTheDocument();
  });

  it("next free IP fills the reserve form", async () => {
    mockApi({ ...routes("engineer"), [`GET /api/subnets/${SUBNET.id}/next-free`]: { subnet: SUBNET.network, ip: "2001:db8:10:10::2" } });
    renderAt(`/ip/subnets/${SUBNET.id}`);
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Find next free IP" }));
    expect(await screen.findByText("2001:db8:10:10::2")).toBeInTheDocument();
    expect(screen.getByLabelText("IP address")).toHaveValue("2001:db8:10:10::2");
  });
});

describe("IPv6 sizes", () => {
  it("shows a /64 exactly, never rounded through Number", async () => {
    mockApi(signedIn("viewer", { [`GET /api/subnets/${SUBNET.id}`]: SUBNET, [`GET /api/subnets/${SUBNET.id}/ips`]: { items: [], next_after: null } }));
    renderAt(`/ip/subnets/${SUBNET.id}`);
    expect(await screen.findByText("18,446,744,073,709,551,612")).toBeInTheDocument(); // free
    expect(screen.getByText(/2\^64 addresses/)).toBeInTheDocument();
    // Number() would have given ...551,616 for the free count; make sure that's not shown.
    expect(screen.queryByText("18,446,744,073,709,551,616")).toBeNull();
  });
});

describe("agent key", () => {
  it("is shown once, and the dialog can't be dismissed until the user confirms", async () => {
    const fetchMock = mockApi(
      signedIn("admin", {
        "GET /api/agents": [],
        "POST /api/agents": {
          id: "agt_0123456789abcdef",
          name: "Lab",
          key_fingerprint: "ab12cd34",
          created_at: new Date().toISOString(),
          created_by: "alice",
          key: "super-secret-agent-key-value",
        },
      }),
    );
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    renderAt("/admin/agents");
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Name"), "Lab");
    await user.click(screen.getByRole("button", { name: "Create agent key" }));

    const dialog = await screen.findByRole("dialog", { name: /copy it now/ });
    expect(within(dialog).getByDisplayValue("super-secret-agent-key-value")).toBeInTheDocument();
    expect(within(dialog).getByText(/only once/)).toBeInTheDocument();
    expect(within(dialog).queryByRole("button", { name: "Close" })).toBeNull();
    await user.keyboard("{Escape}");
    expect(screen.getByRole("dialog")).toBeInTheDocument(); // Escape doesn't close it

    const done = within(dialog).getByRole("button", { name: "Done" });
    expect(done).toBeDisabled();
    await user.click(within(dialog).getByLabelText("I have stored the key safely"));
    await user.click(done);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.queryByDisplayValue("super-secret-agent-key-value")).toBeNull();
    expect(setItem).not.toHaveBeenCalledWith(expect.anything(), expect.stringContaining("super-secret"));
    // The key was requested once; nothing asks for it again.
    expect(fetchMock.mock.calls.filter(([url, init]) => url === "/api/agents" && init.method === "POST")).toHaveLength(1);
  });
});

describe("alerts", () => {
  const ALERT = {
    id: "9".repeat(24),
    key: "duplicate_ip:4:x",
    type: "duplicate_ip",
    severity: "critical",
    status: "open",
    message: 'IP 10.0.0.5 is used by <img src=x onerror="alert(1)">',
    target: { type: "ip", ip: "10.0.0.5" },
    details: {},
    opened_at: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    occurrences: 1,
  };

  it("renders untrusted alert text as text", async () => {
    mockApi(signedIn("viewer", { "GET /api/alerts": [ALERT] }));
    renderAt("/alerts");
    expect(await screen.findByText(/onerror="alert\(1\)"/)).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
    expect(screen.queryByRole("button", { name: "Resolve" })).toBeNull(); // viewer
  });

  it("engineers can acknowledge and resolve", async () => {
    const calls = [];
    mockApi(
      signedIn("engineer", {
        "GET /api/alerts": [ALERT],
        [`POST /api/alerts/${ALERT.id}/acknowledge`]: ({ init }) => {
          calls.push(["ack", init.headers["X-CSRF-Token"]]);
          return { ...ALERT, acknowledged_by: "erin" };
        },
        [`POST /api/alerts/${ALERT.id}/resolve`]: () => {
          calls.push(["resolve"]);
          return { ...ALERT, status: "resolved" };
        },
      }),
    );
    renderAt("/alerts");
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Acknowledge" }));
    await user.click(screen.getByRole("button", { name: "Resolve" }));
    await waitFor(() => expect(calls).toEqual([["ack", "csrf-from-me"], ["resolve"]]));
  });
});

describe("layout", () => {
  it("shows the open-alert count from the summary", async () => {
    mockApi(signedIn("viewer"));
    renderAt("/");
    expect(await screen.findByRole("link", { name: "2 open alerts" })).toBeInTheDocument();
    expect(screen.getByText("Labs")).toBeInTheDocument();
  });

  it("toggles the phone menu", async () => {
    mockApi(signedIn("viewer"));
    renderAt("/");
    const button = await screen.findByRole("button", { name: "Menu" });
    expect(button).toHaveAttribute("aria-expanded", "false");
    await userEvent.setup().click(button);
    expect(button).toHaveAttribute("aria-expanded", "true");
  });

  it("renders device-supplied text as text, not HTML", () => {
    render(<StatusMark status="up" label={'<img src=x onerror="alert(1)">'} />);
    expect(screen.getByText('<img src=x onerror="alert(1)">')).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
  });
});

describe("theme toggle", () => {
  it("switches theme and remembers the choice", async () => {
    mockApi(signedIn("viewer"));
    renderAt("/");
    const user = userEvent.setup();
    const button = await screen.findByRole("button", { name: /Switch to (dark|light) theme/ });
    const target = button.getAttribute("aria-label").includes("dark") ? "dark" : "light";
    await user.click(button);
    expect(document.documentElement.dataset.theme).toBe(target);
    expect(window.localStorage.getItem("netmap.theme")).toBe(target);
  });

  it("still works when storage is blocked", async () => {
    mockApi(signedIn("viewer"));
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("blocked", "SecurityError");
    });
    renderAt("/");
    await userEvent.setup().click(await screen.findByRole("button", { name: /Switch to/ }));
    expect(document.documentElement.dataset.theme).toMatch(/dark|light/);
  });
});

describe("StatusMark", () => {
  it("falls back to the checking state for unknown values", () => {
    render(<StatusMark status="bogus" />);
    expect(screen.getByText("Checking")).toBeInTheDocument();
  });
});
