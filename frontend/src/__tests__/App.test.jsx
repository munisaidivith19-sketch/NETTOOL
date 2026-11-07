import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import App from "../App.jsx";
import StatusMark from "../components/StatusMark.jsx";

function renderApp(healthStatus = 200, body = { status: "ok", database: "ok" }) {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue(new Response(JSON.stringify(body), { status: healthStatus })),
  );
  return render(
    <MemoryRouter>
      <App />
    </MemoryRouter>,
  );
}

describe("App shell", () => {
  it("shows navigation with upcoming sections disabled", () => {
    renderApp();
    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(within(nav).getByRole("link", { name: "Overview" })).toHaveAttribute("aria-current", "page");
    expect(within(nav).getByText("Devices").closest("[aria-disabled]")).toHaveAttribute("aria-disabled", "true");
  });

  it("shows backend and database as up when healthy", async () => {
    renderApp();
    const rows = await screen.findAllByText("Up");
    expect(rows).toHaveLength(2);
    expect(screen.getByText(/Last checked/)).toBeInTheDocument();
  });

  it("explains a database outage", async () => {
    renderApp(503, { status: "degraded", database: "unavailable" });
    expect(await screen.findByText("Down")).toBeInTheDocument();
    expect(screen.getByText(/can’t reach MongoDB/)).toBeInTheDocument();
  });

  it("renders device-supplied text as text, not HTML", () => {
    render(<StatusMark status="up" label={'<img src=x onerror="alert(1)">'} />);
    expect(screen.getByText('<img src=x onerror="alert(1)">')).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
  });
});

describe("theme toggle", () => {
  it("switches theme and remembers the choice", async () => {
    renderApp();
    const user = userEvent.setup();
    const button = screen.getByRole("button", { name: /Switch to (dark|light) theme/ });
    const target = button.getAttribute("aria-label").includes("dark") ? "dark" : "light";
    await user.click(button);
    expect(document.documentElement.dataset.theme).toBe(target);
    expect(window.localStorage.getItem("netmap.theme")).toBe(target);
  });

  it("still works when storage is blocked", async () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("blocked", "SecurityError");
    });
    renderApp();
    await userEvent.setup().click(screen.getByRole("button", { name: /Switch to/ }));
    expect(document.documentElement.dataset.theme).toMatch(/dark|light/);
  });
});

describe("StatusMark", () => {
  it("falls back to the checking state for unknown values", () => {
    render(<StatusMark status="bogus" />);
    expect(screen.getByText("Checking")).toBeInTheDocument();
  });
});
