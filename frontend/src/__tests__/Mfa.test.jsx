import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import App from "../App.jsx";
import { AuthProvider } from "../auth/AuthProvider.jsx";
import { groupKey, QrCode } from "../components/mfaParts.jsx";
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

const SIGNED_OUT = { "GET /api/auth/me": { status: 401, body: { detail: "Not signed in or session expired" } } };
const CODES = ["ABCDE-FGHJK", "LMNPQ-RSTUV", "WXYZ2-34567", "89ABC-DEFGH", "JKLMN-PQRST",
  "UVWXY-Z2345", "6789A-BCDEF", "GHJKL-MNPQR", "STUVW-XYZ23", "45678-9ABCD"];
const SETUP = {
  secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
  otpauth_uri: "otpauth://totp/NetMap:alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=NetMap",
  qr: ["101", "010", "101"],
  expires_in_seconds: 600,
};

async function passwordStep(user) {
  await user.type(await screen.findByLabelText("Username"), "alice");
  await user.type(screen.getByLabelText("Password"), "right-password-123");
  await user.click(screen.getByRole("button", { name: "Sign in" }));
}

describe("two-step sign-in", () => {
  it("asks for a code after the password, then signs in", async () => {
    const fetchMock = mockApi({
      ...signedIn("admin"),
      ...SIGNED_OUT,
      "POST /api/auth/login": { mfa_required: true },
      "POST /api/auth/mfa/verify": ({ body }) =>
        body.code === "123456"
          ? { user: USERS.admin, csrf_token: "csrf-after-mfa" }
          : { status: 401, body: { detail: "Invalid or expired code" } },
    });
    renderAt("/");
    const user = userEvent.setup();
    await passwordStep(user);

    const code = await screen.findByLabelText("Authentication code");
    expect(code).toHaveAttribute("autocomplete", "one-time-code");
    expect(code).toHaveAttribute("inputmode", "numeric");
    await user.type(code, "65a4321"); // letters are dropped, max 6 digits
    expect(code).toHaveValue("654321");
    await user.click(screen.getByRole("button", { name: "Verify" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid or expired code");

    await user.type(screen.getByLabelText("Authentication code"), "123456");
    await user.click(screen.getByRole("button", { name: "Verify" }));
    expect(await screen.findByRole("heading", { name: "Dashboard" })).toBeInTheDocument();
    const verify = fetchMock.mock.calls.filter(([url]) => url === "/api/auth/mfa/verify").at(-1);
    expect(JSON.parse(verify[1].body)).toEqual({ code: "123456" });
  });

  it("accepts a recovery code and warns when few are left", async () => {
    const fetchMock = mockApi({
      ...signedIn("admin"),
      ...SIGNED_OUT,
      "POST /api/auth/login": { mfa_required: true },
      "POST /api/auth/mfa/verify": { user: USERS.admin, csrf_token: "c", recovery_codes_left: 1 },
    });
    renderAt("/");
    const user = userEvent.setup();
    await passwordStep(user);
    await user.click(await screen.findByRole("button", { name: "Use a recovery code" }));
    await user.type(screen.getByLabelText("Recovery code"), "abcde-fghjk");
    await user.click(screen.getByRole("button", { name: "Verify" }));
    expect(await screen.findByText(/You signed in with a recovery code\. 1 left\./)).toBeInTheDocument();
    const verify = fetchMock.mock.calls.find(([url]) => url === "/api/auth/mfa/verify");
    expect(JSON.parse(verify[1].body)).toEqual({ recovery_code: "abcde-fghjk" });
  });

  it("forces an admin without MFA through setup and shows recovery codes before continuing", async () => {
    mockApi({
      ...signedIn("admin"),
      "GET /api/auth/me": { user: { ...USERS.admin, mfa_setup_required: true }, csrf_token: "c1" },
      "POST /api/auth/mfa/setup": SETUP,
      "POST /api/auth/mfa/enable": ({ body }) =>
        body.code === "123456"
          ? { recovery_codes: CODES, session: { user: { ...USERS.admin, mfa_enabled: true }, csrf_token: "c2" } }
          : { status: 400, body: { detail: "That code didn't match." } },
    });
    renderAt("/");
    const user = userEvent.setup();
    expect(await screen.findByRole("heading", { name: "Set up two-step sign-in" })).toBeInTheDocument();
    expect(screen.queryByRole("navigation")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Set up two-step sign-in" }));
    expect(await screen.findByRole("img", { name: /QR code/ })).toBeInTheDocument();
    expect(screen.getByText("JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Code from the app"), "000000");
    await user.click(screen.getByRole("button", { name: "Turn on" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("didn't match");

    await user.type(screen.getByLabelText("Code from the app"), "123456");
    await user.click(screen.getByRole("button", { name: "Turn on" }));
    const list = await screen.findByRole("list", { name: "" });
    expect(within(list).getAllByRole("listitem")).toHaveLength(10);
    expect(screen.getByText("ABCDE-FGHJK")).toBeInTheDocument();
    // Still on the setup screen until the user confirms they saved the codes.
    expect(screen.queryByRole("heading", { name: "Dashboard" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /I have saved these codes/ }));
    expect(await screen.findByRole("heading", { name: "Dashboard" })).toBeInTheDocument();
  });

  it("goes to the setup screen when the server says MFA setup is required", async () => {
    mockApi({
      ...signedIn("admin"),
      "GET /api/dashboard/summary": { status: 403, body: { detail: "mfa_setup_required" } },
    });
    renderAt("/");
    expect(await screen.findByRole("heading", { name: "Set up two-step sign-in" })).toBeInTheDocument();
  });

  it("admins see the MFA column and can reset others but not themselves", async () => {
    mockApi({
      ...signedIn("admin"),
      "GET /api/users": [
        { ...USERS.admin, mfa_enabled: true },
        { ...USERS.engineer, id: "f".repeat(24), username: "frank", role: "admin", mfa_enabled: false },
        { ...USERS.viewer, mfa_enabled: true },
      ],
    });
    renderAt("/admin/users");
    const rows = await screen.findAllByRole("row");
    const own = rows.find((r) => within(r).queryByText("(you)"));
    expect(within(own).queryByRole("button", { name: "Reset two-step" })).not.toBeInTheDocument();
    const frank = rows.find((r) => within(r).queryByText("frank"));
    expect(within(frank).getByText("Not set up")).toBeInTheDocument();
    const victor = rows.find((r) => within(r).queryByText("victor"));
    expect(within(victor).getByRole("button", { name: "Reset two-step" })).toBeInTheDocument();
  });

  it("admins can't turn MFA off on the account page", async () => {
    mockApi({
      ...signedIn("admin"),
      "GET /api/auth/mfa": { enabled: true, required: true, recovery_codes_left: 2 },
    });
    renderAt("/account/security");
    expect(await screen.findByText(/get new ones below/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Turn off two-step sign-in" })).not.toBeInTheDocument();
    expect(screen.getByText("Two-step sign-in is required for admin accounts.")).toBeInTheDocument();
  });
});

describe("QrCode", () => {
  it("draws only dark modules, with a quiet zone, as one path", () => {
    const { container } = render(<QrCode rows={["10", "01"]} label="qr" />);
    expect(container.querySelector("svg")).toHaveAttribute("viewBox", "0 0 10 10");
    expect(container.querySelector("path").getAttribute("d")).toBe("M4 4h1v1h-1zM5 5h1v1h-1z");
    expect(container.querySelector("[style]")).toBeNull(); // no inline styles (CSP)
  });

  it("groups the key in fours", () => {
    expect(groupKey("ABCDEFGHIJ")).toBe("ABCD EFGH IJ");
  });
});
