import { useState } from "react";
import { useAuth } from "../auth/AuthProvider.jsx";
import { ErrorNote } from "../components/ui.jsx";
import ThemeToggle from "../components/ThemeToggle.jsx";

const NOTICES = {
  expired: "Your session has expired. Sign in again.",
  "signed-out": "You are signed out.",
};

/*
 * Second step for accounts with two-step sign-in: a 6-digit code from the authenticator app,
 * or one of the recovery codes. The password step left only a short-lived challenge cookie
 * (5 minutes, 5 tries); there is no session until this step succeeds.
 */
function CodeStep({ onCancel }) {
  const { verifyMfa } = useAuth();
  const [useRecovery, setUseRecovery] = useState(false);
  const [value, setValue] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await verifyMfa(useRecovery ? { recovery_code: value.trim() } : { code: value.trim() });
    } catch (err) {
      setError(err);
      setValue("");
      setBusy(false);
    }
  }

  return (
    <form className="auth-card" onSubmit={submit} aria-labelledby="code-title">
      <h1 id="code-title">Two-step sign-in</h1>
      <p className="muted">
        {useRecovery
          ? "Enter one of the recovery codes you saved when you set up two-step sign-in. Each code works once."
          : "Enter the 6-digit code from your authenticator app."}
      </p>
      <ErrorNote error={error} />
      {useRecovery ? (
        <label className="field">
          <span>Recovery code</span>
          <input
            name="recovery_code"
            autoComplete="off"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            required
            maxLength={14}
            placeholder="XXXXX-XXXXX"
            autoCapitalize="characters"
            spellCheck={false}
          />
        </label>
      ) : (
        <label className="field">
          <span>Authentication code</span>
          <input
            name="code"
            className="code-input"
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="[0-9]{6}"
            title="6 digits"
            value={value}
            onChange={(e) => setValue(e.target.value.replace(/\D/g, "").slice(0, 6))}
            required
            autoFocus
          />
        </label>
      )}
      <button type="submit" className="button" disabled={busy}>
        {busy ? "Checking…" : "Verify"}
      </button>
      <div className="auth-foot">
        <button
          type="button"
          className="link-button"
          onClick={() => {
            setUseRecovery(!useRecovery);
            setValue("");
            setError(null);
          }}
        >
          {useRecovery ? "Use a code from the app" : "Use a recovery code"}
        </button>
        <button type="button" className="link-button" onClick={onCancel}>
          Start again
        </button>
      </div>
    </form>
  );
}

export default function Login() {
  const { login, notice } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [codeStep, setCodeStep] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await login(username.trim(), password);
      setPassword("");
      if (result.mfaRequired) setCodeStep(true);
    } catch (err) {
      // The backend says only "Invalid username or password" (it never reveals which), or
      // asks the user to wait when the account or IP is rate-limited.
      setError(err);
      setPassword("");
    } finally {
      setBusy(false);
    }
  }

  if (codeStep) {
    return (
      <div className="auth-screen">
        <CodeStep onCancel={() => setCodeStep(false)} />
      </div>
    );
  }

  return (
    <div className="auth-screen">
      <form className="auth-card" onSubmit={submit} aria-labelledby="login-title">
        <h1 id="login-title">Sign in to NetMap</h1>
        {notice && !error && (
          <p className="notice" role="status">
            {NOTICES[notice]}
          </p>
        )}
        <ErrorNote error={error} />
        <label className="field">
          <span>Username</span>
          <input
            name="username"
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            maxLength={32}
            autoCapitalize="none"
            spellCheck={false}
          />
        </label>
        <label className="field">
          <span>Password</span>
          <input
            name="password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            maxLength={256}
          />
        </label>
        <button type="submit" className="button" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
        <div className="auth-foot">
          <ThemeToggle />
        </div>
      </form>
    </div>
  );
}
