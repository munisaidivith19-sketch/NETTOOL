import { useState } from "react";
import { useAuth } from "../auth/AuthProvider.jsx";
import { ErrorNote } from "../components/ui.jsx";
import ThemeToggle from "../components/ThemeToggle.jsx";

const NOTICES = {
  expired: "Your session has expired. Sign in again.",
  "signed-out": "You are signed out.",
};

export default function Login() {
  const { login, notice } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username.trim(), password);
    } catch (err) {
      // The backend says only "Invalid username or password" (it never reveals which), or
      // asks the user to wait when the account or IP is rate-limited.
      setError(err);
      setPassword("");
    } finally {
      setBusy(false);
    }
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
