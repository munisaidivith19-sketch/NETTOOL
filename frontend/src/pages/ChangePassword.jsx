import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthProvider.jsx";
import { ErrorNote, Field, PageHead, SuccessNote } from "../components/ui.jsx";

const MIN_LENGTH = 12; // CLAUDE.md 7.1; the backend also rejects common passwords

/*
 * Used twice: as a full screen when the account must change its password (first login, or
 * after an admin reset), and as a normal page from the top bar.
 */
export default function ChangePassword({ forced = false }) {
  const { user, changePassword, logout } = useAuth();
  const navigate = useNavigate();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const [error, setError] = useState(null);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  const mismatch = repeat.length > 0 && next !== repeat;

  async function submit(event) {
    event.preventDefault();
    if (next !== repeat) return;
    setBusy(true);
    setError(null);
    try {
      await changePassword(current, next);
      setCurrent("");
      setNext("");
      setRepeat("");
      if (forced) navigate("/", { replace: true });
      else setDone(true);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  const form = (
    <form className={forced ? "auth-card" : "panel form-panel"} onSubmit={submit} aria-labelledby="pw-title">
      {forced ? (
        <>
          <h1 id="pw-title">Choose a new password</h1>
          <p className="muted">
            Signed in as <strong>{user.username}</strong>. You must set your own password before you continue.
          </p>
        </>
      ) : (
        <h2 id="pw-title" className="visually-hidden">
          Change password
        </h2>
      )}
      <ErrorNote error={error} />
      <SuccessNote>{done && "Password changed."}</SuccessNote>
      <label className="field">
        <span>Current password</span>
        <input
          type="password"
          autoComplete="current-password"
          value={current}
          onChange={(e) => setCurrent(e.target.value)}
          required
          maxLength={256}
        />
      </label>
      <Field label="New password" hint={`At least ${MIN_LENGTH} characters. Common passwords are refused.`}>
        <input
          type="password"
          autoComplete="new-password"
          value={next}
          onChange={(e) => setNext(e.target.value)}
          required
          minLength={MIN_LENGTH}
          maxLength={256}
        />
      </Field>
      <Field label="Repeat new password" error={mismatch && "The passwords don’t match."}>
        <input
          type="password"
          autoComplete="new-password"
          value={repeat}
          onChange={(e) => setRepeat(e.target.value)}
          required
        />
      </Field>
      <div className="form-actions">
        <button type="submit" className="button" disabled={busy || mismatch}>
          {busy ? "Saving…" : "Change password"}
        </button>
        {forced && (
          <button type="button" className="button button-secondary" onClick={logout}>
            Sign out
          </button>
        )}
      </div>
    </form>
  );

  if (forced) return <div className="auth-screen">{form}</div>;
  return (
    <>
      <PageHead title="Change password" />
      {form}
    </>
  );
}
