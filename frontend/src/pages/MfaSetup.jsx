import { useState } from "react";
import { mfa as mfaApi } from "../api/api.js";
import { useAuth } from "../auth/AuthProvider.jsx";
import { CodeField, MfaEnrol, RecoveryCodes } from "../components/mfaParts.jsx";
import { ConfirmButton, ErrorNote, Loading, PageHead, Panel, SuccessNote } from "../components/ui.jsx";
import { useResource } from "../hooks/useResource.js";

/* Full screen for an admin who has no two-step sign-in yet: nothing else works until it is on. */
export function ForcedMfaSetup() {
  const { user, enableMfa, finishMfaSetup, logout } = useAuth();
  return (
    <div className="auth-screen">
      <div className="auth-card auth-card-wide" aria-labelledby="mfa-title">
        <h1 id="mfa-title">Set up two-step sign-in</h1>
        <p className="muted">
          Signed in as <strong>{user.username}</strong>. Admin accounts need a second step at sign-in: a code from an
          app on your phone. A stolen password alone is then not enough.
        </p>
        <MfaEnrol
          username={user.username}
          onStart={mfaApi.setup}
          enableMfa={enableMfa}
          onDone={(result) => finishMfaSetup(result.session)}
          doneLabel="I have saved these codes – continue"
        />
        <div className="auth-foot">
          <button type="button" className="link-button" onClick={logout}>
            Sign out
          </button>
        </div>
      </div>
    </div>
  );
}

function NewRecoveryCodes() {
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState(null);
  const [error, setError] = useState(null);

  async function submit(event) {
    event.preventDefault();
    setError(null);
    try {
      setCodes((await mfaApi.recoveryCodes(code)).recovery_codes);
    } catch (err) {
      setError(err);
    }
    setCode("");
  }

  if (codes) return <RecoveryCodes codes={codes} />;
  return (
    <form className="inline-form" onSubmit={submit} aria-label="New recovery codes">
      <p className="muted">New codes replace all of your old ones.</p>
      <ErrorNote error={error} />
      <CodeField id="mfa-recovery-code" value={code} onChange={setCode} />
      <div className="form-actions">
        <button type="submit" className="button button-secondary" disabled={code.length !== 6}>
          Get new recovery codes
        </button>
      </div>
    </form>
  );
}

function TurnOff({ onDone }) {
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState(null);

  return (
    <form className="inline-form" onSubmit={(e) => e.preventDefault()} aria-label="Turn off two-step sign-in">
      <ErrorNote error={error} />
      <label className="field">
        <span>Password</span>
        <input
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          maxLength={256}
        />
      </label>
      <CodeField id="mfa-off-code" value={code} onChange={setCode} />
      <div className="form-actions">
        <ConfirmButton
          confirmLabel="Yes, turn it off"
          disabled={!password || code.length !== 6}
          onConfirm={async () => {
            setError(null);
            try {
              await mfaApi.disable(password, code);
              onDone();
            } catch (err) {
              setError(err);
            }
          }}
        >
          Turn off two-step sign-in
        </ConfirmButton>
      </div>
    </form>
  );
}

/* Account page: status, enrol, new recovery codes, and (not for admins) turn off. */
export default function MfaSettings() {
  const { user, enableMfa, finishMfaSetup } = useAuth();
  const status = useResource((signal) => mfaApi.status({ signal }), []);
  const [note, setNote] = useState(null);
  const data = status.data;

  return (
    <>
      <PageHead title="Two-step sign-in" />
      <Panel title="Status">
        <SuccessNote>{note}</SuccessNote>
        <ErrorNote error={status.error} />
        {status.loading && !data && <Loading />}
        {data && !data.enabled && (
          <MfaEnrol
            username={user.username}
            onStart={mfaApi.setup}
            enableMfa={enableMfa}
            onDone={(result) => {
              finishMfaSetup(result.session);
              setNote("Two-step sign-in is on.");
              status.reload();
            }}
            doneLabel="I have saved these codes"
          />
        )}
        {data?.enabled && (
          <p>
            Two-step sign-in is <strong>on</strong>. Recovery codes left: <strong>{data.recovery_codes_left}</strong>
            {data.recovery_codes_left <= 2 && " – get new ones below."}
          </p>
        )}
      </Panel>
      {data?.enabled && (
        <Panel title="Recovery codes">
          <NewRecoveryCodes />
        </Panel>
      )}
      {data?.enabled && !data.required && (
        <Panel title="Turn off">
          <TurnOff
            onDone={() => {
              setNote("Two-step sign-in is off.");
              status.reload();
            }}
          />
        </Panel>
      )}
      {data?.required && <p className="muted small">Two-step sign-in is required for admin accounts.</p>}
    </>
  );
}
