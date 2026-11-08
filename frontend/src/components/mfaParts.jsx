import { useState } from "react";
import { CopyButton, ErrorNote } from "./ui.jsx";

/*
 * The QR code from POST /api/auth/mfa/setup arrives as rows of "0"/"1". It is drawn as one SVG
 * path: no image, no data: URL and no inline style, so the strict CSP needs no exception.
 * Black on white whatever the theme, with a 4-module quiet zone, so phone cameras can read it.
 */
export function QrCode({ rows, label }) {
  const size = rows.length + 8;
  let d = "";
  rows.forEach((row, y) => {
    for (let x = 0; x < row.length; x += 1) {
      if (row[x] === "1") d += `M${x + 4} ${y + 4}h1v1h-1z`;
    }
  });
  return (
    <svg className="qr" viewBox={`0 0 ${size} ${size}`} role="img" aria-label={label} shapeRendering="crispEdges">
      <rect className="qr-bg" width={size} height={size} />
      <path className="qr-dots" d={d} />
    </svg>
  );
}

/* "JBSW Y3DP …": easier to type into an app by hand. */
export function groupKey(secret) {
  return secret.match(/.{1,4}/g).join(" ");
}

export function CodeField({ value, onChange, label = "Code from the app", id }) {
  return (
    <label className="field" htmlFor={id}>
      <span>{label}</span>
      <input
        id={id}
        className="code-input"
        inputMode="numeric"
        autoComplete="one-time-code"
        pattern="[0-9]{6}"
        title="6 digits"
        value={value}
        onChange={(e) => onChange(e.target.value.replace(/\D/g, "").slice(0, 6))}
        required
      />
    </label>
  );
}

export function RecoveryCodes({ codes }) {
  return (
    <div className="recovery">
      <p>
        <strong>Save these recovery codes now.</strong> Each one signs you in once if you lose your phone. They
        won't be shown again; NetMap keeps only a fingerprint of each.
      </p>
      <ol className="recovery-codes">
        {codes.map((code) => (
          <li key={code}>
            <code>{code}</code>
          </li>
        ))}
      </ol>
      <CopyButton text={codes.join("\n")} label="Copy codes" />
    </div>
  );
}

/*
 * Turning two-step sign-in on: scan → type a code → save the recovery codes. Used as the
 * forced screen for admins and on the account page.
 */
export function MfaEnrol({ username, enableMfa, onStart, onDone, doneLabel }) {
  const [setup, setSetup] = useState(null);
  const [code, setCode] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function start() {
    setBusy(true);
    setError(null);
    try {
      setSetup(await onStart());
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  async function confirm(event) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      setResult(await enableMfa(code));
    } catch (err) {
      setError(err);
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  if (result) {
    return (
      <div className="mfa-step">
        <RecoveryCodes codes={result.recovery_codes} />
        <div className="form-actions">
          <button type="button" className="button" onClick={() => onDone(result)}>
            {doneLabel}
          </button>
        </div>
      </div>
    );
  }

  if (!setup) {
    return (
      <div className="mfa-step">
        <p className="muted">
          You need an authenticator app on your phone, for example Google Authenticator, Microsoft Authenticator,
          Aegis or 2FAS.
        </p>
        <ErrorNote error={error} />
        <div className="form-actions">
          <button type="button" className="button" onClick={start} disabled={busy}>
            {busy ? "Starting…" : "Set up two-step sign-in"}
          </button>
        </div>
      </div>
    );
  }

  return (
    <form className="mfa-step" onSubmit={confirm}>
      <ol className="mfa-steps">
        <li>In the app, add an account and scan this code.</li>
        <li>Type the 6-digit code the app shows.</li>
      </ol>
      <QrCode rows={setup.qr} label={`QR code to add ${username} to an authenticator app`} />
      <details className="mfa-key">
        <summary>Can't scan? Enter the key by hand</summary>
        <p>
          Account: <strong>{username}</strong> · type: time-based
        </p>
        <p>
          <code className="mfa-secret">{groupKey(setup.secret)}</code>
        </p>
      </details>
      <ErrorNote error={error} />
      <CodeField id="mfa-enable-code" value={code} onChange={setCode} />
      <div className="form-actions">
        <button type="submit" className="button" disabled={busy || code.length !== 6}>
          {busy ? "Checking…" : "Turn on"}
        </button>
      </div>
    </form>
  );
}
