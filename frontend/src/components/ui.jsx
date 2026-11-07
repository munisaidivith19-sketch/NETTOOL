/*
 * Small building blocks used by every page. All text is rendered by React as text nodes, so
 * device names, sysDescr, alert messages and audit details can never inject HTML.
 */
import { cloneElement, useEffect, useId, useRef, useState } from "react";
import { formatCount, formatPercent, formatSize } from "../format.js";

export function Panel({ title, actions, children, className = "", id: anchor }) {
  const id = useId();
  return (
    <section id={anchor} className={`panel ${className}`} aria-labelledby={title ? id : undefined}>
      {(title || actions) && (
        <div className="panel-head">
          {title && <h2 id={id}>{title}</h2>}
          {actions && <div className="panel-actions">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

/*
 * A form field whose hint and error sit outside the <label>, so the input's accessible name
 * is just the label text; the hint is linked with aria-describedby instead.
 */
export function Field({ label, hint, error, children, className = "" }) {
  const id = useId();
  const hintId = hint ? `${id}-hint` : undefined;
  return (
    <div className={`field ${className}`}>
      <label htmlFor={id}>{label}</label>
      {cloneElement(children, { id, "aria-describedby": hintId, "aria-invalid": error ? true : undefined })}
      {hint && (
        <small id={hintId} className="muted">
          {hint}
        </small>
      )}
      {error && <small className="field-error">{error}</small>}
    </div>
  );
}

export function PageHead({ title, children }) {
  return (
    <div className="page-head">
      <h1>{title}</h1>
      {children && <div className="page-actions">{children}</div>}
    </div>
  );
}

export function ErrorNote({ error, children }) {
  if (!error && !children) return null;
  return (
    <p className="notice notice-error" role="alert">
      {children ?? error.message}
    </p>
  );
}

export function SuccessNote({ children }) {
  if (!children) return null;
  return (
    <p className="notice notice-ok" role="status">
      {children}
    </p>
  );
}

export function Loading({ what = "Loading" }) {
  return (
    <p className="muted" role="status">
      {what}…
    </p>
  );
}

export function Empty({ children }) {
  return <p className="empty">{children}</p>;
}

/* Subnet usage: a native <meter> (no inline styles needed, so the strict CSP stays happy). */
export function UsageBar({ usage, threshold = 80 }) {
  const percent = Math.min(Math.max(usage.percent ?? 0, 0), 100);
  return (
    <div className="usage">
      <meter
        className="usage-meter"
        min={0}
        max={100}
        low={threshold - 10}
        high={threshold}
        optimum={0}
        value={percent}
        aria-label={`${formatPercent(usage.percent)} used`}
      />
      <span className="usage-text">
        <strong>{formatPercent(usage.percent)}</strong>{" "}
        <span className="muted">
          {formatCount(usage.used)} of {formatSize(usage.usable)}
        </span>
      </span>
    </div>
  );
}

export function Badge({ tone = "neutral", children, title }) {
  return (
    <span className={`badge badge-${tone}`} title={title}>
      {children}
    </span>
  );
}

const SEVERITY_TONE = { critical: "down", warning: "warn", info: "neutral" };

export function SeverityBadge({ severity }) {
  return <Badge tone={SEVERITY_TONE[severity] ?? "neutral"}>{severity}</Badge>;
}

/*
 * A modal dialog. Focus moves into it, Tab stays inside, Escape closes it unless
 * `dismissable` is false (used for the agent key, which must be acknowledged on purpose).
 */
export function Dialog({ title, onClose, dismissable = true, children }) {
  const titleId = useId();
  const ref = useRef(null);

  useEffect(() => {
    const previous = document.activeElement;
    const node = ref.current;
    const focusable = () =>
      node.querySelectorAll("button, [href], input, select, textarea, [tabindex]:not([tabindex='-1'])");
    (focusable()[0] ?? node).focus();

    function onKey(event) {
      if (event.key === "Escape" && dismissable) {
        event.preventDefault();
        onClose();
      } else if (event.key === "Tab") {
        const items = [...focusable()];
        if (items.length === 0) return;
        const first = items[0];
        const last = items[items.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    }
    node.addEventListener("keydown", onKey);
    return () => {
      node.removeEventListener("keydown", onKey);
      previous?.focus?.();
    };
  }, [dismissable, onClose]);

  return (
    <div className="dialog-backdrop">
      <div className="dialog" role="dialog" aria-modal="true" aria-labelledby={titleId} ref={ref} tabIndex={-1}>
        <div className="dialog-head">
          <h2 id={titleId}>{title}</h2>
          {dismissable && (
            <button type="button" className="icon-button" onClick={onClose} aria-label="Close">
              ×
            </button>
          )}
        </div>
        {children}
      </div>
    </div>
  );
}

export function CopyButton({ text, label = "Copy" }) {
  const [state, setState] = useState("idle");
  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setState("copied");
    } catch {
      setState("failed"); // e.g. clipboard blocked: the text is still selectable on screen
    }
  }
  return (
    <button type="button" className="button button-secondary" onClick={copy}>
      {state === "copied" ? "Copied" : state === "failed" ? "Copy failed – select it by hand" : label}
    </button>
  );
}

/* A confirm step for destructive actions, inline instead of window.confirm(). */
export function ConfirmButton({ children, confirmLabel = "Yes, do it", onConfirm, disabled }) {
  const [asking, setAsking] = useState(false);
  if (!asking) {
    return (
      <button type="button" className="button button-danger" onClick={() => setAsking(true)} disabled={disabled}>
        {children}
      </button>
    );
  }
  return (
    <span className="confirm">
      <span>Are you sure?</span>
      <button
        type="button"
        className="button button-danger"
        onClick={async () => {
          await onConfirm();
          setAsking(false);
        }}
      >
        {confirmLabel}
      </button>
      <button type="button" className="button button-secondary" onClick={() => setAsking(false)}>
        Cancel
      </button>
    </span>
  );
}
