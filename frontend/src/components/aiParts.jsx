/*
 * Phase 7 building blocks: "Explain" buttons, device-type badges and the correction control,
 * and the subnet / uplink forecast panels. AI text is rendered as plain text, never HTML:
 * it may repeat device names or config lines an attacker chose.
 */
import { useState } from "react";
import { ai, predictions } from "../api/api.js";
import { useAuth } from "../auth/AuthProvider.jsx";
import { can } from "../auth/permissions.js";
import { DEVICE_TYPES, formatBps, formatCount, formatDate, formatDateTime } from "../format.js";
import { useResource } from "../hooks/useResource.js";
import ForecastChart from "./ForecastChart.jsx";
import { Badge, Empty, ErrorNote, Loading, Panel } from "./ui.jsx";

const METHODS = { prophet: "Prophet (seasonal model)", linear: "straight-line trend" };

/* ------------------------------------------------------------------ explanations */
export function ExplainButton({ request, label = "Explain" }) {
  const [state, setState] = useState({ busy: false, result: null, error: null, open: false });

  async function explain() {
    if (state.result) {
      setState((s) => ({ ...s, open: !s.open }));
      return;
    }
    setState({ busy: true, result: null, error: null, open: true });
    try {
      setState({ busy: false, result: await ai.explain(request), error: null, open: true });
    } catch (error) {
      setState({ busy: false, result: null, error, open: true });
    }
  }

  const { busy, result, error, open } = state;
  return (
    <div className="explain">
      <button type="button" className="button button-secondary" onClick={explain} disabled={busy} aria-expanded={open}>
        {busy ? "Explaining…" : open && result ? "Hide explanation" : label}
      </button>
      {open && error && <ErrorNote error={error} />}
      {open && result && (
        <div className="explain-box" role="status">
          <p className="explain-text">{result.text}</p>
          <p className="muted small">
            {result.source === "llm"
              ? "Written by a language model from NetMap's data. It can be wrong: check before acting."
              : "NetMap's built-in explanation."}
            {result.removed_lines > 0 &&
              ` ${result.removed_lines} line(s) with passwords, keys or communities were left out.`}
            {result.note && ` ${result.note}`}
          </p>
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ device types */
export function TypeBadge({ classification }) {
  if (!classification?.type) return null;
  const label = DEVICE_TYPES[classification.type] ?? classification.type;
  const manual = classification.source === "manual";
  const confidence =
    !manual && classification.confidence !== null && classification.confidence !== undefined
      ? ` · ${Math.round(classification.confidence * 100)} %`
      : "";
  return (
    <Badge tone="neutral" title={manual ? "Set by an engineer" : "Guessed by NetMap's classifier"}>
      {label}
      {manual ? " · set by hand" : confidence}
    </Badge>
  );
}

export function TypeInfo({ mac, classification, onChanged }) {
  const { user } = useAuth();
  const canCorrect = can(user, "type.correct");
  const [editing, setEditing] = useState(false);
  const [choice, setChoice] = useState(classification?.type ?? "pc");
  const [error, setError] = useState(null);

  async function run(fn) {
    setError(null);
    try {
      await fn();
      setEditing(false);
      onChanged?.();
    } catch (err) {
      setError(err);
    }
  }

  return (
    <div className="type-info">
      {classification ? (
        <>
          <TypeBadge classification={classification} />
          {classification.reasons?.length > 0 && (
            <ul className="plain-list small muted">
              {/* Reasons can quote device-supplied text: plain text only. */}
              {classification.reasons.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          )}
        </>
      ) : (
        <span className="muted">Not classified yet (the agent's AI step runs every few hours).</span>
      )}
      {canCorrect && mac && !editing && (
        <div className="form-actions">
          <button type="button" className="button button-secondary" onClick={() => setEditing(true)}>
            Correct type
          </button>
          {classification?.source === "manual" && (
            <button type="button" className="button button-secondary" onClick={() => run(() => predictions.resetType(mac))}>
              Back to automatic
            </button>
          )}
        </div>
      )}
      {editing && (
        <form
          className="inline-form"
          onSubmit={(event) => {
            event.preventDefault();
            run(() => predictions.correctType(mac, choice));
          }}
        >
          <label className="visually-hidden" htmlFor={`type-${mac}`}>
            Device type
          </label>
          <select id={`type-${mac}`} value={choice} onChange={(event) => setChoice(event.target.value)}>
            {Object.entries(DEVICE_TYPES).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
          <button type="submit" className="button">
            Save
          </button>
          <button type="button" className="button button-secondary" onClick={() => setEditing(false)}>
            Cancel
          </button>
        </form>
      )}
      <ErrorNote error={error} />
    </div>
  );
}

/* ------------------------------------------------------------------ forecasts */
export function subnetForecastText(p) {
  if (!p || p.status === "insufficient_data") return null;
  const method = METHODS[p.method] ?? p.method;
  if (p.days_until_full !== null && p.days_until_full !== undefined) {
    const when = p.days_until_full <= 0 ? "now" : `in about ${p.days_until_full} days`;
    return (
      `Expected to be full ${when} (around ${formatDate(p.full_on)}), ` +
      `growing by about ${p.growth_per_day} addresses a day. Method: ${method}.`
    );
  }
  if (p.status === "growing") {
    return `Growing by about ${p.growth_per_day} addresses a day, but not expected to fill within 180 days. Method: ${method}.`;
  }
  return `Usage is stable: not expected to fill within 180 days. Method: ${method}.`;
}

export function SubnetForecast({ subnetId }) {
  const { data, error, loading } = useResource((signal) => predictions.subnet(subnetId, { signal }), [subnetId]);
  const p = data?.prediction;
  const text = subnetForecastText(p);
  const usable = data ? Number(data.usable) : null;
  return (
    <Panel title="Address forecast">
      <ErrorNote error={error} />
      {loading && !data && <Loading />}
      {data && !text && (
        <Empty>
          No forecast yet. The agent's AI step makes one once it has at least 3 days of usage history (
          {data.history.length} so far).
        </Empty>
      )}
      {text && (
        <>
          <p className={p.days_until_full !== null && p.days_until_full <= 90 ? "forecast-warn" : undefined}>{text}</p>
          {p.warn_on && <p className="small muted">Expected to pass 80 % around {formatDate(p.warn_on)}.</p>}
          <ForecastChart
            label="Used addresses: history and forecast"
            summary={text}
            history={data.history.map((h) => ({ x: h.day, y: h.used }))}
            forecast={(p.series ?? []).map((s) => ({ x: s.ts, y: s.yhat, lo: s.lo, hi: s.hi }))}
            capacity={usable}
            threshold={usable ? usable * 0.8 : null}
            formatValue={(v) => formatCount(Math.round(v))}
            formatTime={(t) => formatDate(new Date(t).toISOString())}
          />
          <p className="small muted">Forecast made {formatDateTime(p.generated_at)} by the agent.</p>
        </>
      )}
    </Panel>
  );
}

export function uplinkForecastText(p) {
  if (!p || p.status === "insufficient_data") return null;
  const method = METHODS[p.method] ?? p.method;
  if (p.status === "busy") {
    return `Expected to exceed 80 % of the port speed from ${formatDateTime(p.busy_from)}. Method: ${method}.`;
  }
  return `Peak expected in the next 7 days: ${formatBps(p.peak_bps)} (${formatDateTime(p.peak_at)}), below 80 % of the port speed. Method: ${method}.`;
}

function UplinkChart({ deviceId, ifIndex }) {
  const { data, error } = useResource(
    (signal) => predictions.device(deviceId, { if_index: ifIndex }, { signal }),
    [deviceId, ifIndex],
  );
  const p = data?.forecasts?.[0];
  if (error) return <ErrorNote error={error} />;
  if (!p) return <Loading />;
  const text = uplinkForecastText(p);
  const capacity = p.speed_mbps ? p.speed_mbps * 1e6 : null;
  return (
    <>
      <p className={p.status === "busy" ? "forecast-warn" : undefined}>{text ?? "Not enough traffic history yet."}</p>
      {text && (
        <ForecastChart
          label={`Traffic on ${p.label}: history and forecast`}
          summary={text}
          history={data.history.map((h) => ({ x: h.ts, y: h.bps }))}
          forecast={(p.series ?? []).map((s) => ({ x: s.ts, y: s.yhat, lo: s.lo, hi: s.hi }))}
          capacity={capacity}
          threshold={capacity ? capacity * 0.8 : null}
          formatValue={formatBps}
          formatTime={(t) => formatDateTime(new Date(t).toISOString())}
        />
      )}
    </>
  );
}

export function DeviceForecast({ deviceId }) {
  const { data, error } = useResource((signal) => predictions.device(deviceId, {}, { signal }), [deviceId]);
  const [chosen, setChosen] = useState(null);
  const list = data?.forecasts ?? [];
  if (error) return <ErrorNote error={error} />;
  if (list.length === 0) return null; // no uplink history yet: nothing to show
  const current = list.find((f) => f.if_index === chosen) ?? list[0];
  return (
    <Panel
      title="Bandwidth forecast"
      actions={
        list.length > 1 && (
          <>
            <label className="visually-hidden" htmlFor={`uplink-${deviceId}`}>
              Interface
            </label>
            <select
              id={`uplink-${deviceId}`}
              value={current.if_index}
              onChange={(event) => setChosen(Number(event.target.value))}
            >
              {list.map((f) => (
                <option key={f.if_index} value={f.if_index}>
                  {f.label}
                </option>
              ))}
            </select>
          </>
        )
      }
    >
      <UplinkChart deviceId={deviceId} ifIndex={current.if_index} />
    </Panel>
  );
}
