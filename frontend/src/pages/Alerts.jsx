import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { alerts as alertsApi } from "../api/api.js";
import { useAuth } from "../auth/AuthProvider.jsx";
import { can } from "../auth/permissions.js";
import { useSummary } from "../components/SummaryProvider.jsx";
import { Badge, Empty, ErrorNote, Loading, PageHead, Panel, SeverityBadge } from "../components/ui.jsx";
import { ALERT_TYPES, formatDateTime, timeAgo } from "../format.js";
import { useResource } from "../hooks/useResource.js";

function AlertCard({ alert, canAct, onAction }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  async function act(fn) {
    setBusy(true);
    setError(null);
    try {
      await fn(alert.id);
      onAction();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <li className={`alert-card alert-${alert.severity}`}>
      <div className="alert-card-head">
        <SeverityBadge severity={alert.severity} />
        <span className="alert-type">{ALERT_TYPES[alert.type] ?? alert.type}</span>
        {alert.status === "resolved" && <Badge>Resolved</Badge>}
        {alert.acknowledged_by && alert.status === "open" && (
          <Badge tone="neutral">Acknowledged by {alert.acknowledged_by}</Badge>
        )}
        {alert.occurrences > 1 && <span className="muted small">{alert.occurrences} times</span>}
      </div>
      {/* Alert messages can contain device names: rendered as plain text. */}
      <p className="alert-message">{alert.message}</p>
      <p className="muted small">
        Opened {formatDateTime(alert.opened_at)} · last seen {timeAgo(alert.last_seen)}
        {alert.resolved_at &&
          ` · resolved ${formatDateTime(alert.resolved_at)}${alert.resolved_by ? ` by ${alert.resolved_by}` : " automatically"}`}
      </p>
      <ErrorNote error={error} />
      {canAct && alert.status === "open" && (
        <div className="form-actions">
          {!alert.acknowledged_by && (
            <button
              type="button"
              className="button button-secondary"
              disabled={busy}
              onClick={() => act(alertsApi.acknowledge)}
            >
              Acknowledge
            </button>
          )}
          <button type="button" className="button button-secondary" disabled={busy} onClick={() => act(alertsApi.resolve)}>
            Resolve
          </button>
        </div>
      )}
    </li>
  );
}

export default function Alerts() {
  const { user } = useAuth();
  const summary = useSummary();
  const [params, setParams] = useSearchParams();
  const status = params.get("status") ?? "open";
  const type = params.get("type") ?? "";
  const list = useResource(
    (signal) => alertsApi.list({ status, type: type || undefined }, { signal }),
    [status, type],
  );
  function update(next) {
    const merged = { status, type, ...next };
    setParams(Object.fromEntries(Object.entries(merged).filter(([, v]) => v)), { replace: true });
  }

  return (
    <>
      <PageHead title="Alerts" />
      <Panel>
        <div className="toolbar">
          <label className="field field-inline">
            <span>Status</span>
            <select value={status} onChange={(e) => update({ status: e.target.value })}>
              <option value="open">Open</option>
              <option value="resolved">Resolved</option>
              <option value="all">All</option>
            </select>
          </label>
          <label className="field field-inline">
            <span>Type</span>
            <select value={type} onChange={(e) => update({ type: e.target.value })}>
              <option value="">Any</option>
              {Object.entries(ALERT_TYPES).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>
        </div>
        {can(user, "alert.act") && (
          <p className="muted small">
            Resolving by hand closes the alert now. If the problem is still there, the next check opens it again.
          </p>
        )}
      </Panel>
      <ErrorNote error={list.error} />
      {list.loading && !list.data && <Loading />}
      {list.data?.length === 0 && <Empty>No alerts match.</Empty>}
      {list.data?.length > 0 && (
        <ul className="alert-list">
          {list.data.map((a) => (
            <AlertCard
              key={a.id}
              alert={a}
              canAct={can(user, "alert.act")}
              onAction={() => {
                list.reload();
                summary.reload();
              }}
            />
          ))}
        </ul>
      )}
    </>
  );
}
