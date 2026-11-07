import { Link } from "react-router-dom";
import { alerts as alertsApi } from "../api/api.js";
import HealthPanel from "../components/HealthPanel.jsx";
import StatusMark from "../components/StatusMark.jsx";
import { REFRESH_MS, useSummary } from "../components/SummaryProvider.jsx";
import { Empty, ErrorNote, Loading, PageHead, Panel, SeverityBadge, UsageBar } from "../components/ui.jsx";
import { ALERT_TYPES, formatDate, formatDateTime, timeAgo } from "../format.js";
import { useResource } from "../hooks/useResource.js";

// An agent that hasn't reported for this long is probably stopped (default poll is 5 min).
const AGENT_STALE_MS = 15 * 60 * 1000;

function Tile({ label, value, mark, to, hint, text = false }) {
  const body = (
    <>
      <span className="tile-label">{label}</span>
      <span className={`tile-value${text ? " tile-value-text" : ""}`}>
        {mark && <StatusMark status={mark} label="" />}
        {value}
      </span>
      {hint && <span className="tile-hint">{hint}</span>}
    </>
  );
  return to ? (
    <Link to={to} className="tile tile-link">
      {body}
    </Link>
  ) : (
    <div className="tile">{body}</div>
  );
}

export default function Dashboard() {
  const { data: summary, error, reload } = useSummary();
  const recent = useResource((signal) => alertsApi.list({ status: "open", limit: 5 }, { signal }), [], {
    refreshMs: REFRESH_MS,
  });

  const agent = summary?.last_agent_check_in;
  const agentStale = agent && Date.now() - new Date(agent.last_seen_at).getTime() > AGENT_STALE_MS;

  return (
    <>
      <PageHead title="Dashboard">
        <button type="button" className="button button-secondary" onClick={reload}>
          Refresh
        </button>
      </PageHead>
      <ErrorNote error={error} />
      {!summary && !error && <Loading />}
      {summary && (
        <>
          <div className="tiles">
            <Tile label="Devices up" value={summary.devices.up} mark="up" to="/devices?status=up" />
            <Tile
              label="Devices down"
              value={summary.devices.down}
              mark={summary.devices.down ? "down" : undefined}
              to="/devices?status=down"
            />
            <Tile
              label="SNMP errors"
              value={summary.devices.snmp_error}
              mark={summary.devices.snmp_error ? "warning" : undefined}
              to="/devices?status=snmp_error"
              hint="Answers ping, not SNMP"
            />
            <Tile
              label="Duplicate IPs"
              value={summary.duplicate_ips}
              mark={summary.duplicate_ips ? "down" : undefined}
              to="/ip#duplicates"
            />
            <Tile label="Open alerts" value={summary.alerts_open} to="/alerts" />
            <Tile
              label="Last agent check-in"
              text
              value={agent ? timeAgo(agent.last_seen_at) : "never"}
              mark={!agent || agentStale ? "warning" : "up"}
              hint={agent ? `${agent.name} · ${formatDateTime(agent.last_seen_at)}` : "No agent has reported yet"}
            />
          </div>

          <div className="dashboard-grid">
            <Panel
              title="Fullest subnets"
              actions={
                <Link to="/ip" className="text-link">
                  All {summary.subnets} subnets
                </Link>
              }
            >
              {summary.fullest_subnets.length === 0 ? (
                <Empty>No subnets yet. They appear after the first agent report, or add one by hand.</Empty>
              ) : (
                <ul className="row-list">
                  {summary.fullest_subnets.map((s) => (
                    <li key={s.id}>
                      <Link to={`/ip/subnets/${s.id}`} className="row-link">
                        <span className="addr">{s.network}</span>
                        {s.name && <span className="muted"> {s.name}</span>}
                      </Link>
                      <UsageBar usage={s.usage} />
                    </li>
                  ))}
                </ul>
              )}
            </Panel>

            <Panel
              title="Running out of addresses"
              actions={
                <Link to="/ask" className="text-link">
                  Ask NetMap
                </Link>
              }
            >
              {!summary.filling_soon?.length ? (
                <Empty>No subnet is forecast to fill within 90 days (forecasts need a few days of history).</Empty>
              ) : (
                <ul className="row-list">
                  {summary.filling_soon.map((s) => (
                    <li key={s.subnet_id}>
                      <Link to={`/ip/subnets/${s.subnet_id}`} className="row-link">
                        <span className="addr">{s.network}</span>
                        {s.label !== s.network && <span className="muted"> {s.label}</span>}
                      </Link>
                      <span className="forecast-warn small">
                        {s.days_until_full <= 0
                          ? "Full now"
                          : `Full in about ${s.days_until_full} days (${formatDate(s.full_on)})`}
                      </span>
                      {s.percent !== null && <span className="muted small"> · {s.percent} % used now</span>}
                    </li>
                  ))}
                </ul>
              )}
            </Panel>

            <Panel
              title="Open alerts"
              actions={
                <Link to="/alerts" className="text-link">
                  All alerts
                </Link>
              }
            >
              <ErrorNote error={recent.error} />
              {recent.data?.length === 0 && <Empty>No open alerts.</Empty>}
              {recent.data?.length > 0 && (
                <ul className="row-list">
                  {recent.data.map((a) => (
                    <li key={a.id} className="alert-row">
                      <span className="alert-row-head">
                        <SeverityBadge severity={a.severity} />
                        <span className="muted">{ALERT_TYPES[a.type] ?? a.type}</span>
                        <span className="muted">{timeAgo(a.last_seen)}</span>
                      </span>
                      <span>{a.message}</span>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>
          </div>
        </>
      )}
      <HealthPanel />
    </>
  );
}
