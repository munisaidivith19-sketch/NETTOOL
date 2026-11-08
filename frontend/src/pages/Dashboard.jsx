import { useId, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { alerts as alertsApi } from "../api/api.js";
import HealthPanel from "../components/HealthPanel.jsx";
import Icon from "../components/icons.jsx";
import StatusMark from "../components/StatusMark.jsx";
import { REFRESH_MS, useSummary } from "../components/SummaryProvider.jsx";
import { Empty, ErrorNote, Loading, PageHead, Panel, SeverityBadge, UsageBar } from "../components/ui.jsx";
import { ALERT_TYPES, formatDate, formatDateTime, formatPercent, timeAgo } from "../format.js";
import { useResource } from "../hooks/useResource.js";

// An agent that hasn't reported for this long is probably stopped (default poll is 5 min).
const AGENT_STALE_MS = 15 * 60 * 1000;
const SUBNET_FULL_PERCENT = 80; // same threshold as the backend's subnet-usage alert
const BOARD_LIMIT = 30;

/*
 * Charts on this page are plain SVG drawn with attributes (x, width, height, fill via class),
 * never style="" attributes, so the strict Content-Security-Policy (style-src 'self') holds.
 * Each chart has a text alternative (aria-label) and the same numbers are printed beside it,
 * so nothing is shown by colour alone.
 */

/* A dashboard card: icon, title, and an optional arrow link to the full page. */
function Widget({ icon, title, to, linkLabel, children, className = "" }) {
  const id = useId();
  return (
    <section className={`widget ${className}`} aria-labelledby={id}>
      <div className="widget-head">
        <span className="widget-icon">
          <Icon name={icon} size={18} />
        </span>
        <h2 id={id}>{title}</h2>
        {to && (
          <Link to={to} className="icon-button widget-link" aria-label={linkLabel}>
            <Icon name="arrow" size={18} />
          </Link>
        )}
      </div>
      {children}
    </section>
  );
}

/* A single bar split into up / SNMP error / down segments, widths proportional to counts. */
function StatusBar({ up, snmpError, down }) {
  const total = up + snmpError + down;
  const label = `${up} up, ${snmpError} with SNMP errors, ${down} down`;
  if (total === 0) {
    return (
      <svg className="status-bar" viewBox="0 0 100 10" preserveAspectRatio="none" role="img" aria-label="No devices yet">
        <rect className="bar-empty" x="0" y="0" width="100" height="10" />
      </svg>
    );
  }
  const parts = [
    ["bar-up", up],
    ["bar-warn", snmpError],
    ["bar-down", down],
  ].filter(([, n]) => n > 0);
  let x = 0;
  return (
    <svg className="status-bar" viewBox="0 0 100 10" preserveAspectRatio="none" role="img" aria-label={label}>
      {parts.map(([cls, n], i) => {
        const width = (n / total) * 100;
        const rect = (
          // A 0.6-unit gap between segments; the last one runs to the end.
          <rect key={cls} className={cls} x={x} y="0" width={Math.max(width - (i < parts.length - 1 ? 0.6 : 0), 0.8)} height="10" />
        );
        x += width;
        return rect;
      })}
    </svg>
  );
}

/* Vertical bars, one per subnet, coloured by how full it is (the % is printed below). */
function SubnetBars({ subnets }) {
  if (subnets.length === 0) return null;
  const width = 100 / subnets.length;
  const label = subnets.map((s) => `${s.network} ${formatPercent(s.usage.percent)} used`).join(", ");
  return (
    <svg className="mini-bars" viewBox="0 0 100 40" preserveAspectRatio="none" role="img" aria-label={label}>
      {subnets.map((s, i) => {
        const percent = Math.min(Math.max(s.usage.percent ?? 0, 0), 100);
        const height = Math.max((percent / 100) * 40, 1.5);
        const tone =
          percent >= SUBNET_FULL_PERCENT ? "bar-down" : percent >= SUBNET_FULL_PERCENT - 10 ? "bar-warn" : "bar-accent";
        return (
          <g key={s.id}>
            <rect className="bar-track" x={i * width + width * 0.18} y="0" width={width * 0.64} height="40" rx="2" />
            <rect className={tone} x={i * width + width * 0.18} y={40 - height} width={width * 0.64} height={height} rx="2" />
          </g>
        );
      })}
    </svg>
  );
}

function DevicesWidget({ devices }) {
  return (
    <Widget icon="server" title="Devices" to="/devices" linkLabel="Open the device list">
      <div className="stat-trio">
        <Link to="/devices?status=up" className="stat">
          <span className="stat-value">{devices.up}</span>
          <StatusMark status="up" label="Up" />
        </Link>
        <Link to="/devices?status=snmp_error" className="stat">
          <span className="stat-value">{devices.snmp_error}</span>
          <StatusMark status={devices.snmp_error ? "warning" : "unknown"} label="SNMP error" />
        </Link>
        <Link to="/devices?status=down" className="stat">
          <span className="stat-value">{devices.down}</span>
          <StatusMark status={devices.down ? "down" : "unknown"} label="Down" />
        </Link>
      </div>
      <StatusBar up={devices.up} snmpError={devices.snmp_error} down={devices.down} />
      <p className="widget-foot">
        {devices.total} {devices.total === 1 ? "device" : "devices"} watched · SNMP error = answers ping, not SNMP
      </p>
    </Widget>
  );
}

function AlertsWidget({ summary }) {
  const bySeverity = summary.alerts_by_severity ?? {};
  const types = Object.entries(summary.alerts_by_type ?? {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3);
  const most = types[0]?.[1] ?? 1;
  return (
    <Widget icon="bell" title="Alerts" to="/alerts" linkLabel="Open all alerts">
      <div className="widget-number-row">
        <span className="widget-number">{summary.alerts_open}</span>
        <span className="severity-chips">
          {bySeverity.critical > 0 && <span className="pill pill-down">{bySeverity.critical} critical</span>}
          {bySeverity.warning > 0 && <span className="pill pill-warn">{bySeverity.warning} warning</span>}
          {bySeverity.info > 0 && <span className="pill">{bySeverity.info} info</span>}
          {summary.alerts_open === 0 && <span className="pill pill-up">All clear</span>}
        </span>
      </div>
      {types.length > 0 && (
        <ul className="type-bars">
          {types.map(([type, n]) => (
            <li key={type}>
              <span className="type-bars-label">{ALERT_TYPES[type] ?? type}</span>
              <span className="type-bars-count">{n}</span>
              <svg className="type-bars-bar" viewBox="0 0 100 6" preserveAspectRatio="none" aria-hidden="true">
                <rect className="bar-track" x="0" y="0" width="100" height="6" rx="3" />
                <rect className="bar-accent" x="0" y="0" width={Math.max((n / most) * 100, 4)} height="6" rx="3" />
              </svg>
            </li>
          ))}
        </ul>
      )}
    </Widget>
  );
}

function IpSpaceWidget({ summary }) {
  const fullest = summary.fullest_subnets[0];
  return (
    <Widget icon="hash" title="IP space" to="/ip" linkLabel="Open IP address management">
      <div className="widget-number-row">
        <span className="widget-number">{summary.subnets}</span>
        <span className="muted">{summary.subnets === 1 ? "subnet" : "subnets"}</span>
      </div>
      <SubnetBars subnets={summary.fullest_subnets} />
      <p className="widget-foot">
        {fullest ? `Fullest is ${formatPercent(fullest.usage.percent)} used` : "No subnets yet"}
        {" · "}
        <Link to="/ip#duplicates" className={summary.duplicate_ips ? "text-danger" : "text-link"}>
          {summary.duplicate_ips} duplicate {summary.duplicate_ips === 1 ? "IP" : "IPs"}
        </Link>
      </p>
    </Widget>
  );
}

function AgentWidget({ agent }) {
  const stale = agent && Date.now() - new Date(agent.last_seen_at).getTime() > AGENT_STALE_MS;
  return (
    <Widget icon="agent" title="Agent">
      <div className="widget-number-row">
        <span className="widget-number widget-number-text">{agent ? timeAgo(agent.last_seen_at) : "never"}</span>
      </div>
      <StatusMark
        status={!agent || stale ? "warning" : "up"}
        label={!agent ? "No agent has reported yet" : stale ? "Not reporting – is it running?" : "Reporting"}
      />
      <p className="widget-foot">
        {agent ? `${agent.name} · last report ${formatDateTime(agent.last_seen_at)}` : "Start the agent inside the network"}
      </p>
    </Widget>
  );
}

/* Board / List switch: the WAI-ARIA tabs pattern (arrow keys move between tabs). */
function ViewTabs({ views, value, onChange, panelId }) {
  const refs = useRef({});
  function onKey(event) {
    const keys = { ArrowRight: 1, ArrowLeft: -1 };
    if (!(event.key in keys)) return;
    event.preventDefault();
    const i = views.findIndex((v) => v.id === value);
    const next = views[(i + keys[event.key] + views.length) % views.length];
    onChange(next.id);
    refs.current[next.id]?.focus();
  }
  return (
    <div className="view-tabs" role="tablist" aria-label="Alert view" onKeyDown={onKey}>
      {views.map((v) => (
        <button
          key={v.id}
          ref={(node) => {
            refs.current[v.id] = node;
          }}
          type="button"
          role="tab"
          id={`${panelId}-${v.id}`}
          aria-selected={v.id === value}
          aria-controls={panelId}
          tabIndex={v.id === value ? 0 : -1}
          className="view-tab"
          onClick={() => onChange(v.id)}
        >
          <Icon name={v.icon} size={16} />
          {v.label}
        </button>
      ))}
    </div>
  );
}

const COLUMNS = [
  { severity: "critical", title: "Critical", mark: "down" },
  { severity: "warning", title: "Warning", mark: "warning" },
  { severity: "info", title: "Info", mark: "unknown" },
];

function AlertBoard({ items }) {
  return (
    <div className="board">
      {COLUMNS.map((col) => {
        const cards = items.filter((a) => a.severity === col.severity);
        return (
          <div key={col.severity} className={`board-column board-${col.severity}`} role="group" aria-label={`${col.title} alerts`}>
            <div className="board-column-head">
              <StatusMark status={col.mark} label={col.title} />
              <span className="board-count">{cards.length}</span>
            </div>
            {cards.length === 0 ? (
              <p className="board-empty">Nothing here</p>
            ) : (
              <ul className="board-cards">
                {cards.map((a) => (
                  <li key={a.id} className="board-card">
                    <span className="board-card-type">{ALERT_TYPES[a.type] ?? a.type}</span>
                    <p className="board-card-message">{a.message}</p>
                    <span className="board-card-foot">
                      <span>{timeAgo(a.last_seen)}</span>
                      {a.occurrences > 1 && <span>Seen {a.occurrences}×</span>}
                      {a.acknowledged_by && <span>Acknowledged</span>}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        );
      })}
    </div>
  );
}

function AlertList({ items }) {
  return (
    <ul className="row-list">
      {items.map((a) => (
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
  );
}

const VIEWS = [
  { id: "board", label: "Board", icon: "grid" },
  { id: "list", label: "List", icon: "list" },
];

function OpenAlerts() {
  const panelId = useId();
  const [view, setView] = useState("board");
  const recent = useResource((signal) => alertsApi.list({ status: "open", limit: BOARD_LIMIT }, { signal }), [], {
    refreshMs: REFRESH_MS,
  });
  const titleId = useId();
  return (
    <section className="panel" aria-labelledby={titleId}>
      <div className="panel-head">
        <h2 id={titleId}>Open alerts</h2>
        <div className="panel-actions">
          <ViewTabs views={VIEWS} value={view} onChange={setView} panelId={panelId} />
          <Link to="/alerts" className="button button-ghost button-small">
            All alerts
            <Icon name="arrow" size={16} />
          </Link>
        </div>
      </div>
      <div id={panelId} role="tabpanel" aria-labelledby={`${panelId}-${view}`}>
        <ErrorNote error={recent.error} />
        {!recent.data && !recent.error && <Loading />}
        {recent.data?.length === 0 && <Empty>No open alerts.</Empty>}
        {recent.data?.length > 0 && (view === "board" ? <AlertBoard items={recent.data} /> : <AlertList items={recent.data} />)}
      </div>
    </section>
  );
}

export default function Dashboard() {
  const { data: summary, error, reload } = useSummary();

  return (
    <>
      <PageHead
        title="Dashboard"
        description="Live view of the network the agent watches: device health, IP space and open alerts. Updates every 30 seconds."
      >
        <button type="button" className="button button-secondary" onClick={reload}>
          <Icon name="refresh" size={16} />
          Refresh
        </button>
        <Link to="/topology" className="button">
          <Icon name="topology" size={16} />
          Open network map
        </Link>
      </PageHead>
      <ErrorNote error={error} />
      {!summary && !error && <Loading />}
      {summary && (
        <>
          <div className="widgets">
            <DevicesWidget devices={summary.devices} />
            <AlertsWidget summary={summary} />
            <IpSpaceWidget summary={summary} />
            <AgentWidget agent={summary.last_agent_check_in} />
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
          </div>

          <OpenAlerts />
        </>
      )}
      <HealthPanel />
    </>
  );
}
