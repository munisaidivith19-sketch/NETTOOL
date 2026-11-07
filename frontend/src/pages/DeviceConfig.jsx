import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { configs as configsApi } from "../api/api.js";
import { useAuth } from "../auth/AuthProvider.jsx";
import { can } from "../auth/permissions.js";
import { ExplainButton } from "../components/aiParts.jsx";
import DiffView from "../components/DiffView.jsx";
import { Badge, Empty, ErrorNote, Loading, PageHead, Panel, SeverityBadge } from "../components/ui.jsx";
import { formatDateTime, timeAgo } from "../format.js";
import { useResource } from "../hooks/useResource.js";
import { BACKUP_ERRORS, ScoreBadge } from "./configParts.jsx";

const SEVERITY = { high: "critical", medium: "warning", low: "info" };
const SOURCES = { scheduled: "Scheduled", manual: "Requested", post_change: "After a change" };

function Findings({ device, report, canChange }) {
  const navigate = useNavigate();
  if (!report) return <Empty>No config backup yet, so no compliance check.</Empty>;
  if (report.findings.length === 0) {
    return <p>All {report.rules_checked} checks passed.</p>;
  }
  return (
    <ul className="finding-list">
      {report.findings.map((f) => (
        <li key={f.rule} className="finding">
          <div className="finding-head">
            <SeverityBadge severity={SEVERITY[f.severity]} />
            <strong>{f.title}</strong>
            <span className="muted small">−{f.weight} points</span>
          </div>
          <p>{f.why}</p>
          {f.items.length > 0 && <p className="small">Affected: {f.items.join(", ")}</p>}
          <details>
            <summary>Suggested fix</summary>
            <pre className="device-text">{f.fix}</pre>
            {f.needs_input && (
              <p className="small muted">Replace the &lt;placeholders&gt; with your own values before using it.</p>
            )}
          </details>
          <ExplainButton request={{ kind: "finding", id: device.id, rule: f.rule }} />
          {canChange && device.config_vendor && (
            <button
              type="button"
              className="button button-secondary"
              onClick={() =>
                navigate("/changes/new", {
                  state: { deviceId: device.id, commands: f.fix, title: `Fix: ${f.title}`.slice(0, 120) },
                })
              }
            >
              Create change from fix
            </button>
          )}
        </li>
      ))}
    </ul>
  );
}

function Versions({ deviceId }) {
  const versions = useResource((signal) => configsApi.versions(deviceId, { signal }), [deviceId]);
  const [from, setFrom] = useState(null);
  const [to, setTo] = useState(null);
  const [view, setView] = useState(null); // {kind: "text"|"diff", data}
  const [error, setError] = useState(null);
  const list = versions.data ?? [];

  useEffect(() => {
    if (list.length >= 2 && from === null) {
      setFrom(list[1].version);
      setTo(list[0].version);
    }
  }, [list, from]);

  async function show(fn) {
    setError(null);
    try {
      setView(await fn());
    } catch (err) {
      setError(err);
    }
  }

  return (
    <Panel title={`Config versions (${list.length})`}>
      <ErrorNote error={versions.error || error} />
      {versions.loading && !versions.data && <Loading />}
      {versions.data && list.length === 0 && <Empty>No backups stored yet.</Empty>}
      {list.length > 0 && (
        <div className="table-wrap">
          <table className="table table-dense">
            <thead>
              <tr>
                <th scope="col">Version</th>
                <th scope="col">Taken</th>
                <th scope="col">Source</th>
                <th scope="col" className="num">Lines</th>
                <th scope="col" className="actions"></th>
              </tr>
            </thead>
            <tbody>
              {list.map((v) => (
                <tr key={v.version}>
                  <td>v{v.version}</td>
                  <td>{formatDateTime(v.taken_at)}</td>
                  <td>
                    {v.change_id ? (
                      <Link to={`/changes/${v.change_id}`} className="text-link">
                        {SOURCES[v.source] ?? v.source}
                      </Link>
                    ) : (
                      (SOURCES[v.source] ?? v.source)
                    )}
                  </td>
                  <td className="num">{v.lines}</td>
                  <td className="actions">
                    <button
                      type="button"
                      className="button button-secondary"
                      onClick={() =>
                        show(async () => ({ kind: "text", data: await configsApi.version(deviceId, v.version) }))
                      }
                    >
                      View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {list.length >= 2 && (
        <form
          className="toolbar"
          onSubmit={(e) => {
            e.preventDefault();
            show(async () => ({ kind: "diff", data: await configsApi.diff(deviceId, from, to) }));
          }}
        >
          <label className="field field-inline">
            <span>Compare</span>
            <select value={from ?? ""} onChange={(e) => setFrom(Number(e.target.value))}>
              {list.map((v) => (
                <option key={v.version} value={v.version}>
                  v{v.version}
                </option>
              ))}
            </select>
          </label>
          <label className="field field-inline">
            <span>with</span>
            <select value={to ?? ""} onChange={(e) => setTo(Number(e.target.value))}>
              {list.map((v) => (
                <option key={v.version} value={v.version}>
                  v{v.version}
                </option>
              ))}
            </select>
          </label>
          <button type="submit" className="button" disabled={from === to}>
            Show differences
          </button>
        </form>
      )}
      {view?.kind === "text" && (
        <div className="config-view">
          <h3>
            Version {view.data.version} <span className="muted small">({formatDateTime(view.data.taken_at)})</span>
          </h3>
          <p className="small muted">Passwords, secrets, communities and keys are masked before storage.</p>
          {/* Device configuration: plain text, never HTML. */}
          <pre className="device-text config-text">{view.data.text}</pre>
        </div>
      )}
      {view?.kind === "diff" && (
        <div className="config-view">
          <h3>
            v{view.data.from.version} → v{view.data.to.version}{" "}
            <span className="muted small">({view.data.changed_lines} changed lines)</span>
          </h3>
          <ExplainButton
            label="Explain this change"
            request={{
              kind: "diff",
              id: deviceId,
              from_version: view.data.from.version,
              to_version: view.data.to.version,
            }}
          />
          <DiffView
            rows={view.data.rows}
            fromLabel={`v${view.data.from.version} (${formatDateTime(view.data.from.taken_at)})`}
            toLabel={`v${view.data.to.version} (${formatDateTime(view.data.to.taken_at)})`}
          />
        </div>
      )}
    </Panel>
  );
}

export default function DeviceConfig() {
  const { id } = useParams();
  const { user } = useAuth();
  const { data: d, error, loading, reload } = useResource((signal) => configsApi.compliance(id, { signal }), [id]);
  const [requested, setRequested] = useState(false);
  const [actionError, setActionError] = useState(null);
  const canChange = can(user, "change.write");
  const baseline = d?.config_vendor ? `${d.config_vendor}/baseline` : null;

  return (
    <>
      <PageHead title={d ? `${d.sys_name || d.mgmt_ip}: configuration` : "Configuration"}>
        <Link to={`/devices/${id}`} className="text-link">
          Device page
        </Link>
        <Link to="/config" className="text-link">
          All devices
        </Link>
      </PageHead>
      <ErrorNote error={error || actionError} />
      {loading && !d && <Loading />}
      {d && (
        <>
          <Panel
            title="Backup"
            actions={
              canChange &&
              (requested || d.backup_requested ? (
                <span className="muted small">Backup requested</span>
              ) : (
                <button
                  type="button"
                  className="button button-secondary"
                  onClick={async () => {
                    setActionError(null);
                    try {
                      await configsApi.backupNow(id);
                      setRequested(true);
                      reload();
                    } catch (err) {
                      setActionError(err);
                    }
                  }}
                >
                  Back up now
                </button>
              ))
            }
          >
            <dl className="facts">
              <div>
                <dt>Status</dt>
                <dd>
                  {d.backup.status === "failed" ? (
                    <Badge tone="down">{BACKUP_ERRORS[d.backup.error] ?? d.backup.error}</Badge>
                  ) : d.backup.version ? (
                    <Badge tone="up">OK</Badge>
                  ) : (
                    "Never backed up"
                  )}
                </dd>
              </div>
              <div>
                <dt>Latest version</dt>
                <dd>{d.backup.version ? `v${d.backup.version}` : "–"}</dd>
              </div>
              <div>
                <dt>Last changed</dt>
                <dd>{d.backup.changed_at ? formatDateTime(d.backup.changed_at) : "–"}</dd>
              </div>
              <div>
                <dt>Last checked</dt>
                <dd>{d.backup.checked_at ? timeAgo(d.backup.checked_at) : "–"}</dd>
              </div>
            </dl>
          </Panel>

          {d.unconfigured.flag && (
            <Panel title="This device looks unconfigured">
              <ul className="row-list">
                {d.unconfigured.reasons.map((r) => (
                  <li key={r}>{r}</li>
                ))}
              </ul>
              {canChange && baseline && (
                <p>
                  <Link to="/changes/new" state={{ deviceId: id, template: baseline }} className="button">
                    Create baseline change
                  </Link>
                </p>
              )}
              {canChange && !baseline && (
                <p className="muted small">Add SSH credentials for it on the agent to back it up and configure it.</p>
              )}
            </Panel>
          )}

          <Panel title="Compliance" actions={<ScoreBadge score={d.compliance?.score} />}>
            {d.compliance?.previous_score != null && d.compliance.previous_score !== d.compliance.score && (
              <p className="small muted">Previously {d.compliance.previous_score}/100.</p>
            )}
            <Findings device={{ ...d, id }} report={d.report} canChange={canChange} />
          </Panel>

          {can(user, "config.read") ? (
            <Versions deviceId={id} />
          ) : (
            <Panel title="Config versions">
              <p className="muted">Config text is visible to engineers and admins only.</p>
            </Panel>
          )}
        </>
      )}
    </>
  );
}
