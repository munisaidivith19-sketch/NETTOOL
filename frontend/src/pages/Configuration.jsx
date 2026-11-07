import { useState } from "react";
import { Link } from "react-router-dom";
import { configs as configsApi } from "../api/api.js";
import { useAuth } from "../auth/AuthProvider.jsx";
import { can } from "../auth/permissions.js";
import { Badge, Empty, ErrorNote, Loading, PageHead, Panel } from "../components/ui.jsx";
import { timeAgo } from "../format.js";
import { useResource } from "../hooks/useResource.js";
import { BACKUP_ERRORS, ScoreBadge } from "./configParts.jsx";

function BackupCell({ row }) {
  const b = row.backup;
  if (b.status === "failed") {
    return (
      <span>
        <Badge tone="down">Failed</Badge> <span className="small">{BACKUP_ERRORS[b.error] ?? b.error}</span>
      </span>
    );
  }
  if (!b.version) return <span className="muted">Never</span>;
  return (
    <span>
      v{b.version} <span className="muted small">checked {timeAgo(b.checked_at)}</span>
    </span>
  );
}

export default function Configuration() {
  const { user } = useAuth();
  const list = useResource((signal) => configsApi.overview({ signal }), [], { refreshMs: 30000 });
  const [requested, setRequested] = useState({});
  const [error, setError] = useState(null);
  const rows = list.data ?? [];
  const unconfigured = rows.filter((r) => r.unconfigured.flag);
  const scored = rows.filter((r) => r.compliance?.score != null);
  const average = scored.length
    ? Math.round(scored.reduce((sum, r) => sum + r.compliance.score, 0) / scored.length)
    : null;

  async function backupNow(id) {
    setError(null);
    try {
      await configsApi.backupNow(id);
      setRequested((r) => ({ ...r, [id]: true }));
    } catch (err) {
      setError(err);
    }
  }

  return (
    <>
      <PageHead title="Configuration">
        {can(user, "change.write") && (
          <Link to="/changes/new" className="button">
            New change
          </Link>
        )}
      </PageHead>
      <ErrorNote error={list.error || error} />
      {list.loading && !list.data && <Loading />}
      {list.data && (
        <>
          <div className="stat-row">
            <Panel title="Average compliance">
              <p className="stat-big">{average === null ? "–" : <ScoreBadge score={average} />}</p>
            </Panel>
            <Panel title="Backed up">
              <p className="stat-big">
                {rows.filter((r) => r.backup.version).length} / {rows.length}
              </p>
            </Panel>
            <Panel title="Unconfigured">
              <p className="stat-big">{unconfigured.length}</p>
            </Panel>
          </div>
          <Panel title={`Devices (${rows.length})`}>
            {rows.length === 0 ? (
              <Empty>No devices yet. They appear after the agent's first discovery report.</Empty>
            ) : (
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th scope="col">Device</th>
                      <th scope="col">Last backup</th>
                      <th scope="col">Compliance</th>
                      <th scope="col">Findings</th>
                      <th scope="col">State</th>
                      {can(user, "change.write") && <th scope="col" className="actions"></th>}
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((r) => (
                      <tr key={r.id}>
                        <td>
                          <Link to={`/devices/${r.id}/config`} className="row-link">
                            {r.sys_name || r.mgmt_ip}
                          </Link>
                          <div className="muted small addr">{r.mgmt_ip}</div>
                        </td>
                        <td>
                          <BackupCell row={r} />
                        </td>
                        <td>
                          <ScoreBadge score={r.compliance?.score} />
                        </td>
                        <td className="num">{r.compliance ? r.compliance.findings : "–"}</td>
                        <td>
                          {r.unconfigured.flag ? (
                            <Badge tone="warn" title={r.unconfigured.reasons.join("; ")}>
                              Unconfigured
                            </Badge>
                          ) : (
                            <span className="muted">Configured</span>
                          )}
                        </td>
                        {can(user, "change.write") && (
                          <td className="actions">
                            {requested[r.id] || r.backup_requested ? (
                              <span className="muted small">Backup requested</span>
                            ) : (
                              <button type="button" className="button button-secondary" onClick={() => backupNow(r.id)}>
                                Back up now
                              </button>
                            )}
                          </td>
                        )}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <p className="muted small">
              Backups run on the agent over SSH; device passwords never leave it. Requested backups start within a
              minute.
            </p>
          </Panel>
        </>
      )}
    </>
  );
}
