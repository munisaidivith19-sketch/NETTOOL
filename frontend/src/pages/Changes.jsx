import { useState } from "react";
import { Link } from "react-router-dom";
import { changes as changesApi } from "../api/api.js";
import { useAuth } from "../auth/AuthProvider.jsx";
import { can } from "../auth/permissions.js";
import { Empty, ErrorNote, Loading, PageHead, Panel } from "../components/ui.jsx";
import { timeAgo } from "../format.js";
import { useResource } from "../hooks/useResource.js";
import { CHANGE_STATUS, ChangeStatus } from "./configParts.jsx";

export default function Changes() {
  const { user } = useAuth();
  const [status, setStatus] = useState("");
  const list = useResource(
    (signal) => changesApi.list(status ? { status } : undefined, { signal }),
    [status],
    { refreshMs: 15000 },
  );

  return (
    <>
      <PageHead title="Change requests">
        {can(user, "change.write") && (
          <Link to="/changes/new" className="button">
            New change
          </Link>
        )}
      </PageHead>
      <Panel>
        <p className="small">
          Every change is previewed, checked against the command denylist, approved by a second person, pushed by
          the agent with automatic rollback, and verified.
        </p>
        <div className="toolbar">
          <label className="field field-inline">
            <span>Status</span>
            <select value={status} onChange={(e) => setStatus(e.target.value)}>
              <option value="">All</option>
              {Object.entries(CHANGE_STATUS).map(([value, [label]]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>
        </div>
      </Panel>
      <ErrorNote error={list.error} />
      {list.loading && !list.data && <Loading />}
      {list.data && (
        <Panel title={`Changes (${list.data.length})`}>
          {list.data.length === 0 ? (
            <Empty>No change requests{status ? " with this status" : ""}.</Empty>
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th scope="col">Title</th>
                    <th scope="col">Device</th>
                    <th scope="col">Status</th>
                    <th scope="col">Created by</th>
                    <th scope="col">Updated</th>
                  </tr>
                </thead>
                <tbody>
                  {list.data.map((c) => (
                    <tr key={c.id}>
                      <td>
                        <Link to={`/changes/${c.id}`} className="row-link">
                          {c.title}
                        </Link>
                      </td>
                      <td>{c.device_name || c.mgmt_ip}</td>
                      <td>
                        <ChangeStatus status={c.status} />
                      </td>
                      <td>{c.created_by?.username}</td>
                      <td>{timeAgo(c.updated_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      )}
    </>
  );
}
