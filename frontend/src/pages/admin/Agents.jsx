import { useState } from "react";
import { agents as agentsApi } from "../../api/api.js";
import {
  Badge,
  ConfirmButton,
  CopyButton,
  Dialog,
  Empty,
  ErrorNote,
  Loading,
  PageHead,
  Panel,
} from "../../components/ui.jsx";
import { formatDateTime, timeAgo } from "../../format.js";
import { useResource } from "../../hooks/useResource.js";

/*
 * The agent key is shown exactly once. The server stores it encrypted and never returns it
 * again, so this dialog is the only chance to copy it. It lives in React state only while the
 * dialog is open and is dropped when the dialog closes; it is never written to storage.
 */
export function AgentKeyDialog({ agent, onClose }) {
  const [confirmed, setConfirmed] = useState(false);
  return (
    <Dialog title="Agent key – copy it now" onClose={onClose} dismissable={false}>
      <p className="notice notice-warn" role="alert">
        This key is shown <strong>only once</strong>. NetMap can’t show it again. If you lose it, revoke this agent
        and create a new one.
      </p>
      <dl className="facts">
        <div>
          <dt>AGENT_ID</dt>
          <dd className="addr">{agent.id}</dd>
        </div>
        <div>
          <dt>Fingerprint</dt>
          <dd className="addr">{agent.key_fingerprint}</dd>
        </div>
      </dl>
      <label className="field">
        <span>AGENT_KEY</span>
        <input className="addr secret-field" readOnly value={agent.key} onFocus={(e) => e.target.select()} />
      </label>
      <div className="form-actions">
        <CopyButton text={agent.key} label="Copy key" />
      </div>
      <p className="muted small">
        Put both values in the agent’s <span className="addr">.env</span> file on the agent machine. Don’t paste the key
        into chat, email or tickets.
      </p>
      <label className="checkbox">
        <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
        I have stored the key safely
      </label>
      <div className="form-actions">
        <button type="button" className="button" disabled={!confirmed} onClick={onClose}>
          Done
        </button>
      </div>
    </Dialog>
  );
}

export default function Agents() {
  const list = useResource((signal) => agentsApi.list({ signal }), []);
  const [name, setName] = useState("");
  const [created, setCreated] = useState(null);
  const [error, setError] = useState(null);

  async function create(event) {
    event.preventDefault();
    setError(null);
    try {
      setCreated(await agentsApi.create(name.trim()));
      setName("");
      list.reload();
    } catch (err) {
      setError(err);
    }
  }

  return (
    <>
      <PageHead title="Agents" />
      <Panel title="Create an agent">
        <form className="toolbar" onSubmit={create}>
          <label className="field field-inline field-grow">
            <span>Name</span>
            <input value={name} onChange={(e) => setName(e.target.value)} required maxLength={64} placeholder="Campus LAN agent" />
          </label>
          <button type="submit" className="button">
            Create agent key
          </button>
        </form>
        <ErrorNote error={error} />
      </Panel>
      <Panel title="All agents">
        <ErrorNote error={list.error} />
        {list.loading && !list.data && <Loading />}
        {list.data?.length === 0 && <Empty>No agents yet.</Empty>}
        {list.data?.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Name</th>
                  <th scope="col">ID</th>
                  <th scope="col">Key fingerprint</th>
                  <th scope="col">Last check-in</th>
                  <th scope="col">State</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {list.data.map((a) => (
                  <tr key={a.id}>
                    <td>{a.name}</td>
                    <td className="addr">{a.id}</td>
                    <td className="addr">{a.key_fingerprint}</td>
                    <td title={formatDateTime(a.last_seen_at)}>{timeAgo(a.last_seen_at)}</td>
                    <td>
                      {a.revoked_at ? (
                        <Badge tone="down">Revoked {formatDateTime(a.revoked_at)}</Badge>
                      ) : (
                        <Badge tone="up">Active</Badge>
                      )}
                    </td>
                    <td className="actions">
                      {!a.revoked_at && (
                        <ConfirmButton
                          confirmLabel="Revoke key"
                          onConfirm={async () => {
                            try {
                              await agentsApi.revoke(a.id);
                              list.reload();
                            } catch (err) {
                              setError(err);
                            }
                          }}
                        >
                          Revoke
                        </ConfirmButton>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      {created && <AgentKeyDialog agent={created} onClose={() => setCreated(null)} />}
    </>
  );
}
