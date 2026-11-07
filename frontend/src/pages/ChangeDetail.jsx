import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { changes as changesApi } from "../api/api.js";
import { useAuth } from "../auth/AuthProvider.jsx";
import { can } from "../auth/permissions.js";
import { ErrorNote, Field, Loading, PageHead, Panel } from "../components/ui.jsx";
import { formatDateTime } from "../format.js";
import { useResource } from "../hooks/useResource.js";
import { ChangeStatus, interfaceNames, Violations } from "./configParts.jsx";

const ACTIVE = new Set(["approved", "pushing", "verifying"]);

function Timeline({ items }) {
  return (
    <ol className="timeline">
      {items.map((t, i) => (
        <li key={i}>
          <ChangeStatus status={t.status} />
          <span className="small">
            {formatDateTime(t.at)}
            {t.by?.username && ` · ${t.by.username}`}
          </span>
          {t.note && <div className="small">{t.note}</div>}
        </li>
      ))}
    </ol>
  );
}

function Approval({ change, user, onDone }) {
  const own = change.created_by?.id === user.id;
  const [comment, setComment] = useState("");
  const [override, setOverride] = useState("");
  const [reason, setReason] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function act(fn) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      onDone();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  if (own && user.role !== "admin") {
    return (
      <p className="notice notice-warn">
        You created this change, so someone else must review and approve it (four-eyes rule).
      </p>
    );
  }
  return (
    <div className="form-grid">
      {own && (
        <p className="notice notice-warn">
          You created this change. As an admin you may approve it yourself only with a written reason; the override is
          recorded in the audit log.
        </p>
      )}
      <Field label={own ? "Override reason (required)" : "Comment (optional)"}>
        <input
          value={own ? override : comment}
          maxLength={500}
          onChange={(e) => (own ? setOverride(e.target.value) : setComment(e.target.value))}
        />
      </Field>
      <div className="form-actions">
        <button
          type="button"
          className="button"
          disabled={busy || (own && override.trim().length < 10)}
          onClick={() =>
            act(() =>
              changesApi.approve(change.id, own ? { override_reason: override.trim() } : comment.trim() ? { comment: comment.trim() } : {}),
            )
          }
        >
          Approve
        </button>
      </div>
      <Field label="Reject with reason">
        <input value={reason} maxLength={500} onChange={(e) => setReason(e.target.value)} />
      </Field>
      <div className="form-actions">
        <button
          type="button"
          className="button button-danger"
          disabled={busy || reason.trim().length < 3}
          onClick={() => act(() => changesApi.reject(change.id, reason.trim()))}
        >
          Reject
        </button>
      </div>
      <ErrorNote error={error} />
      {error?.body?.violations && <Violations items={error.body.violations} />}
    </div>
  );
}

export default function ChangeDetail() {
  const { id } = useParams();
  const { user } = useAuth();
  const { data: c, error, loading, reload } = useResource((signal) => changesApi.get(id, { signal }), [id], {
    refreshMs: 5000,
  });
  const [actionError, setActionError] = useState(null);
  const canWrite = can(user, "change.write");
  const isCreator = c && c.created_by?.id === user.id;

  async function act(fn) {
    setActionError(null);
    try {
      await fn();
      reload();
    } catch (err) {
      setActionError(err);
    }
  }

  return (
    <>
      <PageHead title={c ? c.title : "Change request"}>
        <Link to="/changes" className="text-link">
          All changes
        </Link>
      </PageHead>
      <ErrorNote error={error || actionError} />
      {actionError?.body?.violations && <Violations items={actionError.body.violations} />}
      {loading && !c && <Loading />}
      {c && (
        <>
          <Panel title="Summary" actions={<ChangeStatus status={c.status} />}>
            <dl className="facts">
              <div>
                <dt>Device</dt>
                <dd>
                  <Link to={`/devices/${c.device_id}/config`} className="text-link">
                    {c.device_name || c.mgmt_ip}
                  </Link>
                </dd>
              </div>
              <div>
                <dt>Source</dt>
                <dd>{c.source.kind === "template" ? `Template ${c.source.template}` : "Own commands"}</dd>
              </div>
              <div>
                <dt>Created by</dt>
                <dd>{c.created_by?.username}</dd>
              </div>
              <div>
                <dt>Approved by</dt>
                <dd>{c.approved_by?.username ?? "–"}</dd>
              </div>
              <div>
                <dt>Reviewed against</dt>
                <dd>{c.before_version ? `config v${c.before_version}` : "–"}</dd>
              </div>
              <div>
                <dt>Result config</dt>
                <dd>{c.after_version ? `v${c.after_version}` : "–"}</dd>
              </div>
            </dl>
            {c.override_reason && (
              <p className="notice notice-warn">Approved by its creator (admin override): {c.override_reason}</p>
            )}
            {ACTIVE.has(c.status) && (
              <p className="notice">
                {c.status === "approved"
                  ? "Waiting for the agent to pick this change up (it checks every minute)."
                  : "The agent is pushing and verifying this change. If the device stops answering, it is rolled back automatically."}
              </p>
            )}
          </Panel>

          <Panel title="Commands">
            <Violations items={c.violations} />
            {/* The exact text the agent pushes; device-style text, never HTML. */}
            <pre className="device-text config-text">{c.commands}</pre>
            {c.protected_interfaces.length > 0 && (
              <p className="small muted">Protected interfaces: {interfaceNames(c.protected_interfaces)}</p>
            )}
            {canWrite && (isCreator || user.role === "admin") && (
              <div className="form-actions">
                {c.status === "draft" && (
                  <button type="button" className="button" onClick={() => act(() => changesApi.submit(c.id))}>
                    Submit for approval
                  </button>
                )}
                {["draft", "pending_approval", "approved", "rejected"].includes(c.status) && (
                  <button
                    type="button"
                    className="button button-secondary"
                    onClick={() => act(() => changesApi.cancel(c.id))}
                  >
                    Cancel change
                  </button>
                )}
              </div>
            )}
          </Panel>

          {canWrite && c.status === "pending_approval" && (
            <Panel title="Review">
              <Approval change={c} user={user} onDone={reload} />
            </Panel>
          )}

          {c.result && (
            <Panel title="Agent result">
              <p>
                <ChangeStatus status={c.result.status} /> {c.result.error && <code>{c.result.error}</code>}
              </p>
              {c.result.log && <pre className="device-text config-text">{c.result.log}</pre>}
            </Panel>
          )}

          <Panel title="Timeline">
            <Timeline items={c.timeline} />
          </Panel>
        </>
      )}
    </>
  );
}
