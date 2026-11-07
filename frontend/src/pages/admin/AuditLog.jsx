import { useCallback, useEffect, useState } from "react";
import { audit as auditApi } from "../../api/api.js";
import { Badge, Empty, ErrorNote, Loading, PageHead, Panel } from "../../components/ui.jsx";
import { formatDateTime } from "../../format.js";

const RESULT_TONE = { success: "up", failure: "down", denied: "warn" };
const PAGE = 50;

function describeTarget(target) {
  if (!target) return "–";
  return target.username ?? target.network ?? target.ip ?? target.name ?? target.key ?? target.id ?? target.type;
}

function Details({ details }) {
  const entries = Object.entries(details ?? {});
  if (entries.length === 0) return "–";
  // Shown as text: details hold values like a username someone typed at the login form.
  return (
    <span className="audit-details">
      {entries.map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`).join(" · ")}
    </span>
  );
}

export default function AuditLog() {
  const [action, setAction] = useState("");
  const [actor, setActor] = useState("");
  const [filters, setFilters] = useState({});
  const [items, setItems] = useState([]);
  const [next, setNext] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(
    async (before, signal) => {
      setLoading(true);
      try {
        const page = await auditApi.list({ limit: PAGE, before, ...filters }, { signal });
        setItems((old) => (before ? [...old, ...page.items] : page.items));
        setNext(page.next_before);
        setError(null);
      } catch (err) {
        if (err?.name !== "AbortError") setError(err);
      } finally {
        if (!signal?.aborted) setLoading(false);
      }
    },
    [filters],
  );

  useEffect(() => {
    const controller = new AbortController();
    load(undefined, controller.signal);
    return () => controller.abort();
  }, [load]);

  return (
    <>
      <PageHead title="Audit log" />
      <Panel>
        <form
          className="toolbar"
          onSubmit={(e) => {
            e.preventDefault();
            setFilters({ action: action.trim() || undefined, actor: actor.trim() || undefined });
          }}
        >
          <label className="field field-inline">
            <span>Action</span>
            <input
              value={action}
              onChange={(e) => setAction(e.target.value)}
              placeholder="auth, subnet.create…"
              pattern="[a-z_]+(\.[a-z_]+)?"
              title="An action group like auth, or an exact action like auth.login"
              maxLength={64}
            />
          </label>
          <label className="field field-inline">
            <span>User</span>
            <input
              value={actor}
              onChange={(e) => setActor(e.target.value)}
              pattern="[a-z0-9._\-]{3,32}"
              maxLength={32}
              autoCapitalize="none"
            />
          </label>
          <button type="submit" className="button">
            Filter
          </button>
        </form>
      </Panel>
      <Panel>
        <ErrorNote error={error} />
        {loading && items.length === 0 && <Loading />}
        {!loading && items.length === 0 && !error && <Empty>No entries.</Empty>}
        {items.length > 0 && (
          <div className="table-wrap">
            <table className="table table-dense">
              <thead>
                <tr>
                  <th scope="col">When</th>
                  <th scope="col">Action</th>
                  <th scope="col">Result</th>
                  <th scope="col">Who</th>
                  <th scope="col">Target</th>
                  <th scope="col">Source IP</th>
                  <th scope="col">Details</th>
                </tr>
              </thead>
              <tbody>
                {items.map((e) => (
                  <tr key={e.id}>
                    <td className="nowrap">{formatDateTime(e.at)}</td>
                    <td className="addr">{e.action}</td>
                    <td>
                      <Badge tone={RESULT_TONE[e.result] ?? "neutral"}>{e.result}</Badge>
                    </td>
                    <td>{e.actor?.username ?? e.actor?.name ?? e.actor?.id ?? "–"}</td>
                    <td>{describeTarget(e.target)}</td>
                    <td className="addr">{e.ip ?? "–"}</td>
                    <td>
                      <Details details={e.details} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {next && (
          <div className="panel-foot">
            <button type="button" className="button button-secondary" onClick={() => load(next)} disabled={loading}>
              {loading ? "Loading…" : "Load older"}
            </button>
          </div>
        )}
      </Panel>
    </>
  );
}
