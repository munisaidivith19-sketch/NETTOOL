import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { subnets as subnetsApi } from "../api/api.js";
import { useAuth } from "../auth/AuthProvider.jsx";
import { can } from "../auth/permissions.js";
import {
  Badge,
  ConfirmButton,
  Empty,
  ErrorNote,
  Loading,
  PageHead,
  Panel,
  SuccessNote,
  UsageBar,
} from "../components/ui.jsx";
import { formatCount, formatDateTime, formatSize } from "../format.js";
import { useResource } from "../hooks/useResource.js";
import { IpTable, ipLink, ReserveForm, SubnetForm } from "./ipParts.jsx";

const PAGE = 100;

/* The IP table, 100 rows at a time ("Load more" uses the backend's ip_key cursor). */
function SubnetIps({ subnetId, version }) {
  const [rows, setRows] = useState([]);
  const [next, setNext] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(
    async (after, signal) => {
      setLoading(true);
      try {
        const page = await subnetsApi.ips(subnetId, { limit: PAGE, after }, { signal });
        setRows((old) => (after ? [...old, ...page.items] : page.items));
        setNext(page.next_after);
        setError(null);
      } catch (err) {
        if (err?.name !== "AbortError") setError(err);
      } finally {
        if (!signal?.aborted) setLoading(false);
      }
    },
    [subnetId],
  );

  useEffect(() => {
    const controller = new AbortController();
    load(undefined, controller.signal);
    return () => controller.abort();
  }, [load, version]);

  return (
    <Panel title="Addresses">
      <ErrorNote error={error} />
      {loading && rows.length === 0 && <Loading />}
      {!loading && rows.length === 0 && !error && <Empty>No addresses seen or reserved in this subnet yet.</Empty>}
      {rows.length > 0 && <IpTable rows={rows} />}
      {next && (
        <div className="panel-foot">
          <button type="button" className="button button-secondary" onClick={() => load(next)} disabled={loading}>
            {loading ? "Loading…" : "Load more"}
          </button>
        </div>
      )}
    </Panel>
  );
}

export default function SubnetDetail() {
  const { id } = useParams();
  const { user } = useAuth();
  const navigate = useNavigate();
  const canWrite = can(user, "subnet.write");
  const canReserve = can(user, "ip.reserve");
  const { data: s, error, loading, reload } = useResource((signal) => subnetsApi.get(id, { signal }), [id]);
  const [editing, setEditing] = useState(false);
  const [nextFree, setNextFree] = useState(null); // { ip } | { error }
  const [reserved, setReserved] = useState(null);
  const [tableVersion, setTableVersion] = useState(0);
  const [deleteError, setDeleteError] = useState(null);

  async function findNextFree() {
    try {
      setNextFree(await subnetsApi.nextFree(id));
    } catch (err) {
      setNextFree({ error: err });
    }
  }

  function afterChange() {
    reload();
    setTableVersion((v) => v + 1);
    setNextFree(null);
  }

  return (
    <>
      <PageHead title={s ? s.network : "Subnet"}>
        <Link to="/ip" className="text-link">
          All subnets
        </Link>
      </PageHead>
      <ErrorNote error={error} />
      {loading && !s && <Loading />}
      {s && (
        <>
          <Panel
            title={s.name || "Subnet"}
            actions={
              canWrite &&
              !editing && (
                <>
                  <button type="button" className="button button-secondary" onClick={() => setEditing(true)}>
                    Edit
                  </button>
                  <ConfirmButton
                    confirmLabel="Delete subnet"
                    onConfirm={async () => {
                      try {
                        await subnetsApi.remove(id);
                        navigate("/ip");
                      } catch (err) {
                        setDeleteError(err);
                      }
                    }}
                  >
                    Delete
                  </ConfirmButton>
                </>
              )
            }
          >
            <ErrorNote error={deleteError} />
            {editing ? (
              <SubnetForm
                subnet={s}
                onCancel={() => setEditing(false)}
                onSave={async (body) => {
                  await subnetsApi.update(id, body);
                  setEditing(false);
                  afterChange();
                }}
              />
            ) : (
              <>
                <UsageBar usage={s.usage} />
                <dl className="facts">
                  <div>
                    <dt>Size</dt>
                    <dd>
                      {formatSize(s.usage.size)} addresses ({formatCount(s.usage.usable)} usable)
                    </dd>
                  </div>
                  <div>
                    <dt>Free</dt>
                    <dd>{formatCount(s.usage.free)}</dd>
                  </div>
                  <div>
                    <dt>VLAN</dt>
                    <dd>{s.vlan ?? "–"}</dd>
                  </div>
                  <div>
                    <dt>Gateway</dt>
                    <dd className="addr">{s.gateway ?? "–"}</dd>
                  </div>
                  <div>
                    <dt>Source</dt>
                    <dd>
                      <Badge>{s.source === "manual" ? "Manual" : "Discovered"}</Badge>
                    </dd>
                  </div>
                  <div>
                    <dt>Last discovered</dt>
                    <dd>{formatDateTime(s.last_discovered_at)}</dd>
                  </div>
                </dl>
                {s.description && <p>{s.description}</p>}
                {s.reserved_ranges.length > 0 && (
                  <>
                    <h3 className="subhead">Reserved ranges</h3>
                    <ul className="plain-list">
                      {s.reserved_ranges.map((r) => (
                        <li key={`${r.start}-${r.end}`}>
                          <span className="addr">
                            {r.start} – {r.end}
                          </span>
                          {r.note && <span className="muted"> {r.note}</span>}
                        </li>
                      ))}
                    </ul>
                  </>
                )}
                {s.source !== "manual" && canWrite && (
                  <p className="muted small">
                    Discovered subnets come back on the next agent report if deleted. Edits to name, VLAN and gateway
                    are kept.
                  </p>
                )}
              </>
            )}
          </Panel>

          <Panel
            title="Next free IP"
            actions={
              <button type="button" className="button" onClick={findNextFree}>
                Find next free IP
              </button>
            }
          >
            <p className="muted small">Skips the network and broadcast address, the gateway, reserved ranges and used IPs.</p>
            {nextFree?.error && <ErrorNote error={nextFree.error} />}
            {nextFree && !nextFree.error && (
              <p className="next-free" role="status">
                {nextFree.ip ? (
                  <>
                    Next free: <strong className="addr">{nextFree.ip}</strong>
                  </>
                ) : (
                  "This subnet has no free addresses."
                )}
              </p>
            )}
          </Panel>

          {canReserve && (
            <Panel title="Reserve an address">
              <SuccessNote>
                {reserved && (
                  <>
                    Reserved{" "}
                    <Link to={ipLink(reserved.ip)} className="addr">
                      {reserved.ip}
                    </Link>
                    .
                  </>
                )}
              </SuccessNote>
              <ReserveForm
                initialIp={nextFree?.ip ?? ""}
                onReserved={(result) => {
                  setReserved(result);
                  afterChange();
                }}
              />
            </Panel>
          )}

          <SubnetIps subnetId={id} version={tableVersion} />
        </>
      )}
    </>
  );
}
