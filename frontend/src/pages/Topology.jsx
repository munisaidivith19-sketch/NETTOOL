import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { topology as topologyApi } from "../api/api.js";
import StatusMark from "../components/StatusMark.jsx";
import { REFRESH_MS } from "../components/SummaryProvider.jsx";
import TopologyCanvas from "../components/TopologyCanvas.jsx";
import { Badge, Empty, ErrorNote, Field, Loading, PageHead, Panel } from "../components/ui.jsx";
import { DEVICE_STATUS, formatDateTime, timeAgo } from "../format.js";
import { useResource } from "../hooks/useResource.js";

const PROTOCOL = { lldp: "LLDP", cdp: "CDP" };

function NodeName({ node }) {
  if (!node) return <span className="muted">unknown</span>;
  if (node.external) return <span>{node.label}</span>;
  return (
    <Link to={`/devices/${node.id}`} className="row-link">
      {node.label}
    </Link>
  );
}

function NodeStatus({ node }) {
  if (node.external) return <Badge>Not managed by NetMap</Badge>;
  const s = DEVICE_STATUS[node.device_status] ?? { mark: "unknown", label: node.device_status };
  return <StatusMark status={s.mark} label={s.label} />;
}

function Legend() {
  return (
    <ul className="legend" aria-label="Map legend">
      <li>
        <StatusMark status="up" label="Up" />
      </li>
      <li>
        <StatusMark status="down" label="Down" />
      </li>
      <li>
        <StatusMark status="warning" label="SNMP error" />
      </li>
      <li>
        <span className="legend-external" aria-hidden="true" /> Neighbour not managed by NetMap
      </li>
      <li>
        <span className="legend-line legend-line-down" aria-hidden="true" /> Link down or lost
      </li>
    </ul>
  );
}

function NodePanel({ node, edges, byId }) {
  if (!node) {
    return (
      <Panel title="Details" className="topology-side">
        <p className="muted">Select a device on the map, or search for an IP, MAC or host name.</p>
      </Panel>
    );
  }
  const links = edges.filter((e) => e.source === node.id || e.target === node.id);
  return (
    <Panel title={node.label} className="topology-side">
      <dl className="facts facts-compact">
        <div>
          <dt>Status</dt>
          <dd>
            <NodeStatus node={node} />
          </dd>
        </div>
        <div>
          <dt>Address</dt>
          <dd className="addr">{node.mgmt_ip ?? "–"}</dd>
        </div>
        {node.vendor && (
          <div>
            <dt>Vendor</dt>
            <dd>{node.vendor}</dd>
          </div>
        )}
        {node.platform && (
          <div>
            <dt>Platform</dt>
            <dd>{node.platform}</dd>
          </div>
        )}
        {node.location && (
          <div>
            <dt>Location</dt>
            <dd>{node.location}</dd>
          </div>
        )}
        {!node.external && (
          <div>
            <dt>Open alerts</dt>
            <dd>{node.open_alerts ? <Link to="/alerts">{node.open_alerts}</Link> : "0"}</dd>
          </div>
        )}
      </dl>
      <h3 className="subhead">Connections ({links.length})</h3>
      {links.length === 0 ? (
        <Empty>No LLDP/CDP neighbours.</Empty>
      ) : (
        <ul className="row-list">
          {links.map((e) => {
            const mine = e.source === node.id;
            const other = byId.get(mine ? e.target : e.source);
            return (
              <li key={e.id}>
                <span>
                  <span className="addr">{(mine ? e.source_port : e.target_port) || "?"}</span>
                  {" → "}
                  <NodeName node={other} />{" "}
                  <span className="addr">{(mine ? e.target_port : e.source_port) || ""}</span>{" "}
                  {e.status === "down" && <Badge tone="down">down</Badge>}
                </span>
              </li>
            );
          })}
        </ul>
      )}
      {!node.external && (
        <p>
          <Link to={`/devices/${node.id}`} className="text-link">
            Open device page
          </Link>
        </p>
      )}
    </Panel>
  );
}

function LocateResult({ result }) {
  const loc = result.location;
  const uplinks = result.sightings.filter((s) => s.uplink);
  return (
    <div className={`notice locate-result ${loc ? "notice-ok" : "notice-warn"}`} role="status">
      <p>
        {loc ? (
          <>
            <strong>Found:</strong>{" "}
            <Link to={`/devices/${loc.device_id}`} className="row-link">
              {loc.device}
            </Link>{" "}
            port <span className="addr">{loc.port}</span>
            {loc.vlan ? `, VLAN ${loc.vlan}` : ""}
            {loc.last_seen && <span className="muted"> · seen {timeAgo(loc.last_seen)}</span>}
          </>
        ) : (
          result.message
        )}
      </p>
      {(result.ip || result.mac || result.hostname) && (
        <p className="muted">
          {[result.hostname, result.ip, result.mac].filter(Boolean).join(" · ")}
        </p>
      )}
      {uplinks.length > 0 && (
        <details>
          <summary>Also seen on {uplinks.length} uplink port(s), ignored</summary>
          <ul>
            {uplinks.map((s) => (
              <li key={`${s.device_id}-${s.if_index}-${s.vlan}`}>
                {s.device} <span className="addr">{s.port}</span>: {s.uplink_reason}
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}

export default function Topology() {
  const { data: graph, error, loading, reload } = useResource((signal) => topologyApi.graph({ signal }), [], {
    refreshMs: REFRESH_MS,
  });
  const [selectedId, setSelectedId] = useState(null);
  const [query, setQuery] = useState("");
  const [result, setResult] = useState(null);
  const [searchError, setSearchError] = useState(null);
  const [searching, setSearching] = useState(false);
  const [highlight, setHighlight] = useState(null);

  const byId = useMemo(() => new Map((graph?.nodes ?? []).map((n) => [n.id, n])), [graph]);
  const edges = graph?.edges ?? [];

  async function locate(event) {
    event.preventDefault();
    const q = query.trim();
    if (!q) return;
    setSearching(true);
    setSearchError(null);
    try {
      const found = await topologyApi.locate(q);
      setResult(found);
      const target = found.location?.device_id ?? found.device?.id ?? null;
      setSelectedId(target);
      setHighlight(target ? { nodeId: target, port: found.location?.port ?? null } : null);
    } catch (err) {
      setResult(null);
      setSearchError(err.status === 422 ? { message: "Enter an IP address, a MAC address or a host name." } : err);
    } finally {
      setSearching(false);
    }
  }

  const managed = graph?.nodes.filter((n) => !n.external).length ?? 0;

  return (
    <>
      <PageHead title="Topology">
        <button type="button" className="button button-secondary" onClick={reload}>
          Refresh
        </button>
      </PageHead>

      <form className="toolbar" onSubmit={locate} role="search">
        <Field label="Find which port a device is on" hint="IP address, MAC address or host name">
          <input
            type="search"
            value={query}
            maxLength={100}
            onChange={(e) => setQuery(e.target.value)}
            autoComplete="off"
            spellCheck={false}
          />
        </Field>
        <button type="submit" className="button" disabled={searching || !query.trim()}>
          {searching ? "Searching…" : "Locate"}
        </button>
      </form>
      <ErrorNote error={searchError} />
      {result && <LocateResult result={result} />}

      <ErrorNote error={error} />
      {loading && !graph && <Loading />}
      {graph && managed === 0 && <Empty>No devices yet. The map fills in after the first agent report.</Empty>}
      {graph && managed > 0 && (
        <>
          <div className="topology-layout">
            <Panel title={`Map · ${managed} devices, ${edges.length} links`} className="topology-map">
              <TopologyCanvas
                graph={graph}
                selectedId={selectedId}
                highlight={highlight}
                onSelect={(id) => {
                  setSelectedId(id);
                  setHighlight(null);
                }}
                label={`Network map with ${managed} devices and ${edges.length} links. The same information is in the Connections table below.`}
              />
              <Legend />
            </Panel>
            <NodePanel node={byId.get(selectedId)} edges={edges} byId={byId} />
          </div>

          <Panel title={`Connections (${edges.length})`}>
            {edges.length === 0 ? (
              <Empty>No LLDP or CDP neighbours reported. Enable LLDP/CDP on the switches to see links.</Empty>
            ) : (
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th scope="col">Device</th>
                      <th scope="col">Port</th>
                      <th scope="col">Connected to</th>
                      <th scope="col">Port</th>
                      <th scope="col">Learned by</th>
                      <th scope="col">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {edges.map((e) => (
                      <tr key={e.id}>
                        <td>
                          <button type="button" className="link-button" onClick={() => setSelectedId(e.source)}>
                            {byId.get(e.source)?.label ?? e.source}
                          </button>
                        </td>
                        <td className="addr">{e.source_port || "–"}</td>
                        <td>
                          <NodeName node={byId.get(e.target)} />
                        </td>
                        <td className="addr">{e.target_port || "–"}</td>
                        <td>{e.protocols.map((p) => PROTOCOL[p] ?? p).join(", ")}</td>
                        <td>
                          <StatusMark status={e.status === "up" ? "up" : "down"} label={e.status === "up" ? "Up" : "Down"} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {graph.truncated && <p className="muted">Showing the first part of a very large network.</p>}
            <p className="muted">Updated {formatDateTime(new Date().toISOString())}, refreshes every 30 seconds.</p>
          </Panel>
        </>
      )}
    </>
  );
}
