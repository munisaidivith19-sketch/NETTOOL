import { useEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { alerts as alertsApi, subnets as subnetsApi } from "../api/api.js";
import { useAuth } from "../auth/AuthProvider.jsx";
import { can } from "../auth/permissions.js";
import { Badge, Empty, ErrorNote, Loading, PageHead, Panel, UsageBar } from "../components/ui.jsx";
import { formatSize, timeAgo } from "../format.js";
import { useResource } from "../hooks/useResource.js";
import { ipLink, SubnetForm } from "./ipParts.jsx";

export function IpSearchBox({ initial = "" }) {
  const navigate = useNavigate();
  const [q, setQ] = useState(initial);
  return (
    <form
      className="toolbar"
      role="search"
      onSubmit={(e) => {
        e.preventDefault();
        if (q.trim()) navigate(`/ip/search?q=${encodeURIComponent(q.trim())}`);
      }}
    >
      <label className="field field-inline field-grow">
        <span>Find an address</span>
        <input
          type="search"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="IP, subnet (10.0.0.0/24), MAC or host name"
          maxLength={100}
          pattern="[A-Za-z0-9.:_\- /]+"
          title="Letters, digits and . : _ - / only"
        />
      </label>
      <button type="submit" className="button">
        Search
      </button>
    </form>
  );
}

function DuplicateIps() {
  const { data, error } = useResource(
    (signal) => alertsApi.list({ status: "open", type: "duplicate_ip" }, { signal }),
    [],
  );
  // The dashboard links to /ip#duplicates: scroll here once the list has loaded.
  const { hash } = useLocation();
  const scrolled = useRef(false);
  useEffect(() => {
    if (hash === "#duplicates" && data && !scrolled.current) {
      scrolled.current = true;
      document.getElementById("duplicates")?.scrollIntoView?.({ block: "start" });
    }
  }, [hash, data]);
  return (
    <Panel title="Duplicate IPs" id="duplicates">
      <ErrorNote error={error} />
      {data?.length === 0 && <Empty>No duplicate IPs seen in the detection window.</Empty>}
      {data?.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th scope="col">Address</th>
                <th scope="col">MAC addresses claiming it</th>
                <th scope="col">Seen by</th>
                <th scope="col">Since</th>
              </tr>
            </thead>
            <tbody>
              {data.map((a) => (
                <tr key={a.id}>
                  <td>
                    <Link to={ipLink(a.target.ip)} className="row-link addr">
                      {a.target.ip}
                    </Link>
                  </td>
                  <td className="addr">{(a.details.macs ?? []).join(", ")}</td>
                  <td>{(a.details.seen_by ?? []).join(", ")}</td>
                  <td>{timeAgo(a.opened_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

export default function Subnets() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [adding, setAdding] = useState(false);
  const [version, setVersion] = useState("");
  const list = useResource((signal) => subnetsApi.list({ signal }), []);
  const rows = (list.data ?? []).filter((s) => !version || String(s.version) === version);

  return (
    <>
      <PageHead title="IP addresses">
        {can(user, "subnet.write") && !adding && (
          <button type="button" className="button" onClick={() => setAdding(true)}>
            Add subnet
          </button>
        )}
      </PageHead>
      <Panel>
        <IpSearchBox />
      </Panel>
      {adding && (
        <Panel title="Add subnet">
          <SubnetForm
            onCancel={() => setAdding(false)}
            onSave={async (body) => {
              const created = await subnetsApi.create(body);
              navigate(`/ip/subnets/${created.id}`);
            }}
          />
        </Panel>
      )}
      <Panel
        title="Subnets"
        actions={
          <label className="field field-inline">
            <span>Show</span>
            <select value={version} onChange={(e) => setVersion(e.target.value)}>
              <option value="">IPv4 and IPv6</option>
              <option value="4">IPv4</option>
              <option value="6">IPv6</option>
            </select>
          </label>
        }
      >
        <ErrorNote error={list.error} />
        {list.loading && !list.data && <Loading />}
        {list.data && rows.length === 0 && (
          <Empty>No subnets yet. They appear after the first agent report, or add one by hand.</Empty>
        )}
        {rows.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Network</th>
                  <th scope="col">Name</th>
                  <th scope="col">VLAN</th>
                  <th scope="col">Size</th>
                  <th scope="col">Usage</th>
                  <th scope="col">Source</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <Link to={`/ip/subnets/${s.id}`} className="row-link addr">
                        {s.network}
                      </Link>
                    </td>
                    <td>{s.name ?? "–"}</td>
                    <td className="num">{s.vlan ?? "–"}</td>
                    <td className="num">{formatSize(s.usage.size)}</td>
                    <td className="cell-usage">
                      <UsageBar usage={s.usage} />
                    </td>
                    <td>
                      <Badge>{s.source === "manual" ? "Manual" : "Discovered"}</Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      <DuplicateIps />
    </>
  );
}
