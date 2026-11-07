import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { devices as devicesApi } from "../api/api.js";
import StatusMark from "../components/StatusMark.jsx";
import { Badge, Empty, ErrorNote, Loading, PageHead, Panel } from "../components/ui.jsx";
import { DEVICE_STATUS, timeAgo } from "../format.js";
import { useResource } from "../hooks/useResource.js";

// Same characters the backend accepts; anything else would only produce a 422.
const SEARCH_PATTERN = "[A-Za-z0-9.:_\\- /]+";

export function DeviceStatus({ status }) {
  const info = DEVICE_STATUS[status] ?? { mark: "unknown", label: status };
  return <StatusMark status={info.mark} label={info.label} />;
}

export function V2cBadge() {
  return (
    <Badge tone="warn" title="SNMPv2c sends the community string in clear text. Use SNMPv3 outside the lab.">
      SNMPv2c
    </Badge>
  );
}

export default function Devices() {
  const [params, setParams] = useSearchParams();
  const q = params.get("q") ?? "";
  const status = params.get("status") ?? "";
  const [draft, setDraft] = useState(q);
  useEffect(() => setDraft(q), [q]);

  const list = useResource(
    (signal) => devicesApi.list({ q: q || undefined, status: status || undefined }, { signal }),
    [q, status],
  );

  function update(next) {
    const merged = { q, status, ...next };
    setParams(Object.fromEntries(Object.entries(merged).filter(([, v]) => v)), { replace: true });
  }

  return (
    <>
      <PageHead title="Devices" />
      <Panel>
        <form
          className="toolbar"
          role="search"
          onSubmit={(e) => {
            e.preventDefault();
            update({ q: draft.trim() });
          }}
        >
          <label className="field field-inline">
            <span>Search</span>
            <input
              type="search"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder="Name, IP, subnet, vendor or location"
              maxLength={100}
              pattern={SEARCH_PATTERN}
              title="Letters, digits and . : _ - / only"
            />
          </label>
          <label className="field field-inline">
            <span>Status</span>
            <select value={status} onChange={(e) => update({ status: e.target.value })}>
              <option value="">Any</option>
              <option value="up">Up</option>
              <option value="snmp_error">SNMP error</option>
              <option value="down">Down</option>
            </select>
          </label>
          <button type="submit" className="button">
            Search
          </button>
        </form>
        <ErrorNote error={list.error} />
        {list.loading && !list.data && <Loading />}
        {list.data?.length === 0 && (
          <Empty>{q || status ? "No devices match." : "No devices yet. Run the agent to discover the network."}</Empty>
        )}
        {list.data?.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Status</th>
                  <th scope="col">Name</th>
                  <th scope="col">Management IP</th>
                  <th scope="col">Vendor</th>
                  <th scope="col">Location</th>
                  <th scope="col">Last seen</th>
                </tr>
              </thead>
              <tbody>
                {list.data.map((d) => (
                  <tr key={d.id}>
                    <td>
                      <DeviceStatus status={d.status} />
                    </td>
                    <td>
                      <Link to={`/devices/${d.id}`} className="row-link">
                        {d.sys_name || "(no name)"}
                      </Link>{" "}
                      {d.snmp_v2c && <V2cBadge />}
                    </td>
                    <td className="addr">{d.mgmt_ip}</td>
                    <td>{d.vendor ?? "–"}</td>
                    <td>{d.sys_location || "–"}</td>
                    <td title={d.last_seen ?? ""}>{timeAgo(d.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </>
  );
}
