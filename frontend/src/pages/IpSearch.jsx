import { Link, useSearchParams } from "react-router-dom";
import { ips as ipsApi } from "../api/api.js";
import { Empty, ErrorNote, Loading, PageHead, Panel } from "../components/ui.jsx";
import { useResource } from "../hooks/useResource.js";
import { DeviceStatus } from "./Devices.jsx";
import { IpTable } from "./ipParts.jsx";
import { IpSearchBox } from "./Subnets.jsx";

const KIND = { ip: "IP address", network: "subnet", mac: "MAC address", hostname: "host name" };

export default function IpSearch() {
  const [params] = useSearchParams();
  const q = params.get("q") ?? "";
  const result = useResource((signal) => (q ? ipsApi.search(q, { signal }) : Promise.resolve(null)), [q]);
  const data = result.data;

  return (
    <>
      <PageHead title="Search addresses">
        <Link to="/ip" className="text-link">
          All subnets
        </Link>
      </PageHead>
      <Panel>
        <IpSearchBox key={q} initial={q} />
      </Panel>
      <ErrorNote error={result.error} />
      {q && result.loading && !data && <Loading what="Searching" />}
      {data && (
        <>
          {data.devices.length > 0 && (
            <Panel title="Matching devices">
              <ul className="row-list">
                {data.devices.map((d) => (
                  <li key={d.id}>
                    <Link to={`/devices/${d.id}`} className="row-link">
                      {d.name}
                    </Link>{" "}
                    <span className="addr muted">{d.mgmt_ip}</span> <DeviceStatus status={d.status} />
                  </li>
                ))}
              </ul>
            </Panel>
          )}
          <Panel title={`Addresses matching ${KIND[data.query_type] ?? "search"} “${q}”`}>
            {data.items.length === 0 ? <Empty>Nothing found.</Empty> : <IpTable rows={data.items} />}
            {data.truncated && <p className="muted small">Showing the first {data.items.length}. Narrow the search.</p>}
          </Panel>
        </>
      )}
    </>
  );
}
