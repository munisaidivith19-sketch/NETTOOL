import { Link, useParams } from "react-router-dom";
import { devices as devicesApi } from "../api/api.js";
import StatusMark from "../components/StatusMark.jsx";
import { Badge, Empty, ErrorNote, Loading, PageHead, Panel } from "../components/ui.jsx";
import { formatBps, formatDateTime, formatUptime, timeAgo } from "../format.js";
import { useResource } from "../hooks/useResource.js";
import { DeviceStatus, V2cBadge } from "./Devices.jsx";
import { IpStatus } from "./ipParts.jsx";

const IF_STATUS = { up: "up", down: "down" };

function Facts({ items }) {
  return (
    <dl className="facts">
      {items.map(([label, value]) => (
        <div key={label}>
          <dt>{label}</dt>
          <dd>{value ?? "–"}</dd>
        </div>
      ))}
    </dl>
  );
}

export default function DeviceDetail() {
  const { id } = useParams();
  const { data: d, error, loading } = useResource((signal) => devicesApi.get(id, { signal }), [id]);

  return (
    <>
      <PageHead title={d ? d.sys_name || d.mgmt_ip : "Device"}>
        <Link to={`/devices/${id}/config`} className="text-link">
          Configuration and compliance
        </Link>
        <Link to="/devices" className="text-link">
          All devices
        </Link>
      </PageHead>
      <ErrorNote error={error} />
      {loading && !d && <Loading />}
      {d && (
        <>
          <Panel title="Overview">
            <Facts
              items={[
                ["Status", <DeviceStatus key="s" status={d.status} />],
                ["Since", formatDateTime(d.status_changed_at)],
                ["Management IP", <span className="addr">{d.mgmt_ip}</span>],
                ["Vendor", d.vendor],
                ["Location", d.sys_location || "–"],
                [
                  "SNMP",
                  <>
                    {d.snmp_version ?? "–"} {d.snmp_v2c && <V2cBadge />}
                  </>,
                ],
                ["Uptime", formatUptime(d.uptime_seconds)],
                ["Last seen", `${timeAgo(d.last_seen)} (${formatDateTime(d.last_seen)})`],
                ["First seen", formatDateTime(d.first_seen)],
              ]}
            />
            {d.sys_descr && (
              <div className="descr">
                <h3>Description (sysDescr)</h3>
                {/* Device-supplied text: rendered as plain text, never as HTML. */}
                <pre className="device-text">{d.sys_descr}</pre>
              </div>
            )}
            {d.last_error && <ErrorNote>Last poll error: {d.last_error}</ErrorNote>}
          </Panel>

          <Panel title={`Interfaces (${d.interfaces.length})`}>
            {d.interfaces.length === 0 ? (
              <Empty>No interfaces reported.</Empty>
            ) : (
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th scope="col">#</th>
                      <th scope="col">Name</th>
                      <th scope="col">Description</th>
                      <th scope="col">Status</th>
                      <th scope="col">Speed</th>
                      <th scope="col">Traffic in / out</th>
                      <th scope="col">MAC</th>
                    </tr>
                  </thead>
                  <tbody>
                    {d.interfaces.map((i) => (
                      <tr key={i.if_index}>
                        <td className="num">{i.if_index}</td>
                        <td>{i.name ?? i.descr ?? "–"}</td>
                        <td>{i.alias || "–"}</td>
                        <td>
                          <StatusMark
                            status={IF_STATUS[i.oper_status] ?? "unknown"}
                            label={i.admin_status === "down" ? "Disabled" : (i.oper_status ?? "unknown")}
                          />
                        </td>
                        <td>{i.speed_mbps ? `${i.speed_mbps} Mb/s` : "–"}</td>
                        <td className="num">
                          {i.rates ? `${formatBps(i.rates.in_bps)} / ${formatBps(i.rates.out_bps)}` : "–"}
                        </td>
                        <td className="addr">{i.mac ?? "–"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>

          <Panel title={`Neighbours (${d.links.length})`}>
            {d.links.length === 0 ? (
              <Empty>No LLDP or CDP neighbours reported by this device.</Empty>
            ) : (
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th scope="col">Local port</th>
                      <th scope="col">Neighbour</th>
                      <th scope="col">Its port</th>
                      <th scope="col">Address</th>
                      <th scope="col">Learned by</th>
                      <th scope="col">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {d.links.map((l) => (
                      <tr key={`${l.protocol}-${l.if_index}-${l.remote_name}-${l.remote_port}`}>
                        <td className="addr">{l.local_port ?? "–"}</td>
                        <td>
                          {/* Neighbour names are what the neighbour claims: plain text. */}
                          {l.remote_device_id ? (
                            <Link to={`/devices/${l.remote_device_id}`} className="row-link">
                              {l.remote_name ?? "unnamed device"}
                            </Link>
                          ) : (
                            <>
                              {l.remote_name ?? "unnamed device"} <Badge>Not managed</Badge>
                            </>
                          )}
                          {l.remote_platform && <span className="muted small"> {l.remote_platform}</span>}
                        </td>
                        <td className="addr">{l.remote_port ?? "–"}</td>
                        <td className="addr">{l.remote_mgmt_ip ?? "–"}</td>
                        <td>{l.protocol.toUpperCase()}</td>
                        <td>
                          {l.status === "active" ? (
                            <StatusMark status="up" label="Seen now" />
                          ) : (
                            <StatusMark status="down" label={`Lost, last seen ${timeAgo(l.last_seen)}`} />
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>

          <Panel title={`IP addresses (${d.addresses.length})`}>
            {d.addresses.length === 0 ? (
              <Empty>No addresses on this device.</Empty>
            ) : (
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th scope="col">Address</th>
                      <th scope="col">Status</th>
                      <th scope="col">MAC</th>
                      <th scope="col">Last seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {d.addresses.map((a) => (
                      <tr key={a.ip}>
                        <td>
                          <Link to={`/ip/address/${encodeURIComponent(a.ip)}`} className="row-link addr">
                            {a.ip}
                          </Link>
                        </td>
                        <td>
                          <IpStatus status={a.status} />
                        </td>
                        <td className="addr">{a.mac ?? "–"}</td>
                        <td>{timeAgo(a.last_seen)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        </>
      )}
    </>
  );
}
