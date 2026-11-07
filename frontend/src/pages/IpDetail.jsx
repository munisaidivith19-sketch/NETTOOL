import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ips as ipsApi } from "../api/api.js";
import { useAuth } from "../auth/AuthProvider.jsx";
import { can } from "../auth/permissions.js";
import { ConfirmButton, Empty, ErrorNote, Loading, PageHead, Panel, SuccessNote } from "../components/ui.jsx";
import { TypeInfo } from "../components/aiParts.jsx";
import { formatDateTime, timeAgo } from "../format.js";
import { useResource } from "../hooks/useResource.js";
import { IpStatus, ReserveForm } from "./ipParts.jsx";

function Hop({ label, children }) {
  return (
    <li className="chain-hop">
      <span className="chain-label">{label}</span>
      <span className="chain-value">{children ?? <span className="muted">unknown</span>}</span>
    </li>
  );
}

function PortName({ port }) {
  return (
    <>
      <Link to={`/devices/${port.device_id}`} className="row-link">
        {port.device || port.mgmt_ip}
      </Link>
      {port.interface && (
        <>
          {" "}
          <span className="addr">{port.interface}</span>
        </>
      )}
      {port.interface_alias && <span className="muted"> ({port.interface_alias})</span>}
    </>
  );
}

export default function IpDetail() {
  const { ip } = useParams();
  const { user } = useAuth();
  const canReserve = can(user, "ip.reserve");
  const { data: d, error, loading, reload } = useResource((signal) => ipsApi.get(ip, { signal }), [ip]);
  const [note, setNote] = useState(null);
  const [actionError, setActionError] = useState(null);

  return (
    <>
      <PageHead title={<span className="addr">{d?.ip ?? ip}</span>}>
        {d?.subnet && (
          <Link to={`/ip/subnets/${d.subnet.id}`} className="text-link">
            Subnet <span className="addr">{d.subnet.network}</span>
          </Link>
        )}
      </PageHead>
      <ErrorNote error={error} />
      {loading && !d && <Loading />}
      {d && (
        <>
          {d.duplicate_alert && (
            <p className="notice notice-error" role="alert">
              <strong>Duplicate IP.</strong> {d.duplicate_alert.message}
            </p>
          )}
          <Panel title="Where this address is">
            <ol className="chain">
              <Hop label="IP">
                <span className="addr">{d.ip}</span> <IpStatus status={d.status} />
              </Hop>
              <Hop label="MAC">
                {d.macs_recent.length > 1 ? (
                  <span className="addr">{d.macs_recent.join(", ")}</span>
                ) : (
                  d.mac && <span className="addr">{d.mac}</span>
                )}
              </Hop>
              <Hop label="Device">{d.owner && <PortName port={d.owner} />}</Hop>
              <Hop label="Switch port">
                {d.switch_port ? (
                  <>
                    <Link to={`/devices/${d.switch_port.device_id}`} className="row-link">
                      {d.switch_port.device}
                    </Link>{" "}
                    port <span className="addr">{d.switch_port.port}</span>
                    {d.switch_port.vlan ? `, VLAN ${d.switch_port.vlan}` : ""}
                  </>
                ) : (
                  <span className="muted">not found in any switch MAC address table</span>
                )}
              </Hop>
            </ol>
            <dl className="facts">
              <div>
                <dt>Subnet</dt>
                <dd>{d.subnet ? <span className="addr">{d.subnet.network}</span> : "Not inside any known subnet"}</dd>
              </div>
              {d.mac && (
                <div>
                  <dt>Device type</dt>
                  <dd>
                    <TypeInfo mac={d.mac} classification={d.classification} onChanged={reload} />
                  </dd>
                </div>
              )}
              <div>
                <dt>Seen via</dt>
                <dd>{d.sources.length ? d.sources.join(", ") : "–"}</dd>
              </div>
              <div>
                <dt>First seen</dt>
                <dd>{formatDateTime(d.first_seen)}</dd>
              </div>
              <div>
                <dt>Last seen</dt>
                <dd>{d.last_seen ? `${timeAgo(d.last_seen)} (${formatDateTime(d.last_seen)})` : "–"}</dd>
              </div>
            </dl>
          </Panel>

          <Panel title="Seen in ARP / neighbour tables">
            {d.seen_by.length === 0 ? (
              <Empty>No router or switch has this address in its ARP table.</Empty>
            ) : (
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th scope="col">Device and interface</th>
                      <th scope="col">MAC</th>
                      <th scope="col">Type</th>
                      <th scope="col">Last seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {d.seen_by.map((s) => (
                      <tr key={`${s.device_id}-${s.mac}`} className={s.recent ? "" : "row-old"}>
                        <td>
                          <PortName port={s} />
                        </td>
                        <td className="addr">{s.mac}</td>
                        <td>{s.kind ?? "–"}</td>
                        <td>{timeAgo(s.last_seen)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>

          <Panel title="Reservation">
            <SuccessNote>{note}</SuccessNote>
            <ErrorNote error={actionError} />
            {d.reservation ? (
              <>
                <dl className="facts">
                  <div>
                    <dt>Host name</dt>
                    <dd>{d.reservation.hostname || "–"}</dd>
                  </div>
                  <div>
                    <dt>MAC</dt>
                    <dd className="addr">{d.reservation.mac || "–"}</dd>
                  </div>
                  <div>
                    <dt>Description</dt>
                    <dd>{d.reservation.description || "–"}</dd>
                  </div>
                  <div>
                    <dt>Reserved by</dt>
                    <dd>
                      {d.reservation.reserved_by} · {formatDateTime(d.reservation.reserved_at)}
                    </dd>
                  </div>
                </dl>
                {canReserve && (
                  <ConfirmButton
                    confirmLabel="Release reservation"
                    onConfirm={async () => {
                      try {
                        await ipsApi.release(d.ip);
                        setNote("Reservation released.");
                        setActionError(null);
                        reload();
                      } catch (err) {
                        setActionError(err);
                      }
                    }}
                  >
                    Release
                  </ConfirmButton>
                )}
              </>
            ) : canReserve && d.subnet && (d.status === "free" || d.status === "stale") ? (
              <ReserveForm
                initialIp={d.ip}
                onReserved={() => {
                  setNote("Reserved.");
                  reload();
                }}
              />
            ) : (
              <Empty>Not reserved.</Empty>
            )}
          </Panel>
        </>
      )}
    </>
  );
}
