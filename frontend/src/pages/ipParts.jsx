/* Pieces shared by the IP management pages. */
import { useState } from "react";
import { Link } from "react-router-dom";
import { ips as ipsApi } from "../api/api.js";
import StatusMark from "../components/StatusMark.jsx";
import { ErrorNote } from "../components/ui.jsx";
import { timeAgo } from "../format.js";

const IP_STATUS = {
  used: { mark: "up", label: "In use" },
  reserved: { mark: "warning", label: "Reserved" },
  stale: { mark: "unknown", label: "Stale" },
  free: { mark: "unknown", label: "Free" },
};

export function IpStatus({ status }) {
  const info = IP_STATUS[status] ?? { mark: "unknown", label: status };
  return <StatusMark status={info.mark} label={info.label} />;
}

export function ipLink(ip) {
  return `/ip/address/${encodeURIComponent(ip)}`;
}

export function IpTable({ rows }) {
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th scope="col">Address</th>
            <th scope="col">Status</th>
            <th scope="col">MAC</th>
            <th scope="col">Device</th>
            <th scope="col">Host / note</th>
            <th scope="col">Last seen</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.ip}>
              <td>
                <Link to={ipLink(r.ip)} className="row-link addr">
                  {r.ip}
                </Link>
              </td>
              <td>
                <IpStatus status={r.status} />
              </td>
              <td className="addr">{r.mac ?? r.reservation?.mac ?? "–"}</td>
              <td>
                {r.device ? (
                  <Link to={`/devices/${r.device.id}`} className="row-link">
                    {r.device.name || r.device.mgmt_ip}
                  </Link>
                ) : (
                  "–"
                )}
                {r.device?.relation === "seen_by" && <span className="muted"> (ARP)</span>}
              </td>
              <td>{r.reservation ? r.reservation.hostname || r.reservation.description || "–" : "–"}</td>
              <td>{r.last_seen ? timeAgo(r.last_seen) : "–"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const HOSTNAME = "[A-Za-z0-9]([A-Za-z0-9\\-]{0,61}[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9\\-]{0,61}[A-Za-z0-9])?)*";

/* Reserve one address. The backend refuses it if it's in use, reserved, the gateway, etc. */
export function ReserveForm({ initialIp = "", onReserved }) {
  const [ip, setIp] = useState(initialIp);
  const [hostname, setHostname] = useState("");
  const [mac, setMac] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  // Let "Next free IP" fill the field after the form is open.
  const [lastInitial, setLastInitial] = useState(initialIp);
  if (initialIp !== lastInitial) {
    setLastInitial(initialIp);
    setIp(initialIp);
  }

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const body = { ip: ip.trim(), description: description.trim() };
      if (hostname.trim()) body.hostname = hostname.trim();
      if (mac.trim()) body.mac = mac.trim();
      const result = await ipsApi.reserve(body);
      setHostname("");
      setMac("");
      setDescription("");
      onReserved?.(result);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="form-grid" onSubmit={submit} aria-label="Reserve an IP address">
      <ErrorNote error={error} />
      <label className="field">
        <span>IP address</span>
        <input className="addr" value={ip} onChange={(e) => setIp(e.target.value)} required maxLength={45} />
      </label>
      <label className="field">
        <span>Host name (optional)</span>
        <input
          value={hostname}
          onChange={(e) => setHostname(e.target.value)}
          maxLength={253}
          pattern={HOSTNAME}
          title="Letters, digits, - and . only, e.g. printer-2.floor1"
        />
      </label>
      <label className="field">
        <span>MAC (optional)</span>
        <input className="addr" value={mac} onChange={(e) => setMac(e.target.value)} maxLength={20} />
      </label>
      <label className="field field-wide">
        <span>Description (optional)</span>
        <input value={description} onChange={(e) => setDescription(e.target.value)} maxLength={500} />
      </label>
      <div className="form-actions">
        <button type="submit" className="button" disabled={busy}>
          {busy ? "Reserving…" : "Reserve"}
        </button>
      </div>
    </form>
  );
}

const blankRange = () => ({ start: "", end: "", note: "" });

/*
 * Create (no `subnet`) or edit a subnet. Empty fields are sent as null, which the backend
 * treats as "clear this field". The network itself can't be changed after creation.
 */
export function SubnetForm({ subnet, onSave, onCancel }) {
  const [network, setNetwork] = useState(subnet?.network ?? "");
  const [name, setName] = useState(subnet?.name ?? "");
  const [vlan, setVlan] = useState(subnet?.vlan ?? "");
  const [gateway, setGateway] = useState(subnet?.gateway ?? "");
  const [description, setDescription] = useState(subnet?.description ?? "");
  const [ranges, setRanges] = useState(subnet?.reserved_ranges?.map((r) => ({ ...r })) ?? []);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  function setRange(index, field, value) {
    setRanges((list) => list.map((r, i) => (i === index ? { ...r, [field]: value } : r)));
  }

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    const body = {
      name: name.trim() || null,
      vlan: vlan === "" ? null : Number(vlan),
      gateway: gateway.trim() || null,
      description: description.trim() || null,
      reserved_ranges: ranges
        .filter((r) => r.start.trim() || r.end.trim())
        .map((r) => ({ start: r.start.trim(), end: r.end.trim(), note: r.note.trim() })),
    };
    if (!subnet) body.network = network.trim();
    try {
      await onSave(body);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="form-grid" onSubmit={submit} aria-label={subnet ? "Edit subnet" : "Add subnet"}>
      <ErrorNote error={error} />
      <label className="field">
        <span>Network (CIDR)</span>
        <input
          className="addr"
          value={network}
          onChange={(e) => setNetwork(e.target.value)}
          placeholder="10.0.10.0/24 or 2001:db8:10::/64"
          required
          disabled={Boolean(subnet)}
          maxLength={49}
        />
      </label>
      <label className="field">
        <span>Name</span>
        <input value={name} onChange={(e) => setName(e.target.value)} maxLength={64} />
      </label>
      <label className="field">
        <span>VLAN</span>
        <input type="number" min={1} max={4094} value={vlan} onChange={(e) => setVlan(e.target.value)} />
      </label>
      <label className="field">
        <span>Gateway</span>
        <input className="addr" value={gateway} onChange={(e) => setGateway(e.target.value)} maxLength={45} />
      </label>
      <label className="field field-wide">
        <span>Description</span>
        <input value={description} onChange={(e) => setDescription(e.target.value)} maxLength={500} />
      </label>
      <fieldset className="field-wide ranges">
        <legend>Reserved ranges (DHCP pools, printers…) – never offered as “next free”</legend>
        {ranges.map((r, i) => (
          <div className="range-row" key={i}>
            <input
              className="addr"
              aria-label={`Range ${i + 1} start`}
              placeholder="start"
              value={r.start}
              onChange={(e) => setRange(i, "start", e.target.value)}
              maxLength={45}
            />
            <input
              className="addr"
              aria-label={`Range ${i + 1} end`}
              placeholder="end"
              value={r.end}
              onChange={(e) => setRange(i, "end", e.target.value)}
              maxLength={45}
            />
            <input
              aria-label={`Range ${i + 1} note`}
              placeholder="note"
              value={r.note}
              onChange={(e) => setRange(i, "note", e.target.value)}
              maxLength={100}
            />
            <button
              type="button"
              className="button button-secondary"
              onClick={() => setRanges((list) => list.filter((_, j) => j !== i))}
              aria-label={`Remove range ${i + 1}`}
            >
              Remove
            </button>
          </div>
        ))}
        <button type="button" className="button button-secondary" onClick={() => setRanges((l) => [...l, blankRange()])}>
          Add range
        </button>
      </fieldset>
      <div className="form-actions">
        <button type="submit" className="button" disabled={busy}>
          {busy ? "Saving…" : subnet ? "Save changes" : "Add subnet"}
        </button>
        {onCancel && (
          <button type="button" className="button button-secondary" onClick={onCancel}>
            Cancel
          </button>
        )}
      </div>
    </form>
  );
}
