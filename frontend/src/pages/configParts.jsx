import { Badge } from "../components/ui.jsx";

/* Small pieces shared by the configuration and change-request pages. */

export function ScoreBadge({ score }) {
  if (score === null || score === undefined) return <span className="muted">–</span>;
  const tone = score >= 90 ? "up" : score >= 70 ? "warn" : "down";
  return (
    <Badge tone={tone} title="Compliance score out of 100">
      {score}/100
    </Badge>
  );
}

export const CHANGE_STATUS = {
  draft: ["Draft", "neutral"],
  pending_approval: ["Waiting for approval", "warn"],
  approved: ["Approved", "up"],
  rejected: ["Rejected", "down"],
  pushing: ["Pushing", "warn"],
  verifying: ["Verifying", "warn"],
  done: ["Done", "up"],
  rolled_back: ["Rolled back", "down"],
  failed: ["Failed", "down"],
  cancelled: ["Cancelled", "neutral"],
  expired: ["Expired", "neutral"],
};

export function ChangeStatus({ status }) {
  const [label, tone] = CHANGE_STATUS[status] ?? [status, "neutral"];
  return <Badge tone={tone}>{label}</Badge>;
}

export const BACKUP_ERRORS = {
  no_credentials: "No SSH credentials on the agent for this device",
  auth_failed: "SSH login rejected",
  timeout: "No answer on SSH",
  host_key_rejected: "Unknown or changed SSH host key",
  ssh_error: "SSH connection failed",
  too_large: "Config larger than 1 MB",
  empty_config: "Device returned an empty config",
};

/*
 * The server lists each protected interface in both forms ("Gi1/0/1" and
 * "GigabitEthernet1/0/1") so the denylist matches either; show only the long form.
 */
export function interfaceNames(names) {
  const key = (n) => `${n.slice(0, 2).toLowerCase()}${n.replace(/^[A-Za-z-]+/, "")}`;
  const longest = new Map();
  for (const n of names) {
    const k = key(n);
    if (!longest.has(k) || n.length > longest.get(k).length) longest.set(k, n);
  }
  return [...longest.values()].join(", ");
}

/* Blocked lines from the denylist (or secrets / bad template variables). Text, never HTML. */
export function Violations({ items }) {
  if (!items?.length) return null;
  return (
    <div className="notice notice-error" role="alert">
      <strong>Blocked – this change can't be submitted:</strong>
      <ul className="violations">
        {items.map((v, i) => (
          <li key={i}>
            {v.line > 0 && <span className="muted">Line {v.line}: </span>}
            {v.text && <code>{v.text}</code>} {v.reason}
          </li>
        ))}
      </ul>
    </div>
  );
}
