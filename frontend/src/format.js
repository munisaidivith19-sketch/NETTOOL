/*
 * Display helpers.
 * Address counts arrive as strings: an IPv6 /64 has 18,446,744,073,709,551,616 addresses, far
 * above JavaScript's safe integer limit (2^53). Number("18446744073709551616") would silently
 * round, so counts are formatted with BigInt, which is exact.
 */

const groupFormat = new Intl.NumberFormat("en-US");

export function formatCount(value) {
  if (value === null || value === undefined || value === "") return "–";
  try {
    return groupFormat.format(BigInt(value));
  } catch {
    return String(value);
  }
}

/* 2^64 and up is unreadable as digits; "2^64" is how engineers say it. */
export function formatSize(value) {
  try {
    const n = BigInt(value);
    if (n >= 2n ** 32n && (n & (n - 1n)) === 0n) return `2^${n.toString(2).length - 1}`;
  } catch {
    // fall through
  }
  return formatCount(value);
}

export function formatPercent(percent) {
  if (typeof percent !== "number" || Number.isNaN(percent)) return "–";
  if (percent > 0 && percent < 0.01) return "<0.01%";
  return `${percent.toFixed(percent < 10 ? 2 : 1)}%`;
}

const dateTime = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

export function formatDateTime(value) {
  if (!value) return "–";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "–" : dateTime.format(date);
}

const relative = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
const STEPS = [
  [60, "second"],
  [60, "minute"],
  [24, "hour"],
  [30, "day"],
  [12, "month"],
  [Infinity, "year"],
];

export function timeAgo(value, now = Date.now()) {
  if (!value) return "never";
  let amount = (new Date(value).getTime() - now) / 1000;
  if (Number.isNaN(amount)) return "–";
  for (const [size, unit] of STEPS) {
    if (Math.abs(amount) < size) return relative.format(Math.round(amount), unit);
    amount /= size;
  }
  return "–";
}

export function formatUptime(seconds) {
  if (seconds === null || seconds === undefined) return "–";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days) return `${days} d ${hours} h`;
  if (hours) return `${hours} h ${minutes} min`;
  return `${minutes} min`;
}

/* Traffic rate in bits per second, in network units (1 kb/s = 1000 b/s, not 1024). */
export function formatBps(bps) {
  if (bps === null || bps === undefined) return "–";
  const units = ["b/s", "kb/s", "Mb/s", "Gb/s", "Tb/s"];
  let value = Number(bps);
  let unit = 0;
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000;
    unit += 1;
  }
  const digits = unit === 0 || value >= 100 ? 0 : value >= 10 ? 1 : 2;
  return `${value.toFixed(digits)} ${units[unit]}`;
}

export const DEVICE_STATUS = {
  up: { mark: "up", label: "Up" },
  snmp_error: { mark: "warning", label: "SNMP error" },
  down: { mark: "down", label: "Down" },
};

export const ALERT_TYPES = {
  duplicate_ip: "Duplicate IP",
  subnet_usage: "Subnet usage",
  device_down: "Device down",
  interface_down: "Uplink down",
  new_mac: "New device (MAC)",
  anomaly: "Anomaly",
  compliance: "Compliance",
  config_changed: "Config changed",
  change_failed: "Change failed",
};
