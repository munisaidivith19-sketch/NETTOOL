/*
 * One function per backend route, so pages never build URLs by hand. Path parts that come
 * from data (ids, IPs) are passed through encodeURIComponent.
 */
import { request } from "./client.js";

const enc = encodeURIComponent;

export const auth = {
  me: (options) => request("GET", "/api/auth/me", { auth: false, ...options }),
  login: (username, password) =>
    request("POST", "/api/auth/login", { body: { username, password }, auth: false }),
  logout: () => request("POST", "/api/auth/logout", { auth: false }),
  changePassword: (current_password, new_password) =>
    request("POST", "/api/auth/change-password", { body: { current_password, new_password } }),
};

/* Two-step sign-in (Phase 8). verify is the second sign-in step, so it runs without a session. */
export const mfa = {
  status: (options) => request("GET", "/api/auth/mfa", options),
  verify: (body) => request("POST", "/api/auth/mfa/verify", { body, auth: false }),
  setup: () => request("POST", "/api/auth/mfa/setup"),
  enable: (code) => request("POST", "/api/auth/mfa/enable", { body: { code } }),
  recoveryCodes: (code) => request("POST", "/api/auth/mfa/recovery-codes", { body: { code } }),
  disable: (password, code) => request("POST", "/api/auth/mfa/disable", { body: { password, code } }),
};

export const dashboard = {
  summary: (options) => request("GET", "/api/dashboard/summary", options),
};

export const devices = {
  list: (query, options) => request("GET", "/api/devices", { query, ...options }),
  get: (id, options) => request("GET", `/api/devices/${enc(id)}`, options),
  metrics: (id, query, options) => request("GET", `/api/devices/${enc(id)}/metrics`, { query, ...options }),
};

export const topology = {
  graph: (options) => request("GET", "/api/topology", options),
  locate: (q, options) => request("GET", "/api/topology/locate", { query: { q }, ...options }),
};

export const notifications = {
  status: (options) => request("GET", "/api/admin/notifications", options),
  test: () => request("POST", "/api/admin/notifications/test"),
};

export const subnets = {
  list: (options) => request("GET", "/api/subnets", options),
  get: (id, options) => request("GET", `/api/subnets/${enc(id)}`, options),
  create: (body) => request("POST", "/api/subnets", { body }),
  update: (id, body) => request("PATCH", `/api/subnets/${enc(id)}`, { body }),
  remove: (id) => request("DELETE", `/api/subnets/${enc(id)}`),
  ips: (id, query, options) => request("GET", `/api/subnets/${enc(id)}/ips`, { query, ...options }),
  nextFree: (id) => request("GET", `/api/subnets/${enc(id)}/next-free`),
};

export const ips = {
  search: (q, options) => request("GET", "/api/ips/search", { query: { q }, ...options }),
  get: (ip, options) => request("GET", `/api/ips/${enc(ip)}`, options),
  reserve: (body) => request("POST", "/api/ips/reservations", { body }),
  release: (ip) => request("DELETE", `/api/ips/reservations/${enc(ip)}`),
};

export const alerts = {
  list: (query, options) => request("GET", "/api/alerts", { query, ...options }),
  acknowledge: (id) => request("POST", `/api/alerts/${enc(id)}/acknowledge`),
  resolve: (id) => request("POST", `/api/alerts/${enc(id)}/resolve`),
};

export const users = {
  list: (options) => request("GET", "/api/users", options),
  create: (body) => request("POST", "/api/users", { body }),
  update: (id, body) => request("PATCH", `/api/users/${enc(id)}`, { body }),
  resetPassword: (id, new_password) =>
    request("POST", `/api/users/${enc(id)}/reset-password`, { body: { new_password } }),
  resetMfa: (id) => request("POST", `/api/users/${enc(id)}/mfa/reset`),
};

export const agents = {
  list: (options) => request("GET", "/api/agents", options),
  create: (name) => request("POST", "/api/agents", { body: { name } }),
  revoke: (id) => request("POST", `/api/agents/${enc(id)}/revoke`),
};

export const audit = {
  list: (query, options) => request("GET", "/api/audit", { query, ...options }),
};

export const configs = {
  overview: (options) => request("GET", "/api/configs", options),
  compliance: (id, options) => request("GET", `/api/devices/${enc(id)}/compliance`, options),
  versions: (id, options) => request("GET", `/api/devices/${enc(id)}/configs`, options),
  version: (id, version, options) => request("GET", `/api/devices/${enc(id)}/configs/${enc(version)}`, options),
  diff: (id, from, to, options) =>
    request("GET", `/api/devices/${enc(id)}/configs/diff`, { query: { from, to }, ...options }),
  backupNow: (id) => request("POST", `/api/devices/${enc(id)}/configs/backup-now`),
};

export const changes = {
  list: (query, options) => request("GET", "/api/changes", { query, ...options }),
  get: (id, options) => request("GET", `/api/changes/${enc(id)}`, options),
  templates: (options) => request("GET", "/api/templates", options),
  preview: (body) => request("POST", "/api/changes/preview", { body }),
  create: (body) => request("POST", "/api/changes", { body }),
  update: (id, body) => request("PUT", `/api/changes/${enc(id)}`, { body }),
  submit: (id) => request("POST", `/api/changes/${enc(id)}/submit`),
  approve: (id, body) => request("POST", `/api/changes/${enc(id)}/approve`, { body }),
  reject: (id, reason) => request("POST", `/api/changes/${enc(id)}/reject`, { body: { reason } }),
  cancel: (id) => request("POST", `/api/changes/${enc(id)}/cancel`),
};

export const ai = {
  status: (options) => request("GET", "/api/ai/status", options),
  ask: (question) => request("POST", "/api/ai/ask", { body: { question } }),
  explain: (body) => request("POST", "/api/ai/explain", { body }),
};

export const predictions = {
  list: (query, options) => request("GET", "/api/predictions", { query, ...options }),
  subnet: (id, options) => request("GET", `/api/subnets/${enc(id)}/forecast`, options),
  device: (id, query, options) => request("GET", `/api/devices/${enc(id)}/forecast`, { query, ...options }),
  correctType: (mac, type) => request("PUT", `/api/macs/${enc(mac)}/classification`, { body: { type } }),
  resetType: (mac) => request("DELETE", `/api/macs/${enc(mac)}/classification`),
};
