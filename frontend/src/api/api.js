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
};

export const agents = {
  list: (options) => request("GET", "/api/agents", options),
  create: (name) => request("POST", "/api/agents", { body: { name } }),
  revoke: (id) => request("POST", `/api/agents/${enc(id)}/revoke`),
};

export const audit = {
  list: (query, options) => request("GET", "/api/audit", { query, ...options }),
};
