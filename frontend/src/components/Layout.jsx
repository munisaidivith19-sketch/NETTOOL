import { useEffect, useState } from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "../auth/AuthProvider.jsx";
import { can, ROLE_LABELS } from "../auth/permissions.js";
import { useSummary } from "./SummaryProvider.jsx";
import ThemeToggle from "./ThemeToggle.jsx";

const NAV = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/devices", label: "Devices" },
  { to: "/ip", label: "IP addresses" },
  { to: "/alerts", label: "Alerts" },
  { to: "/topology", label: "Topology" },
  { to: "/config", label: "Configuration" },
  { to: "/changes", label: "Changes" },
];

const ADMIN_NAV = [
  { to: "/admin/users", label: "Users" },
  { to: "/admin/agents", label: "Agents" },
  { to: "/admin/notifications", label: "Notifications" },
  { to: "/admin/audit", label: "Audit log" },
];

function PortIcon() {
  // An RJ45 port outline: the NetMap mark.
  return (
    <svg width="22" height="22" viewBox="0 0 22 22" aria-hidden="true">
      <path d="M3 6h16v11h-4v2H7v-2H3z" fill="none" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
      <path d="M7 9v3M10 9v3M13 9v3M16 9v3" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  );
}

function NavItems({ items }) {
  return items.map((item) => (
    <li key={item.label}>
      {item.soon ? (
        <span className="nav-link" aria-disabled="true">
          {item.label}
          <span className="nav-note">Soon</span>
        </span>
      ) : (
        <NavLink to={item.to} end={item.end} className="nav-link">
          {item.label}
        </NavLink>
      )}
    </li>
  ));
}

function AlertCounter() {
  const { data } = useSummary();
  const open = data?.alerts_open ?? 0;
  const critical = data?.alerts_by_severity?.critical ?? 0;
  const label = open === 1 ? "1 open alert" : `${open} open alerts`;
  return (
    <Link to="/alerts" className={`alert-counter${critical ? " alert-counter-critical" : ""}`} aria-label={label}>
      <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
        <path d="M8 1.5 15 14.5H1z" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" />
        <path d="M8 6v4M8 11.5v1" stroke="currentColor" strokeWidth="1.6" />
      </svg>
      <span aria-hidden="true">{data ? open : "–"}</span>
    </Link>
  );
}

export default function Layout() {
  const { user, logout } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);
  const location = useLocation();

  useEffect(() => setMenuOpen(false), [location.pathname]); // close the phone menu on navigation

  return (
    <div className="shell">
      <nav className="sidebar" aria-label="Main" data-open={menuOpen || undefined}>
        <div className="sidebar-top">
          <Link to="/" className="wordmark">
            <PortIcon />
            NetMap
          </Link>
          <button
            type="button"
            className="menu-button"
            aria-expanded={menuOpen}
            aria-controls="main-nav"
            onClick={() => setMenuOpen((open) => !open)}
          >
            Menu
          </button>
        </div>
        <div className="nav-groups" id="main-nav">
          <ul className="nav-list">
            <NavItems items={NAV} />
          </ul>
          {can(user, "admin.view") && (
            <>
              <p className="nav-heading">Admin</p>
              <ul className="nav-list">
                <NavItems items={ADMIN_NAV} />
              </ul>
            </>
          )}
        </div>
        <div className="sidebar-foot">
          <ThemeToggle />
        </div>
      </nav>
      <div className="workspace">
        <header className="topbar">
          <AlertCounter />
          <div className="user-chip">
            <span className="user-name">{user.username}</span>
            <span className={`role role-${user.role}`}>{ROLE_LABELS[user.role] ?? user.role}</span>
          </div>
          <Link to="/account/password" className="topbar-link">
            Password
          </Link>
          <button type="button" className="button button-secondary" onClick={logout}>
            Sign out
          </button>
        </header>
        <main className="main" id="main">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
