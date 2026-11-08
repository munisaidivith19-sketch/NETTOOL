import { useEffect, useRef, useState } from "react";
import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthProvider.jsx";
import { can, ROLE_LABELS } from "../auth/permissions.js";
import Icon from "./icons.jsx";
import { useSummary } from "./SummaryProvider.jsx";
import ThemeToggle from "./ThemeToggle.jsx";

/*
 * Sidebar sections. `count` names a live number from the dashboard summary that is shown as a
 * badge next to the link (open alerts, devices down); the badge hides itself at zero.
 */
const NAV_GROUPS = [
  {
    heading: "Overview",
    items: [
      { to: "/", label: "Dashboard", icon: "grid", end: true },
      { to: "/alerts", label: "Alerts", icon: "bell", count: "alerts" },
      { to: "/ask", label: "Ask NetMap", icon: "spark" },
    ],
  },
  {
    heading: "Network",
    items: [
      { to: "/devices", label: "Devices", icon: "server", count: "down" },
      { to: "/ip", label: "IP addresses", icon: "hash" },
      { to: "/topology", label: "Topology", icon: "topology" },
    ],
  },
  {
    heading: "Operations",
    items: [
      { to: "/config", label: "Configuration", icon: "file" },
      { to: "/changes", label: "Changes", icon: "branch" },
    ],
  },
];

const ADMIN_GROUP = {
  heading: "Admin",
  items: [
    { to: "/admin/users", label: "Users", icon: "users" },
    { to: "/admin/agents", label: "Agents", icon: "key" },
    { to: "/admin/notifications", label: "Notifications", icon: "send" },
    { to: "/admin/audit", label: "Audit log", icon: "list" },
  ],
};

/* Breadcrumb names for the first path segment, and for the admin / account sub-pages. */
const SECTIONS = {
  devices: "Devices",
  ip: "IP addresses",
  alerts: "Alerts",
  topology: "Topology",
  config: "Configuration",
  changes: "Changes",
  ask: "Ask NetMap",
  admin: "Admin",
  account: "Account",
};
const SUB_PAGES = {
  users: "Users",
  agents: "Agents",
  notifications: "Notifications",
  audit: "Audit log",
  password: "Password",
  security: "Two-step sign-in",
  new: "New",
  subnets: "Subnet",
  address: "Address",
  search: "Search",
};

function PortIcon() {
  // An RJ45 port outline: the NetMap mark.
  return (
    <svg width="22" height="22" viewBox="0 0 22 22" aria-hidden="true">
      <path d="M3 6h16v11h-4v2H7v-2H3z" fill="none" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
      <path d="M7 9v3M10 9v3M13 9v3M16 9v3" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  );
}

function useCounts() {
  const { data } = useSummary();
  return {
    alerts: { n: data?.alerts_open ?? 0, urgent: (data?.alerts_by_severity?.critical ?? 0) > 0, what: "open" },
    down: { n: data?.devices?.down ?? 0, urgent: true, what: "down" },
  };
}

function NavGroup({ group, counts }) {
  return (
    <div className="nav-group">
      <p className="nav-heading">{group.heading}</p>
      <ul className="nav-list">
        {group.items.map((item) => {
          const count = item.count ? counts[item.count] : null;
          return (
            <li key={item.to}>
              <NavLink to={item.to} end={item.end} className="nav-link">
                <Icon name={item.icon} className="nav-icon" />
                <span className="nav-label">{item.label}</span>
                {count?.n > 0 && (
                  <>
                    <span className={`nav-count${count.urgent ? " nav-count-urgent" : ""}`} aria-hidden="true">
                      {count.n}
                    </span>
                    {/* Leading comma, not a space: accessible-name computation trims spaces. */}
                    <span className="visually-hidden">
                      , {count.n} {count.what}
                    </span>
                  </>
                )}
              </NavLink>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function AlertCounter() {
  const { data } = useSummary();
  const open = data?.alerts_open ?? 0;
  const critical = data?.alerts_by_severity?.critical ?? 0;
  const label = open === 1 ? "1 open alert" : `${open} open alerts`;
  return (
    <Link to="/alerts" className={`alert-counter${critical ? " alert-counter-critical" : ""}`} aria-label={label}>
      <Icon name="bell" size={18} />
      <span aria-hidden="true">{data ? open : "–"}</span>
    </Link>
  );
}

function isTyping(target) {
  return target instanceof HTMLElement && (target.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName));
}

/*
 * The top-bar question box: hands the question to the Ask page as navigation state.
 * Press "/" anywhere (outside a text field) to jump into it.
 */
function AskBox() {
  const navigate = useNavigate();
  const [question, setQuestion] = useState("");
  const input = useRef(null);

  useEffect(() => {
    function onKey(event) {
      if (event.key !== "/" || event.ctrlKey || event.metaKey || event.altKey || isTyping(event.target)) return;
      event.preventDefault();
      input.current?.focus();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <form
      className="topbar-ask"
      role="search"
      onSubmit={(event) => {
        event.preventDefault();
        if (question.trim().length < 2) return;
        navigate("/ask", { state: { question: question.trim() } });
        setQuestion("");
      }}
    >
      <label htmlFor="topbar-ask" className="visually-hidden">
        Ask NetMap
      </label>
      <Icon name="search" size={18} className="topbar-ask-icon" />
      <input
        id="topbar-ask"
        ref={input}
        type="text"
        value={question}
        maxLength={300}
        placeholder="Ask NetMap…"
        autoComplete="off"
        aria-keyshortcuts="/"
        onChange={(event) => setQuestion(event.target.value)}
      />
      <kbd className="topbar-ask-key" aria-hidden="true">
        /
      </kbd>
    </form>
  );
}

function Breadcrumbs() {
  const { pathname } = useLocation();
  const [first, second] = pathname.split("/").filter(Boolean);
  const crumbs = [{ label: "NetMap", to: "/" }];
  if (!first) {
    crumbs.push({ label: "Dashboard" });
  } else {
    // "Admin" and "Account" have no page of their own, so they are plain text, not links.
    crumbs.push({ label: SECTIONS[first] ?? "Page", to: first === "admin" || first === "account" ? null : `/${first}` });
    if (second) crumbs.push({ label: SUB_PAGES[second] ?? "Details" });
  }
  return (
    <nav className="breadcrumbs" aria-label="Breadcrumb">
      <ol>
        {crumbs.map((crumb, i) => {
          const last = i === crumbs.length - 1;
          return (
            <li key={`${i}-${crumb.label}`}>
              {last || !crumb.to ? (
                <span aria-current={last ? "page" : undefined}>{crumb.label}</span>
              ) : (
                <Link to={crumb.to}>{crumb.label}</Link>
              )}
              {!last && <Icon name="chevron" size={14} className="breadcrumb-sep" />}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

export default function Layout() {
  const { user, logout, recoveryCodesLeft, dismissRecoveryWarning } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);
  const location = useLocation();
  const counts = useCounts();

  useEffect(() => setMenuOpen(false), [location.pathname]); // close the phone menu on navigation

  return (
    <div className="shell">
      <aside className="sidebar" data-open={menuOpen || undefined}>
        <div className="sidebar-top">
          <Link to="/" className="wordmark">
            <span className="wordmark-mark">
              <PortIcon />
            </span>
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
        <div className="sidebar-body" id="main-nav">
          <nav className="nav-groups" aria-label="Main">
            {NAV_GROUPS.map((group) => (
              <NavGroup key={group.heading} group={group} counts={counts} />
            ))}
            {can(user, "admin.view") && <NavGroup group={ADMIN_GROUP} counts={counts} />}
          </nav>
          <div className="sidebar-foot">
            <div className="account-links">
              <Link to="/account/password" className="account-link">
                <Icon name="lock" size={18} />
                Password
              </Link>
              <Link to="/account/security" className="account-link">
                <Icon name="shield" size={18} />
                Two-step
              </Link>
            </div>
            <div className="profile-card">
              <span className="avatar" aria-hidden="true">
                {user.username.slice(0, 1).toUpperCase()}
              </span>
              <span className="profile-text">
                <span className="user-name">{user.username}</span>
                <span className={`role role-${user.role}`}>{ROLE_LABELS[user.role] ?? user.role}</span>
              </span>
              <button type="button" className="button button-ghost button-small" onClick={logout}>
                <Icon name="logout" size={16} />
                Sign out
              </button>
            </div>
          </div>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <Breadcrumbs />
          <div className="topbar-tools">
            <AskBox />
            <AlertCounter />
            <ThemeToggle />
          </div>
        </header>
        <main className="main" id="main">
          {recoveryCodesLeft !== null && recoveryCodesLeft <= 2 && (
            <div className="notice notice-warn" role="status">
              You signed in with a recovery code. {recoveryCodesLeft} left.{" "}
              <Link to="/account/security" onClick={dismissRecoveryWarning}>
                Get new recovery codes
              </Link>{" "}
              <button type="button" className="link-button" onClick={dismissRecoveryWarning}>
                Dismiss
              </button>
            </div>
          )}
          <Outlet />
        </main>
      </div>
    </div>
  );
}
