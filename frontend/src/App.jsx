import { NavLink, Route, Routes } from "react-router-dom";
import ThemeToggle from "./components/ThemeToggle.jsx";
import Overview from "./pages/Overview.jsx";

// Sections arrive in later phases. They are listed now so the navigation shape is settled,
// but rendered as disabled items rather than links to empty pages.
const UPCOMING = ["Devices", "IP addresses", "Topology", "Alerts", "Configuration", "Admin"];

function PortIcon() {
  // An RJ45 port outline: the NetMap mark.
  return (
    <svg width="22" height="22" viewBox="0 0 22 22" aria-hidden="true">
      <path
        d="M3 6h16v11h-4v2H7v-2H3z"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinejoin="round"
      />
      <path d="M7 9v3M10 9v3M13 9v3M16 9v3" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  );
}

export default function App() {
  return (
    <div className="shell">
      <nav className="sidebar" aria-label="Main">
        <div className="wordmark">
          <PortIcon />
          NetMap
        </div>
        <ul className="nav-list">
          <li>
            <NavLink to="/" end className="nav-link">
              Overview
            </NavLink>
          </li>
          {UPCOMING.map((name) => (
            <li key={name}>
              <span className="nav-link" aria-disabled="true">
                {name}
                <span className="nav-note">Soon</span>
              </span>
            </li>
          ))}
        </ul>
        <div className="sidebar-foot">
          <ThemeToggle />
        </div>
      </nav>
      <main className="main">
        <Routes>
          <Route
            path="*"
            element={
              <>
                <div className="page-head">
                  <h1>Overview</h1>
                </div>
                <Overview />
              </>
            }
          />
        </Routes>
      </main>
    </div>
  );
}
