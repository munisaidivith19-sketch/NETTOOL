import { Link, Route, Routes } from "react-router-dom";
import { useAuth } from "./auth/AuthProvider.jsx";
import { can } from "./auth/permissions.js";
import Layout from "./components/Layout.jsx";
import { SummaryProvider } from "./components/SummaryProvider.jsx";
import { PageHead } from "./components/ui.jsx";
import Agents from "./pages/admin/Agents.jsx";
import AuditLog from "./pages/admin/AuditLog.jsx";
import Users from "./pages/admin/Users.jsx";
import Alerts from "./pages/Alerts.jsx";
import ChangePassword from "./pages/ChangePassword.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import DeviceDetail from "./pages/DeviceDetail.jsx";
import Devices from "./pages/Devices.jsx";
import IpDetail from "./pages/IpDetail.jsx";
import IpSearch from "./pages/IpSearch.jsx";
import Login from "./pages/Login.jsx";
import SubnetDetail from "./pages/SubnetDetail.jsx";
import Subnets from "./pages/Subnets.jsx";

function NotFound() {
  return (
    <>
      <PageHead title="Page not found" />
      <p>
        <Link to="/">Back to the dashboard</Link>
      </p>
    </>
  );
}

/* Hides admin pages from other roles. The backend refuses their API calls with 403 anyway. */
function RequireAdmin({ children }) {
  const { user } = useAuth();
  if (can(user, "admin.view")) return children;
  return (
    <>
      <PageHead title="No access" />
      <p>This page is for administrators.</p>
    </>
  );
}

export default function App() {
  const { status, user } = useAuth();

  if (status === "loading") {
    return (
      <div className="auth-screen">
        <p className="muted" role="status">
          Loading NetMap…
        </p>
      </div>
    );
  }
  // Signed out: whatever the URL, show the login form. The URL is kept, so after signing in
  // the user lands on the page they were trying to open.
  if (status === "signed-out") return <Login />;
  if (user.must_change_password) return <ChangePassword forced />;

  return (
    <SummaryProvider>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="devices" element={<Devices />} />
          <Route path="devices/:id" element={<DeviceDetail />} />
          <Route path="ip" element={<Subnets />} />
          <Route path="ip/search" element={<IpSearch />} />
          <Route path="ip/subnets/:id" element={<SubnetDetail />} />
          <Route path="ip/address/:ip" element={<IpDetail />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="account/password" element={<ChangePassword />} />
          <Route path="admin/users" element={<RequireAdmin><Users /></RequireAdmin>} />
          <Route path="admin/agents" element={<RequireAdmin><Agents /></RequireAdmin>} />
          <Route path="admin/audit" element={<RequireAdmin><AuditLog /></RequireAdmin>} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </SummaryProvider>
  );
}
