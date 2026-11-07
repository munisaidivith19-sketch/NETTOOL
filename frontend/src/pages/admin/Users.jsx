import { useState } from "react";
import { users as usersApi } from "../../api/api.js";
import { useAuth } from "../../auth/AuthProvider.jsx";
import { ROLE_LABELS } from "../../auth/permissions.js";
import { Badge, Dialog, Empty, ErrorNote, Field, Loading, PageHead, Panel, SuccessNote } from "../../components/ui.jsx";
import { formatDateTime } from "../../format.js";
import { useResource } from "../../hooks/useResource.js";

const ROLES = ["viewer", "engineer", "admin"];

function CreateUser({ onCreated }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("viewer");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const user = await usersApi.create({ username: username.trim(), password, role });
      setUsername("");
      setPassword("");
      setRole("viewer");
      onCreated(user);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="form-grid" onSubmit={submit} aria-label="Create user">
      <ErrorNote error={error} />
      <label className="field">
        <span>Username</span>
        <input
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          required
          pattern="[a-z0-9._\-]{3,32}"
          title="3–32 lowercase letters, digits, . _ or -"
          autoCapitalize="none"
          autoComplete="off"
        />
      </label>
      <Field label="Temporary password" hint="At least 12 characters. They must change it at first sign-in.">
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          minLength={12}
          maxLength={256}
          autoComplete="new-password"
        />
      </Field>
      <label className="field">
        <span>Role</span>
        <select value={role} onChange={(e) => setRole(e.target.value)}>
          {ROLES.map((r) => (
            <option key={r} value={r}>
              {ROLE_LABELS[r]}
            </option>
          ))}
        </select>
      </label>
      <div className="form-actions">
        <button type="submit" className="button" disabled={busy}>
          {busy ? "Creating…" : "Create user"}
        </button>
      </div>
    </form>
  );
}

function ResetPassword({ user, onClose, onDone }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  return (
    <Dialog title={`Reset password for ${user.username}`} onClose={onClose}>
      <form
        className="form-grid"
        onSubmit={async (e) => {
          e.preventDefault();
          try {
            await usersApi.resetPassword(user.id, password);
            onDone();
          } catch (err) {
            setError(err);
          }
        }}
      >
        <p className="muted field-wide">The user must choose a new password at their next sign-in. Their sessions end.</p>
        <ErrorNote error={error} />
        <label className="field field-wide">
          <span>Temporary password</span>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength={12}
            maxLength={256}
            autoComplete="new-password"
          />
        </label>
        <div className="form-actions">
          <button type="submit" className="button">
            Reset password
          </button>
          <button type="button" className="button button-secondary" onClick={onClose}>
            Cancel
          </button>
        </div>
      </form>
    </Dialog>
  );
}

export default function Users() {
  const { user: me } = useAuth();
  const list = useResource((signal) => usersApi.list({ signal }), []);
  const [note, setNote] = useState(null);
  const [error, setError] = useState(null);
  const [resetting, setResetting] = useState(null);

  async function change(user, body, message) {
    setError(null);
    try {
      await usersApi.update(user.id, body);
      setNote(message);
      list.reload();
    } catch (err) {
      setError(err);
    }
  }

  return (
    <>
      <PageHead title="Users" />
      <Panel title="Create a user">
        <CreateUser
          onCreated={(u) => {
            setNote(`Created ${u.username}.`);
            list.reload();
          }}
        />
      </Panel>
      <Panel title="All users">
        <SuccessNote>{note}</SuccessNote>
        <ErrorNote error={error ?? list.error} />
        {list.loading && !list.data && <Loading />}
        {list.data?.length === 0 && <Empty>No users.</Empty>}
        {list.data?.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Username</th>
                  <th scope="col">Role</th>
                  <th scope="col">State</th>
                  <th scope="col">Last sign-in</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {list.data.map((u) => {
                  const self = u.id === me.id;
                  return (
                    <tr key={u.id}>
                      <td>
                        {u.username} {self && <span className="muted">(you)</span>}
                      </td>
                      <td>
                        <select
                          aria-label={`Role of ${u.username}`}
                          value={u.role}
                          disabled={self}
                          onChange={(e) => change(u, { role: e.target.value }, `${u.username} is now ${ROLE_LABELS[e.target.value]}.`)}
                        >
                          {ROLES.map((r) => (
                            <option key={r} value={r}>
                              {ROLE_LABELS[r]}
                            </option>
                          ))}
                        </select>
                      </td>
                      <td>
                        {u.disabled ? <Badge tone="down">Disabled</Badge> : <Badge tone="up">Active</Badge>}{" "}
                        {u.must_change_password && <Badge tone="warn">Must change password</Badge>}
                      </td>
                      <td>{formatDateTime(u.last_login_at)}</td>
                      <td className="actions">
                        {!self && (
                          <>
                            <button
                              type="button"
                              className="button button-secondary"
                              onClick={() =>
                                change(u, { disabled: !u.disabled }, `${u.username} ${u.disabled ? "enabled" : "disabled"}.`)
                              }
                            >
                              {u.disabled ? "Enable" : "Disable"}
                            </button>
                            <button type="button" className="button button-secondary" onClick={() => setResetting(u)}>
                              Reset password
                            </button>
                          </>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      {resetting && (
        <ResetPassword
          user={resetting}
          onClose={() => setResetting(null)}
          onDone={() => {
            setNote(`Password reset for ${resetting.username}.`);
            setResetting(null);
            list.reload();
          }}
        />
      )}
    </>
  );
}
