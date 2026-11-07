/*
 * Which buttons to show. This is only about not offering actions that would fail: the backend
 * checks the role on every request (CLAUDE.md 7.2), so editing this file grants nothing.
 * Keep it in step with the require_role(...) calls in backend/app/api/.
 */
const RULES = {
  "subnet.write": ["admin", "engineer"],
  "ip.reserve": ["admin", "engineer"],
  "alert.act": ["admin", "engineer"],
  "admin.view": ["admin"],
};

export function can(user, action) {
  return Boolean(user && !user.must_change_password && RULES[action]?.includes(user.role));
}

export const ROLE_LABELS = { admin: "Admin", engineer: "Engineer", viewer: "Viewer" };
