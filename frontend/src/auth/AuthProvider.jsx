import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { auth as authApi, mfa as mfaApi } from "../api/api.js";
import { setAuthHandlers, setCsrfToken } from "../api/client.js";

/*
 * Who is signed in. The browser holds the session cookie (httpOnly, so not readable here);
 * this context only holds the user's name and role for display and for hiding buttons.
 * The server checks the role on every request regardless.
 *
 * state.status: "loading" (asking /me) | "signed-out" | "signed-in"
 * state.notice: why the user is on the login page ("expired", "signed-out") or null
 * state.recoveryCodesLeft: set after signing in with a recovery code, for the "few left" warning
 *
 * Sign-in is one or two requests: login() returns { mfaRequired: true } when the account uses
 * two-step sign-in, and verifyMfa() then sends the code.
 */
const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [state, setState] = useState({ status: "loading", user: null, notice: null, recoveryCodesLeft: null });

  const acceptSession = useCallback((session) => {
    setCsrfToken(session.csrf_token);
    setState({
      status: "signed-in",
      user: session.user,
      notice: null,
      recoveryCodesLeft: session.recovery_codes_left ?? null,
    });
  }, []);

  const signOutLocally = useCallback((notice) => {
    setCsrfToken(null);
    setState({ status: "signed-out", user: null, notice });
  }, []);

  useEffect(() => {
    setAuthHandlers({
      unauthorized: () => signOutLocally("expired"),
      passwordChangeRequired: () =>
        setState((s) => (s.user ? { ...s, user: { ...s.user, must_change_password: true } } : s)),
      mfaSetupRequired: () =>
        setState((s) => (s.user ? { ...s, user: { ...s.user, mfa_setup_required: true } } : s)),
    });
  }, [signOutLocally]);

  useEffect(() => {
    // After a reload the cookie may still be valid: ask the server who we are.
    const controller = new AbortController();
    authApi
      .me({ signal: controller.signal })
      .then(acceptSession)
      .catch((error) => {
        if (error?.name !== "AbortError") signOutLocally(null);
      });
    return () => controller.abort();
  }, [acceptSession, signOutLocally]);

  const login = useCallback(
    async (username, password) => {
      const result = await authApi.login(username, password);
      if (result.mfa_required) return { mfaRequired: true };
      acceptSession(result);
      return { mfaRequired: false };
    },
    [acceptSession],
  );

  /* body: { code } or { recovery_code } */
  const verifyMfa = useCallback(async (body) => acceptSession(await mfaApi.verify(body)), [acceptSession]);

  /*
   * Turning MFA on replaces the session. The new CSRF token is needed at once, but the user
   * object is updated only later (finishMfaSetup), so the forced setup screen stays up while
   * the recovery codes are shown.
   */
  const enableMfa = useCallback(async (code) => {
    const result = await mfaApi.enable(code);
    setCsrfToken(result.session.csrf_token);
    return result;
  }, []);

  const dismissRecoveryWarning = useCallback(() => setState((s) => ({ ...s, recoveryCodesLeft: null })), []);

  const logout = useCallback(async () => {
    try {
      await authApi.logout(); // ends the session on the server, not just in this tab
    } finally {
      signOutLocally("signed-out");
    }
  }, [signOutLocally]);

  const changePassword = useCallback(
    async (current, next) => acceptSession(await authApi.changePassword(current, next)),
    [acceptSession],
  );

  const value = useMemo(
    () => ({
      ...state,
      login,
      verifyMfa,
      enableMfa,
      finishMfaSetup: acceptSession,
      dismissRecoveryWarning,
      logout,
      changePassword,
    }),
    [state, login, verifyMfa, enableMfa, acceptSession, dismissRecoveryWarning, logout, changePassword],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside <AuthProvider>");
  return value;
}
