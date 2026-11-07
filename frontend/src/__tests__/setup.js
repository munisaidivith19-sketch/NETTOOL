import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";
import { setAuthHandlers, setCsrfToken } from "../api/client.js";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  // The CSRF token and auth handlers are module state: reset them between tests.
  setCsrfToken(null);
  setAuthHandlers({ unauthorized: () => {}, passwordChangeRequired: () => {} });
  delete document.documentElement.dataset.theme;
  try {
    window.localStorage.clear();
  } catch {
    // ignore
  }
});
