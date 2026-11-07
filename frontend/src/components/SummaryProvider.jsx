import { createContext, useContext } from "react";
import { dashboard } from "../api/api.js";
import { useResource } from "../hooks/useResource.js";

/*
 * One /api/dashboard/summary poll (every 30 s) shared by the top bar's alert counter and the
 * dashboard page, so the two never disagree and the backend gets one request, not two.
 */
export const REFRESH_MS = 30_000;
const SummaryContext = createContext({ data: null, error: null, loading: false, reload: () => {} });

export function SummaryProvider({ children }) {
  const summary = useResource((signal) => dashboard.summary({ signal }), [], { refreshMs: REFRESH_MS });
  return <SummaryContext.Provider value={summary}>{children}</SummaryContext.Provider>;
}

export function useSummary() {
  return useContext(SummaryContext);
}
