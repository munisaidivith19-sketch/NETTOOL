import { useCallback, useEffect, useRef, useState } from "react";

/*
 * Load data for a page: const { data, error, loading, reload } = useResource(fetcher, [deps]).
 * - fetcher(signal) returns a promise; the request is aborted when the page is left or the
 *   deps change, so a slow old response can never overwrite a newer one.
 * - refreshMs re-fetches in the background (the dashboard uses 30 s). Old data stays on screen
 *   while refreshing, so the page doesn't flicker.
 */
export function useResource(fetcher, deps, { refreshMs } = {}) {
  const [state, setState] = useState({ data: null, error: null, loading: true });
  const controllerRef = useRef(null);
  // The caller lists what the fetcher depends on, exactly like a useEffect dependency list.
  const run = useCallback(fetcher, deps);

  const load = useCallback(async () => {
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    setState((s) => ({ ...s, loading: true }));
    try {
      const data = await run(controller.signal);
      if (!controller.signal.aborted) setState({ data, error: null, loading: false });
    } catch (error) {
      if (!controller.signal.aborted && error?.name !== "AbortError") {
        setState((s) => ({ ...s, error, loading: false }));
      }
    }
  }, [run]);

  useEffect(() => {
    setState({ data: null, error: null, loading: true });
    load();
    const timer = refreshMs ? setInterval(load, refreshMs) : null;
    return () => {
      controllerRef.current?.abort();
      if (timer) clearInterval(timer);
    };
  }, [load, refreshMs]);

  return { ...state, reload: load };
}
