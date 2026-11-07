import { useCallback, useEffect, useState } from "react";
import { getHealth } from "../api/client.js";
import StatusMark from "../components/StatusMark.jsx";

const REFRESH_MS = 30_000;

const timeFormat = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });

export default function Overview() {
  const [health, setHealth] = useState({ api: "unknown", database: "unknown" });
  const [checkedAt, setCheckedAt] = useState(null);
  const [checking, setChecking] = useState(true);

  const check = useCallback(async (signal) => {
    setChecking(true);
    try {
      setHealth(await getHealth({ signal }));
      setCheckedAt(new Date());
    } catch {
      // Aborted because the page was left; nothing to update.
    } finally {
      if (!signal?.aborted) setChecking(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    check(controller.signal);
    const timer = setInterval(() => check(controller.signal), REFRESH_MS);
    return () => {
      controller.abort();
      clearInterval(timer);
    };
  }, [check]);

  return (
    <section className="health" aria-labelledby="health-title">
      <div className="health-head">
        <h2 id="health-title">System health</h2>
        <button type="button" className="button" onClick={() => check()} disabled={checking}>
          {checking ? "Checking…" : "Check now"}
        </button>
      </div>
      <dl className="health-rows" aria-live="polite">
        <div className="health-row">
          <dt>Backend API</dt>
          <dd>
            <StatusMark status={checking && !checkedAt ? "unknown" : health.api} />
          </dd>
        </div>
        <div className="health-row">
          <dt>Database</dt>
          <dd>
            <StatusMark status={checking && !checkedAt ? "unknown" : health.database} />
          </dd>
        </div>
      </dl>
      <p className="health-foot">
        {checkedAt ? `Last checked ${timeFormat.format(checkedAt)}. Refreshes every 30 seconds.` : "Checking the backend…"}
      </p>
      {health.api === "down" && (
        <p className="health-hint">
          The backend isn’t answering. Start it from the backend folder with{" "}
          <code className="addr">uvicorn app.main:app --reload</code>.
        </p>
      )}
      {health.api === "up" && health.database === "down" && (
        <p className="health-hint">
          The backend is running but can’t reach MongoDB. Check that the MongoDB service is running and
          that <code className="addr">MONGODB_URI</code> is correct.
        </p>
      )}
    </section>
  );
}
