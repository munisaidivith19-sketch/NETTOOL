import { useState } from "react";
import { notifications as notificationsApi } from "../../api/api.js";
import StatusMark from "../../components/StatusMark.jsx";
import { Badge, Empty, ErrorNote, Loading, PageHead, Panel, SuccessNote } from "../../components/ui.jsx";
import { ALERT_TYPES, formatDateTime } from "../../format.js";
import { useResource } from "../../hooks/useResource.js";

const STATUS_TONE = { sent: "up", failed: "down", suppressed: "warn" };
const REASONS = { cooldown: "same alert sent in the last 30 min", hourly_cap: "hourly limit reached" };

function Channel({ name, on, setup }) {
  return (
    <div>
      <dt>{name}</dt>
      <dd>
        {on ? <StatusMark status="up" label="Configured" /> : <StatusMark status="unknown" label="Off" />}
        {!on && <span className="muted small"> Set {setup} on the server.</span>}
      </dd>
    </div>
  );
}

export default function Notifications() {
  const { data, error, loading, reload } = useResource((signal) => notificationsApi.status({ signal }), []);
  const [busy, setBusy] = useState(false);
  const [testError, setTestError] = useState(null);
  const [testResult, setTestResult] = useState(null);

  async function sendTest() {
    setBusy(true);
    setTestError(null);
    setTestResult(null);
    try {
      const result = await notificationsApi.test();
      setTestResult(result.channels);
      reload();
    } catch (err) {
      setTestError(err);
    } finally {
      setBusy(false);
    }
  }

  const anyChannel = data && (data.channels.telegram || data.channels.email);

  return (
    <>
      <PageHead title="Notifications" />
      <ErrorNote error={error} />
      {loading && !data && <Loading />}
      {data && (
        <>
          <Panel title="Channels">
            <p className="muted">
              Alerts are sent when they open or reopen, if they are at least <strong>{data.min_severity}</strong>.
              At most one message per alert every {data.cooldown_minutes} minutes and {data.hourly_cap} messages
              per hour. Bot tokens and passwords are set as server environment variables, never in this page.
            </p>
            <dl className="facts">
              <Channel name="Telegram" on={data.channels.telegram} setup="TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID" />
              <Channel name="E-mail" on={data.channels.email} setup="SMTP_HOST, SMTP_FROM and SMTP_TO" />
            </dl>
            <div className="form-actions">
              <button type="button" className="button" disabled={!anyChannel || busy} onClick={sendTest}>
                {busy ? "Sending…" : "Send test notification"}
              </button>
            </div>
            <ErrorNote error={testError} />
            {testResult && (
              <SuccessNote>
                {Object.entries(testResult)
                  .map(([channel, result]) => `${channel}: ${result}`)
                  .join(" · ")}
              </SuccessNote>
            )}
          </Panel>

          <Panel title="Recent notifications (7 days)">
            {data.recent.length === 0 ? (
              <Empty>Nothing sent yet.</Empty>
            ) : (
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th scope="col">When</th>
                      <th scope="col">Alert</th>
                      <th scope="col">Result</th>
                      <th scope="col">Channels</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.recent.map((n, i) => (
                      <tr key={`${n.at}-${i}`}>
                        <td>{formatDateTime(n.at)}</td>
                        <td>{n.type === "test" ? "Test message" : (ALERT_TYPES[n.type] ?? n.type)}</td>
                        <td>
                          <Badge tone={STATUS_TONE[n.status] ?? "neutral"}>{n.status}</Badge>
                          {n.reason && <span className="muted small"> {REASONS[n.reason] ?? n.reason}</span>}
                        </td>
                        <td>
                          {Object.entries(n.channels)
                            .map(([channel, result]) => `${channel}: ${result}`)
                            .join(" · ") || "–"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        </>
      )}
    </>
  );
}
