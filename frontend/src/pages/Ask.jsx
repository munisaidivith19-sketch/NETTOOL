/*
 * Ask NetMap: a plain-English question becomes a read-only database query.
 * The exact query that ran is always shown, so a wrong interpretation is easy to spot.
 * Answers are plain text in a table: values come from devices and may contain anything.
 */
import { useEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { ai } from "../api/api.js";
import { Badge, Empty, ErrorNote, Loading, PageHead, Panel } from "../components/ui.jsx";
import { formatDateTime } from "../format.js";
import { useResource } from "../hooks/useResource.js";

const MAX_QUESTION = 300;
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/;

function cellText(value) {
  if (value === null || value === undefined || value === "") return "–";
  if (Array.isArray(value)) return value.join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  if (typeof value === "string" && ISO_TIME.test(value)) return formatDateTime(value);
  return String(value);
}

/* Link a value to its page when the column says what it is. */
function Cell({ column, value, row }) {
  const text = cellText(value);
  if (value && typeof value === "string") {
    if (column === "ip" || column === "mgmt_ip") {
      return (
        <Link to={`/ip/address/${encodeURIComponent(value)}`} className="row-link addr">
          {text}
        </Link>
      );
    }
    if (column === "sys_name" && row._id) {
      return (
        <Link to={`/devices/${encodeURIComponent(row._id)}`} className="row-link">
          {text}
        </Link>
      );
    }
  }
  return text;
}

function Answer({ answer }) {
  const columns = answer.columns.filter((c) => c !== "_id");
  return (
    <Panel
      title="Answer"
      actions={
        <Badge tone="neutral">{answer.source === "rules" ? "Built-in parser" : "Language model"}</Badge>
      }
    >
      {answer.explanation && <p>{answer.explanation}</p>}
      {answer.rows.length === 0 ? (
        <Empty>No matching records.</Empty>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                {columns.map((c) => (
                  <th key={c} scope="col">
                    {c}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {answer.rows.map((row, i) => (
                // Rows have no stable id of their own (counts, groups), so the index is the key.
                <tr key={i}>
                  {columns.map((c) => (
                    <td key={c}>
                      <Cell column={c} value={row[c]} row={row} />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="small muted">
        {answer.row_count} row(s){answer.row_count >= answer.limit ? `, limited to ${answer.limit}` : ""}.
      </p>
      <details className="query-box">
        <summary>Query that ran</summary>
        <pre className="device-text">{JSON.stringify(answer.query, null, 2)}</pre>
        <p className="small muted">
          Read-only: only find-style stages on allowlisted collections and fields, at most 100 rows, 3 seconds.
          {!answer.readonly_user &&
            " Development mode: the read-only database user (AI_MONGODB_URI) is not configured, so the main connection is used."}
        </p>
      </details>
    </Panel>
  );
}

export default function Ask() {
  const location = useLocation();
  const navigate = useNavigate();
  const status = useResource((signal) => ai.status({ signal }), []);
  const [question, setQuestion] = useState("");
  const [state, setState] = useState({ busy: false, answer: null, error: null });
  const inputRef = useRef(null);

  async function run(text) {
    const q = text.trim();
    if (q.length < 2) return;
    setQuestion(q);
    setState({ busy: true, answer: null, error: null });
    try {
      setState({ busy: false, answer: await ai.ask(q), error: null });
    } catch (error) {
      setState({ busy: false, answer: null, error });
    }
  }

  // A question typed in the top bar arrives as navigation state (never from the URL, so a
  // link someone sends can't make the page run a question by itself).
  const incoming = location.state?.question;
  useEffect(() => {
    if (incoming) {
      run(incoming);
      navigate(location.pathname, { replace: true, state: null });
    }
    // Runs once per incoming question; `run` is deliberately not a dependency.
  }, [incoming]);

  const rejected = state.error?.body?.detail;
  const examples = status.data?.examples ?? [];
  const provider = status.data?.provider;

  return (
    <>
      <PageHead title="Ask NetMap" />
      <Panel>
        <form
          className="ask-form"
          onSubmit={(event) => {
            event.preventDefault();
            run(question);
          }}
        >
          <label htmlFor="ask-question">Question</label>
          <div className="ask-row">
            <input
              id="ask-question"
              ref={inputRef}
              type="text"
              value={question}
              maxLength={MAX_QUESTION}
              placeholder="Which switch port is 10.10.10.20 on?"
              onChange={(event) => setQuestion(event.target.value)}
              autoComplete="off"
            />
            <button type="submit" className="button" disabled={state.busy || question.trim().length < 2}>
              {state.busy ? "Asking…" : "Ask"}
            </button>
          </div>
        </form>
        {examples.length > 0 && (
          <div className="ask-examples">
            <span className="small muted">Try:</span>
            {examples.map((example) => (
              <button
                key={example}
                type="button"
                className="chip"
                onClick={() => {
                  setQuestion(example);
                  run(example);
                }}
              >
                {example}
              </button>
            ))}
          </div>
        )}
        {provider && (
          <p className="small muted">
            {provider === "none"
              ? "No language model is configured: NetMap's built-in parser answers common questions."
              : `Questions the built-in parser doesn't know go to a language model (${provider}). It only sees your question, never your network data.`}
          </p>
        )}
      </Panel>

      {state.busy && <Loading what="Asking" />}
      {state.error && (
        <Panel title="No answer">
          <ErrorNote error={state.error} />
          {rejected?.query_text && (
            <details className="query-box" open>
              <summary>The query that was refused</summary>
              <pre className="device-text">{rejected.query_text}</pre>
            </details>
          )}
        </Panel>
      )}
      {state.answer && <Answer answer={state.answer} />}
    </>
  );
}
