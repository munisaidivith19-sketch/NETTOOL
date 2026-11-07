/*
 * A small line chart for forecasts: past values (solid), the forecast (dashed), its
 * uncertainty band (shaded), and optional "warning" (80 %) and "full" lines.
 *
 * Plain SVG drawn by React: no chart library, no inline style attributes (the strict CSP
 * blocks them), colours come from CSS classes and design tokens. Screen readers get a text
 * summary, and every chart has a "Show as table" fallback.
 */
import { useId } from "react";

const W = 640;
const H = 220;
const PAD = { left: 64, right: 16, top: 14, bottom: 30 };
const TABLE_ROWS = 14;

function toTime(x) {
  return typeof x === "number" ? x : new Date(x.length === 10 ? `${x}T00:00:00Z` : x).getTime();
}

function pathOf(points, sx, sy) {
  return points.map((p, i) => `${i ? "L" : "M"}${sx(p.t).toFixed(1)},${sy(p.y).toFixed(1)}`).join(" ");
}

/* Every n-th point, always keeping the last one, so the table stays short. */
function sample(rows, count) {
  if (rows.length <= count) return rows;
  const step = Math.ceil(rows.length / count);
  return rows.filter((_, i) => i % step === 0 || i === rows.length - 1);
}

export default function ForecastChart({
  history = [],
  forecast = [],
  capacity = null,
  threshold = null,
  formatValue = (v) => String(Math.round(v)),
  formatTime = (t) => new Date(t).toLocaleDateString(),
  label,
  summary,
}) {
  const titleId = useId();
  const descId = useId();
  const past = history.map((p) => ({ t: toTime(p.x), y: p.y })).filter((p) => Number.isFinite(p.t));
  const future = forecast
    .map((p) => ({ t: toTime(p.x), y: p.y, lo: p.lo ?? p.y, hi: p.hi ?? p.y }))
    .filter((p) => Number.isFinite(p.t));
  const all = [...past, ...future];
  if (all.length < 2) return null;

  const t0 = Math.min(...all.map((p) => p.t));
  const t1 = Math.max(...all.map((p) => p.t));
  const top = Math.max(capacity ?? 0, ...all.map((p) => p.y), ...future.map((p) => p.hi)) * 1.05 || 1;
  const sx = (t) => PAD.left + ((t - t0) / Math.max(t1 - t0, 1)) * (W - PAD.left - PAD.right);
  const sy = (y) => H - PAD.bottom - (Math.max(y, 0) / top) * (H - PAD.top - PAD.bottom);
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => f * top);
  const today = past.length ? past[past.length - 1].t : null;
  // The forecast line starts at the last real point, so the two lines join up.
  const joined = today !== null && future.length ? [past[past.length - 1], ...future] : future;
  const band = future.length
    ? `${future.map((p, i) => `${i ? "L" : "M"}${sx(p.t).toFixed(1)},${sy(p.hi).toFixed(1)}`).join(" ")} ` +
      `${[...future].reverse().map((p) => `L${sx(p.t).toFixed(1)},${sy(p.lo).toFixed(1)}`).join(" ")} Z`
    : null;
  const rows = sample(
    [...past.map((p) => ({ ...p, kind: "Measured" })), ...future.map((p) => ({ ...p, kind: "Forecast" }))],
    TABLE_ROWS,
  );

  return (
    <figure className="chart">
      <svg
        className="chart-svg"
        viewBox={`0 0 ${W} ${H}`}
        role="img"
        aria-labelledby={`${titleId} ${descId}`}
      >
        <title id={titleId}>{label}</title>
        <desc id={descId}>{summary}</desc>
        {ticks.map((v) => (
          <g key={v}>
            <line className="chart-grid" x1={PAD.left} x2={W - PAD.right} y1={sy(v)} y2={sy(v)} />
            <text className="chart-axis" x={PAD.left - 6} y={sy(v) + 4} textAnchor="end">
              {formatValue(v)}
            </text>
          </g>
        ))}
        {band && <path className="chart-band" d={band} />}
        {threshold !== null && threshold < top && (
          <>
            <line className="chart-threshold" x1={PAD.left} x2={W - PAD.right} y1={sy(threshold)} y2={sy(threshold)} />
            <text className="chart-mark" x={W - PAD.right - 4} y={sy(threshold) - 4} textAnchor="end">
              80 %
            </text>
          </>
        )}
        {capacity !== null && (
          <>
            <line className="chart-capacity" x1={PAD.left} x2={W - PAD.right} y1={sy(capacity)} y2={sy(capacity)} />
            <text className="chart-mark" x={W - PAD.right - 4} y={sy(capacity) - 4} textAnchor="end">
              Full
            </text>
          </>
        )}
        {today !== null && future.length > 0 && (
          <line className="chart-today" x1={sx(today)} x2={sx(today)} y1={PAD.top} y2={H - PAD.bottom} />
        )}
        {past.length > 1 && <path className="chart-history" d={pathOf(past, sx, sy)} />}
        {joined.length > 1 && <path className="chart-forecast" d={pathOf(joined, sx, sy)} />}
        <text className="chart-axis" x={PAD.left} y={H - 8}>
          {formatTime(t0)}
        </text>
        {today !== null && future.length > 0 && (
          <text className="chart-axis" x={sx(today)} y={H - 8} textAnchor="middle">
            now
          </text>
        )}
        <text className="chart-axis" x={W - PAD.right} y={H - 8} textAnchor="end">
          {formatTime(t1)}
        </text>
      </svg>
      <figcaption className="chart-legend small">
        <span className="legend legend-history">Measured</span>
        {future.length > 0 && <span className="legend legend-forecast">Forecast</span>}
        {future.length > 0 && <span className="legend legend-band">Likely range</span>}
      </figcaption>
      <details className="chart-table">
        <summary>Show as table</summary>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th scope="col">Time</th>
                <th scope="col">Value</th>
                <th scope="col">Likely range</th>
                <th scope="col">Kind</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={`${r.kind}-${r.t}`}>
                  <td>{formatTime(r.t)}</td>
                  <td className="num">{formatValue(r.y)}</td>
                  <td className="num">{r.lo !== undefined ? `${formatValue(r.lo)} – ${formatValue(r.hi)}` : "–"}</td>
                  <td>{r.kind}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </figure>
  );
}
