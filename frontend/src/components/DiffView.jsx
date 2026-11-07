/*
 * Side-by-side config diff. Rows come from the backend (difflib), already aligned:
 * same | changed | added | removed | skip (a run of unchanged lines) | truncated.
 * Config text is device data: shown as text only. Colour is backed up by a +/- marker.
 */
const MARK = { added: "+", removed: "−", changed: "~", same: "" };

export default function DiffView({ rows, fromLabel, toLabel }) {
  return (
    <div className="diff" role="table" aria-label={`Differences between ${fromLabel} and ${toLabel}`}>
      <div className="diff-row diff-head" role="row">
        <span role="columnheader" className="diff-cell">
          {fromLabel}
        </span>
        <span role="columnheader" className="diff-cell">
          {toLabel}
        </span>
      </div>
      {rows.map((row, i) => {
        if (row.kind === "skip" || row.kind === "truncated") {
          return (
            <div key={i} className="diff-row diff-skip" role="row">
              <span role="cell" className="diff-cell">
                {row.kind === "skip" ? `… ${row.count} unchanged lines …` : "… diff truncated …"}
              </span>
            </div>
          );
        }
        const left = row.kind === "added" ? null : row;
        const right = row.kind === "removed" ? null : row;
        return (
          <div key={i} className={`diff-row diff-${row.kind}`} role="row">
            <span role="cell" className={`diff-cell${left ? "" : " diff-empty"}`}>
              {left && (
                <>
                  <span className="diff-no">{row.left_no}</span>
                  <span className="diff-mark">{MARK[row.kind]}</span>
                  <code>{row.left}</code>
                </>
              )}
            </span>
            <span role="cell" className={`diff-cell${right ? "" : " diff-empty"}`}>
              {right && (
                <>
                  <span className="diff-no">{row.right_no}</span>
                  <span className="diff-mark">{MARK[row.kind]}</span>
                  <code>{row.right}</code>
                </>
              )}
            </span>
          </div>
        );
      })}
    </div>
  );
}
