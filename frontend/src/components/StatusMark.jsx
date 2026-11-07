/*
 * Status is shown by shape AND colour, never colour alone, so it still reads for colour-blind
 * users and in greyscale printouts:
 *   up = filled circle, down = hollow square, warning = triangle, unknown = dashed ring.
 * The visible text label next to it is what screen readers announce; the shape is decorative.
 */
const SHAPES = {
  up: <circle cx="8" cy="8" r="6" fill="currentColor" />,
  down: <rect x="2.5" y="2.5" width="11" height="11" fill="none" stroke="currentColor" strokeWidth="2.5" />,
  warning: <path d="M8 1.5 15 14.5H1z" fill="currentColor" />,
  unknown: (
    <circle cx="8" cy="8" r="5.5" fill="none" stroke="currentColor" strokeWidth="2" strokeDasharray="3 2.5" />
  ),
};

const LABELS = { up: "Up", down: "Down", warning: "Warning", unknown: "Checking" };

export default function StatusMark({ status = "unknown", label }) {
  const state = status in SHAPES ? status : "unknown";
  return (
    <span className={`status status-${state}`}>
      <svg className="status-shape" width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
        {SHAPES[state]}
      </svg>
      <span className="status-label">{label ?? LABELS[state]}</span>
    </span>
  );
}
