/*
 * A small set of line icons drawn as plain SVG paths (no icon font, no extra request, nothing
 * the CSP has to allow). Icons are decorative: the text next to them is the accessible name,
 * so every icon is aria-hidden. A button with only an icon must have an aria-label.
 */
const PATHS = {
  grid: (
    <>
      <rect x="3" y="3" width="6" height="6" rx="1.5" />
      <rect x="11" y="3" width="6" height="6" rx="1.5" />
      <rect x="3" y="11" width="6" height="6" rx="1.5" />
      <rect x="11" y="11" width="6" height="6" rx="1.5" />
    </>
  ),
  bell: (
    <>
      <path d="M5 13.5V9a5 5 0 0 1 10 0v4.5l1.5 1.5h-13z" />
      <path d="M8.5 17.5a1.6 1.6 0 0 0 3 0" />
    </>
  ),
  spark: (
    <>
      <path d="M10 2.5 11.6 8.4 17.5 10l-5.9 1.6L10 17.5l-1.6-5.9L2.5 10l5.9-1.6z" />
    </>
  ),
  server: (
    <>
      <rect x="3" y="3.5" width="14" height="5.5" rx="1.5" />
      <rect x="3" y="11" width="14" height="5.5" rx="1.5" />
      <path d="M6 6.25h.01M6 13.75h.01" />
    </>
  ),
  hash: <path d="M8 3 6.5 17M13.5 3 12 17M3.5 7.5h13M3 12.5h13" />,
  topology: (
    <>
      <circle cx="10" cy="4.5" r="2" />
      <circle cx="4.5" cy="15.5" r="2" />
      <circle cx="15.5" cy="15.5" r="2" />
      <path d="M9 6.3 5.5 13.7M11 6.3l3.5 7.4M6.5 15.5h7" />
    </>
  ),
  file: (
    <>
      <path d="M5 2.5h6.5L15 6v11.5H5z" />
      <path d="M11 2.5V6.5h4M7.5 10.5h5M7.5 13.5h5" />
    </>
  ),
  branch: (
    <>
      <circle cx="6" cy="4.5" r="2" />
      <circle cx="6" cy="15.5" r="2" />
      <circle cx="14" cy="7.5" r="2" />
      <path d="M6 6.5v7M14 9.5c0 3-4 2.5-7 4.6" />
    </>
  ),
  users: (
    <>
      <circle cx="7.5" cy="7" r="3" />
      <path d="M2.5 16.5a5 5 0 0 1 10 0M13 4.3a3 3 0 0 1 0 5.4M15 12.2a5 5 0 0 1 2.5 4.3" />
    </>
  ),
  key: (
    <>
      <circle cx="6.5" cy="13.5" r="3.5" />
      <path d="m9 11 7.5-7.5M14 6l2 2M12 8l1.5 1.5" />
    </>
  ),
  send: <path d="M17 3 3 9l5.5 2.5L11 17zM8.5 11.5 17 3" />,
  list: <path d="M7 5.5h10M7 10h10M7 14.5h10M3.5 5.5h.01M3.5 10h.01M3.5 14.5h.01" />,
  search: (
    <>
      <circle cx="9" cy="9" r="5.5" />
      <path d="m13.2 13.2 3.8 3.8" />
    </>
  ),
  arrow: <path d="M4 10h11.5M11 5.5l4.5 4.5-4.5 4.5" />,
  refresh: <path d="M16 10a6 6 0 1 1-1.8-4.3M16 3.5v3.5h-3.5" />,
  logout: <path d="M8 3.5H4.5v13H8M12 6.5 15.5 10 12 13.5M15.5 10H7.5" />,
  lock: (
    <>
      <rect x="4" y="9" width="12" height="8" rx="2" />
      <path d="M7 9V6.5a3 3 0 0 1 6 0V9" />
    </>
  ),
  shield: <path d="M10 2.5 16 5v4.5c0 3.8-2.6 6.6-6 8-3.4-1.4-6-4.2-6-8V5z" />,
  pulse: <path d="M2.5 10.5h3.5l2-5 4 9 2-4h3.5" />,
  chevron: <path d="m7.5 4.5 5.5 5.5-5.5 5.5" />,
  agent: (
    <>
      <rect x="3" y="4" width="14" height="10" rx="2" />
      <path d="M7 17h6M10 14v3M6.5 9.5l2 1.5-2 1.5" />
    </>
  ),
};

export default function Icon({ name, size = 20, className = "" }) {
  return (
    <svg
      className={`icon ${className}`}
      width={size}
      height={size}
      viewBox="0 0 20 20"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {PATHS[name] ?? PATHS.grid}
    </svg>
  );
}
