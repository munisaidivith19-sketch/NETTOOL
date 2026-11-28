/*
 * Device-role icons for the network map, drawn on a 24x24 grid with 2px strokes.
 *
 * Each icon is plain data (a list of shapes). The same data becomes:
 *   - an SVG data: URL that Cytoscape paints inside the map node (CSP allows img-src data:), and
 *   - React <svg> elements for the legend.
 * No HTML strings are ever injected into the page.
 *
 * Shapes follow the usual network-diagram convention: router = circle with arrows,
 * switch = box with arrows, access point = Wi-Fi waves, outside neighbour = cloud.
 */

export const ROLES = ["router", "switch", "ap", "device", "external"];

export const ROLE_LABEL = {
  router: "Router",
  switch: "Switch",
  ap: "Access point",
  device: "Other device",
  external: "Not managed by NetMap",
};

const GLYPHS = {
  router: [
    { tag: "circle", cx: 12, cy: 12, r: 9 },
    { tag: "path", d: "M7.5 10h8M13.5 8l2 2-2 2M16.5 14h-8M10.5 12l-2 2 2 2" },
  ],
  switch: [
    { tag: "rect", x: 2.5, y: 5.5, width: 19, height: 13, rx: 2.5 },
    { tag: "path", d: "M6.5 10h10M14.5 8l2 2-2 2M17.5 14h-10M9.5 12l-2 2 2 2" },
  ],
  ap: [
    { tag: "path", d: "M4.5 10a10.5 10.5 0 0 1 15 0M7.8 13.3a6 6 0 0 1 8.4 0" },
    { tag: "circle", cx: 12, cy: 17, r: 1.6, filled: true },
  ],
  device: [
    { tag: "rect", x: 3.5, y: 4.5, width: 17, height: 11.5, rx: 1.5 },
    { tag: "path", d: "M9 20h6M12 16v4" },
  ],
  external: [
    { tag: "path", d: "M7 18.5h10.2a4.2 4.2 0 0 0 .5-8.4 6 6 0 0 0-11.5 1.6A3.5 3.5 0 0 0 7 18.5z" },
  ],
};

const ATTR_KEYS = ["cx", "cy", "r", "x", "y", "width", "height", "rx", "d"];

function shapeAttrs(shape, color) {
  const attrs = {};
  for (const key of ATTR_KEYS) if (shape[key] !== undefined) attrs[key] = shape[key];
  return shape.filled ? { ...attrs, fill: color, stroke: "none" } : attrs;
}

/* A data: URL for Cytoscape's background-image. Colours come from our own CSS tokens. */
export function iconUrl(role, color) {
  const shapes = GLYPHS[role] ?? GLYPHS.device;
  const safeColor = /^[#a-z0-9(),.%\s-]+$/i.test(color) ? color : "#ffffff";
  const body = shapes
    .map((shape) => {
      const attrs = Object.entries(shapeAttrs(shape, safeColor))
        .map(([k, v]) => `${k}="${v}"`)
        .join(" ");
      return `<${shape.tag} ${attrs}/>`;
    })
    .join("");
  const svg =
    // width/height make the browser rasterise the icon large, so it stays sharp when
    // Cytoscape scales it into the node at any zoom or screen scaling.
    `<svg xmlns="http://www.w3.org/2000/svg" width="192" height="192" viewBox="0 0 24 24" fill="none" stroke="${safeColor}" ` +
    `stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${body}</svg>`;
  return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
}

/* The same icon as React elements, for the legend and the details panel. */
export function RoleIcon({ role, size = 18 }) {
  const shapes = GLYPHS[role] ?? GLYPHS.device;
  return (
    <svg
      className={`role-icon role-icon-${role}`}
      viewBox="0 0 24 24"
      width={size}
      height={size}
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {shapes.map((shape, i) => {
        const Tag = shape.tag;
        return <Tag key={i} {...shapeAttrs(shape, "currentColor")} />;
      })}
    </svg>
  );
}
