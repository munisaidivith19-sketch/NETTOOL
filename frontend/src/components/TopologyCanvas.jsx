import cytoscape from "cytoscape";
import { useCallback, useEffect, useRef, useState } from "react";
import { iconUrl } from "./topologyIcons.jsx";

/*
 * The interactive network map, drawn by Cytoscape.js on a <canvas>.
 *
 * Device names come from the devices themselves (untrusted). Cytoscape draws labels as canvas
 * text, never as HTML, so a device called "<img onerror=...>" is just shown as those
 * characters. Colours are read from the CSS tokens, so the map follows light/dark theme.
 *
 * How to read it:
 *   - the icon inside a node is the device's role (router, switch, access point, cloud for a
 *     neighbour NetMap doesn't manage);
 *   - the fill is the status, and the caption repeats it in words (DOWN, SNMP ERROR), so
 *     colour is never the only signal;
 *   - the layout is a tree from the outside world inwards: ISP at the top, then router, core,
 *     access switches and access points; devices with no LLDP/CDP neighbour sit in a separate
 *     box at the bottom.
 */

export const ISOLATED_GROUP = "group:isolated";

const X_GAP = 185; // horizontal space per leaf device (node + caption on its right)
const Y_GAP = 165; // vertical space per tier: room for a port tag at each end of a link
const ROLE_RANK = { external: 0, router: 1, switch: 2, ap: 3, device: 3 };
// "Fit" keeps the drawing between these zoom levels. Further out, the canvas text gets too
// small and turns soft, so a big network starts at this zoom (top left) and the user zooms
// out on purpose; a small one isn't blown up to fill the box.
const MIN_FIT_ZOOM = 0.78;
const MAX_FIT_ZOOM = 1.25;
// Canvas text is sharpest in the operating system's own UI font, which is hinted for screens
// and has a plain zero (the page's web fonts slash/dot the zero, which reads as 8 or 9 when small).
const CANVAS_FONT = '"Segoe UI", system-ui, -apple-system, Roboto, "Helvetica Neue", Arial, sans-serif';

function tokens() {
  const css = getComputedStyle(document.documentElement);
  const v = (name, fallback) => css.getPropertyValue(name).trim() || fallback;
  return {
    up: v("--up", "#157a45"),
    down: v("--down", "#c42323"),
    warn: v("--warn", "#8f5b0a"),
    muted: v("--muted", "#555b70"),
    ink: v("--ink", "#171a2b"),
    line: v("--line", "#dde0eb"),
    panel: v("--panel", "#ffffff"),
    sunken: v("--panel-sunken", "#f2f3f9"),
    accent: v("--accent", "#6240d9"),
  };
}

/* Fill, border and icon colour per status. */
function look(t, status) {
  switch (status) {
    case "up":
      return { fill: t.up, border: t.panel, icon: t.panel };
    case "warning":
      return { fill: t.warn, border: t.panel, icon: t.panel };
    case "down":
      return { fill: t.panel, border: t.down, icon: t.down };
    default: // external
      return { fill: t.panel, border: t.muted, icon: t.muted };
  }
}

function stylesheet(t, showPorts) {
  const portLabels = showPorts
    ? {
        "source-label": "data(source_port)",
        "target-label": "data(target_port)",
        "source-text-offset": 38,
        "target-text-offset": 38,
        "font-family": CANVAS_FONT,
        "font-size": 12,
        "font-weight": 500,
        color: t.ink,
        "text-background-color": t.panel,
        "text-background-opacity": 1,
        "text-background-padding": 3,
        "text-background-shape": "roundrectangle",
        "text-border-width": 1,
        "text-border-color": t.line,
        "text-border-opacity": 1,
      }
    : {};
  return [
    {
      selector: "node",
      style: {
        label: "data(caption)",
        color: t.ink,
        "font-family": CANVAS_FONT,
        "font-size": 14,
        "font-weight": 600,
        "line-height": 1.3,
        // Caption on the right: links leave a node upwards and downwards, never through it.
        "text-valign": "center",
        "text-halign": "right",
        "text-justification": "left",
        "text-margin-x": 10,
        "text-wrap": "wrap",
        "text-max-width": 150,
        "text-background-color": t.panel,
        "text-background-opacity": 1,
        "text-background-padding": 3,
        "text-background-shape": "roundrectangle",
        width: 52,
        height: 52,
        "border-width": 3,
        "background-color": (ele) => look(t, ele.data("status")).fill,
        "border-color": (ele) => look(t, ele.data("status")).border,
        "overlay-padding": 6,
      },
    },
    {
      selector: 'node[role != "group"]',
      style: {
        "background-image": (ele) => iconUrl(ele.data("role"), look(t, ele.data("status")).icon),
        "background-width": "62%",
        "background-height": "62%",
        "background-clip": "none",
      },
    },
    { selector: 'node[role = "router"], node[role = "ap"]', style: { shape: "ellipse" } },
    {
      selector: 'node[role = "switch"], node[role = "device"], node[role = "external"]',
      style: { shape: "round-rectangle" },
    },
    { selector: 'node[status = "down"]', style: { "border-width": 4, color: t.down } },
    {
      selector: 'node[status = "external"]',
      style: { "border-style": "dashed", "border-width": 2, color: t.muted, "font-weight": 500 },
    },
    {
      selector: 'node[role = "group"]',
      style: {
        shape: "round-rectangle",
        "background-color": t.sunken,
        "background-opacity": 0.7,
        "border-style": "dashed",
        "border-width": 1.5,
        "border-color": t.muted,
        color: t.muted,
        "font-weight": 500,
        "font-size": 12,
        "text-valign": "top",
        "text-halign": "center",
        "text-margin-x": 0,
        "text-margin-y": -6,
        "text-background-opacity": 0,
        padding: 28,
      },
    },
    {
      selector: "edge",
      style: {
        width: 2.5,
        "line-color": t.muted,
        "line-opacity": 0.8,
        "curve-style": "bezier",
        ...portLabels,
      },
    },
    { selector: 'edge[status = "down"]', style: { "line-color": t.down, "line-style": "dashed", width: 3, "line-opacity": 1 } },
    { selector: ".faded", style: { opacity: 0.18 } },
    { selector: "edge.traced", style: { "line-color": t.accent, width: 4, "line-opacity": 1 } },
    { selector: "node:selected", style: { "border-color": t.accent, "border-width": 5 } },
    { selector: "node.highlight", style: { "border-color": t.accent, "border-width": 6 } },
    { selector: "edge.highlight", style: { "line-color": t.accent, width: 6, "line-opacity": 1 } },
  ];
}

const STATUS_WORDS = { down: "DOWN", warning: "SNMP ERROR" };

/* The text under a node: name, address, then the status in words when it isn't "up". */
function caption(node) {
  const lines = [node.label ?? node.id];
  if (node.external) {
    if (node.platform) lines.push(node.platform);
  } else if (node.mgmt_ip) {
    lines.push(node.mgmt_ip);
  }
  const words = [STATUS_WORDS[node.status], node.unconfigured ? "NEEDS SETUP" : null].filter(Boolean);
  if (words.length) lines.push(words.join(" · "));
  return lines.map((line) => String(line).slice(0, 60)).join("\n");
}

export function toElements(graph) {
  const linked = new Set(graph.edges.flatMap((e) => [e.source, e.target]));
  // Devices without a neighbour get their own box, but only when there is a map to set them
  // apart from; a network with no links at all is just a row of devices.
  const grouped = linked.size > 0 && graph.nodes.some((n) => !linked.has(n.id));
  return [
    ...(grouped
      ? [
          {
            group: "nodes",
            selectable: false,
            grabbable: false,
            data: { id: ISOLATED_GROUP, caption: "No LLDP/CDP neighbours", role: "group", status: "group" },
          },
        ]
      : []),
    ...graph.nodes.map((n) => ({
      group: "nodes",
      data: {
        id: n.id,
        label: n.label ?? n.id,
        caption: caption(n),
        status: n.status,
        role: n.role ?? (n.external ? "external" : "device"),
        ...(grouped && !linked.has(n.id) ? { parent: ISOLATED_GROUP } : {}),
      },
    })),
    ...graph.edges.map((e) => ({
      group: "edges",
      data: {
        id: e.id,
        source: e.source,
        target: e.target,
        status: e.status,
        source_port: e.source_port ?? "",
        target_port: e.target_port ?? "",
      },
    })),
  ];
}

const rank = (node) => ROLE_RANK[node.data("role")] ?? 3;
const byRankThenName = (a, b) => rank(a) - rank(b) || String(a.data("label")).localeCompare(String(b.data("label")));

/*
 * A tidy tree: every leaf gets one column, a parent sits centred over its children.
 * Roots are the outside neighbours (the ISP); a part of the network without one starts at
 * its most "central" role (router before switch), busiest first. Extra links that would make
 * a loop (redundant uplinks) are still drawn, just not used for placement.
 */
export function treePositions(cy, { loosePlacement = "right" } = {}) {
  const positions = {};
  const devices = cy.nodes().filter((n) => n.data("role") !== "group");
  const loose = devices.filter((n) => n.data("parent") === ISOLATED_GROUP);
  const main = devices.difference(loose);
  let left = 0;
  let deepest = 0;

  // components() only follows edges that are in the collection, so add the links.
  const components = main
    .union(main.connectedEdges())
    .components()
    .sort((a, b) => b.nodes().length - a.nodes().length);
  for (const component of components) {
    const members = component.nodes();
    let roots = members.filter('[role = "external"]');
    if (roots.empty()) {
      const best = Math.min(...members.map(rank));
      const candidates = members.filter((n) => rank(n) === best).sort((a, b) => b.degree() - a.degree());
      roots = candidates.slice(0, 1);
    }
    const children = new Map();
    const seen = new Set();
    const order = [];
    const queue = [...roots].sort(byRankThenName);
    for (const root of queue) seen.add(root.id());
    while (queue.length) {
      const node = queue.shift();
      order.push(node);
      const kids = node
        .neighborhood("node")
        .filter((n) => !seen.has(n.id()) && members.contains(n))
        .sort(byRankThenName);
      for (const kid of kids) seen.add(kid.id());
      children.set(node.id(), kids);
      queue.push(...kids);
    }
    const width = new Map();
    for (const node of [...order].reverse()) {
      const kids = children.get(node.id()) ?? [];
      width.set(node.id(), kids.length ? kids.reduce((sum, k) => sum + width.get(k.id()), 0) : 1);
    }
    const place = (node, start, depth) => {
      const w = width.get(node.id());
      positions[node.id()] = { x: (start + w / 2) * X_GAP, y: depth * Y_GAP };
      deepest = Math.max(deepest, depth);
      let cursor = start;
      for (const kid of children.get(node.id()) ?? []) {
        place(kid, cursor, depth + 1);
        cursor += width.get(kid.id());
      }
    };
    let cursor = left;
    for (const root of [...roots].sort(byRankThenName)) {
      place(root, cursor, 0);
      cursor += width.get(root.id());
    }
    left = cursor + 0.5; // a little air between separate parts of the network
  }

  // Devices without neighbours: a small grid either to the right of the map, level with its
  // lowest tier, or in a row below it. runLayout tries both and keeps the one that fits the
  // box at the larger zoom.
  const looseList = [...loose].sort(byRankThenName);
  let columns;
  let looseLeft;
  let looseTop;
  if (loosePlacement === "below" || main.empty()) {
    columns = Math.max(1, Math.max(Math.round(left), 1) + 1);
    const rowWidth = (Math.min(columns, looseList.length) - 1) * X_GAP;
    looseLeft = Math.max(0, ((left - 0.5) * X_GAP) / 2 - rowWidth / 2);
    looseTop = main.empty() ? 0 : (deepest + 1) * Y_GAP + 20;
  } else {
    columns = Math.max(1, Math.ceil(Math.sqrt(looseList.length)));
    const rows = Math.ceil(looseList.length / columns);
    looseLeft = left * X_GAP + X_GAP * 0.4;
    looseTop = Math.max(0, deepest * Y_GAP - (rows - 1) * Y_GAP);
  }
  looseList.forEach((node, i) => {
    positions[node.id()] = {
      x: looseLeft + (i % columns) * X_GAP,
      y: looseTop + Math.floor(i / columns) * Y_GAP,
    };
  });
  return positions;
}

function fitView(cy) {
  cy.fit(undefined, 40);
  if (cy.zoom() > MAX_FIT_ZOOM) {
    cy.zoom(MAX_FIT_ZOOM);
    cy.center();
  } else if (cy.zoom() < MIN_FIT_ZOOM) {
    // Too big to fit at 100%: show it at 100% from the top-left corner, where the tree starts.
    const box = cy.elements().boundingBox();
    cy.zoom(MIN_FIT_ZOOM);
    cy.pan({ x: 40 - box.x1 * MIN_FIT_ZOOM, y: 40 - box.y1 * MIN_FIT_ZOOM });
  }
}

/* The zoom at which a set of positions would fit the box (captions sit to the right). */
function fitZoomFor(positions, width, height) {
  const points = Object.values(positions);
  if (!points.length || !width || !height) return 1;
  const xs = points.map((p) => p.x);
  const ys = points.map((p) => p.y);
  const w = Math.max(...xs) - Math.min(...xs) + 60 + 170; // node + caption
  const h = Math.max(...ys) - Math.min(...ys) + 120; // node + group label + padding
  return Math.min((width - 80) / w, (height - 80) / h);
}

function runLayout(cy) {
  let positions = treePositions(cy);
  const hasLoose = cy.getElementById(ISOLATED_GROUP).nonempty();
  if (hasLoose) {
    const below = treePositions(cy, { loosePlacement: "below" });
    const w = cy.width();
    const h = cy.height();
    if (fitZoomFor(below, w, h) > fitZoomFor(positions, w, h)) positions = below;
  }
  cy.layout({ name: "preset", positions: (node) => positions[node.id()], fit: false, animate: false }).run();
  fitView(cy);
}

export default function TopologyCanvas({ graph, selectedId, highlight, onSelect, label }) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const onSelectRef = useRef(onSelect);
  onSelectRef.current = onSelect;
  const [showPorts, setShowPorts] = useState(true);
  const showPortsRef = useRef(showPorts);
  showPortsRef.current = showPorts;

  useEffect(() => {
    const cy = cytoscape({
      container: containerRef.current,
      style: stylesheet(tokens(), showPortsRef.current),
      minZoom: 0.2,
      maxZoom: 3,
      wheelSensitivity: 0.3,
      boxSelectionEnabled: false,
      selectionType: "single",
    });
    cy.on("tap", "node", (event) => {
      const isGroup = event.target.data("role") === "group";
      onSelectRef.current?.(isGroup ? null : event.target.id());
    });
    cy.on("tap", (event) => {
      if (event.target === cy) onSelectRef.current?.(null);
    });
    // Hovering a device traces its links and fades everything else.
    cy.on("mouseover", "node", (event) => {
      const node = event.target;
      if (node.data("role") === "group") return;
      const keep = node.closedNeighborhood();
      cy.elements().not(keep).not('[role = "group"]').addClass("faded");
      node.connectedEdges().addClass("traced");
      if (containerRef.current) containerRef.current.style.cursor = "pointer";
    });
    cy.on("mouseout", "node", () => {
      cy.elements().removeClass("faded traced");
      if (containerRef.current) containerRef.current.style.cursor = "";
    });
    cyRef.current = cy;

    const restyle = () => cy.style(stylesheet(tokens(), showPortsRef.current));
    const media = window.matchMedia?.("(prefers-color-scheme: dark)");
    media?.addEventListener?.("change", restyle);
    const observer = new MutationObserver(restyle);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    // Cytoscape only notices window resizes. If the box changes size for another reason
    // (sidebar, scrollbar, panel next to it), the browser would stretch the old drawing and
    // blur it; tell Cytoscape to redraw at the new size instead.
    const sizeWatcher = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(() => cy.resize());
    sizeWatcher?.observe(containerRef.current);
    return () => {
      sizeWatcher?.disconnect();
      media?.removeEventListener?.("change", restyle);
      observer.disconnect();
      cy.destroy();
      cyRef.current = null;
    };
  }, []);

  useEffect(() => {
    cyRef.current?.style(stylesheet(tokens(), showPorts));
  }, [showPorts]);

  // New data every 30 s: update in place, and only lay out again when devices or links
  // were added, removed or moved in/out of the "no neighbours" box, so the map doesn't jump
  // around under the user's mouse.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !graph) return;
    const wanted = toElements(graph);
    const ids = new Set(wanted.map((el) => el.data.id));
    const before = new Set(cy.elements().map((el) => el.id()));
    let changed = ids.size !== before.size || [...ids].some((id) => !before.has(id));
    cy.batch(() => {
      // Add first (the group before its members), then move members, and remove last:
      // removing a group would also remove whatever is still inside it.
      for (const el of wanted) {
        const existing = cy.getElementById(el.data.id);
        if (existing.empty()) {
          cy.add(el);
          continue;
        }
        const { parent = null, ...data } = el.data;
        if (el.group === "nodes" && (existing.data("parent") ?? null) !== parent) {
          existing.move({ parent });
          changed = true;
        }
        existing.data(data);
      }
      cy.elements()
        .filter((el) => !ids.has(el.id()))
        .remove();
    });
    if (changed) runLayout(cy);
  }, [graph]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements().unselect();
    if (selectedId) cy.getElementById(selectedId).select();
  }, [selectedId, graph]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements().removeClass("highlight");
    if (!highlight?.nodeId) return;
    const node = cy.getElementById(highlight.nodeId);
    if (node.empty()) return;
    node.addClass("highlight");
    if (highlight.port) {
      node
        .connectedEdges()
        .filter((e) => (e.source().id() === node.id() ? e.data("source_port") : e.data("target_port")) === highlight.port)
        .addClass("highlight");
    }
    cy.animate({ center: { eles: node }, zoom: Math.max(cy.zoom(), 1) }, { duration: 300 });
  }, [highlight, graph]);

  const zoomBy = useCallback((factor) => {
    const cy = cyRef.current;
    if (!cy) return;
    const box = containerRef.current.getBoundingClientRect();
    cy.zoom({ level: cy.zoom() * factor, renderedPosition: { x: box.width / 2, y: box.height / 2 } });
  }, []);

  return (
    <div className="topology-stage">
      <div ref={containerRef} className="topology-canvas" role="img" aria-label={label} />
      <div className="topology-controls" role="toolbar" aria-label="Map controls">
        <button type="button" onClick={() => zoomBy(1.25)} aria-label="Zoom in" title="Zoom in">
          +
        </button>
        <button type="button" onClick={() => zoomBy(0.8)} aria-label="Zoom out" title="Zoom out">
          −
        </button>
        <button type="button" onClick={() => cyRef.current && fitView(cyRef.current)} title="Show the whole network">
          Fit
        </button>
        <button
          type="button"
          aria-pressed={showPorts}
          onClick={() => setShowPorts((v) => !v)}
          title="Show or hide the port name at each end of a link"
        >
          Port names
        </button>
      </div>
    </div>
  );
}
