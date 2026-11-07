import cytoscape from "cytoscape";
import { useEffect, useRef } from "react";

/*
 * The interactive network map, drawn by Cytoscape.js on a <canvas>.
 *
 * Device names come from the devices themselves (untrusted). Cytoscape draws labels as canvas
 * text, never as HTML, so a device called "<img onerror=...>" is just shown as those
 * characters. Colours are read from the CSS tokens, so the map follows light/dark theme.
 * Shapes repeat the status (not colour alone), like StatusMark:
 *   up = filled circle, down = hollow square, warning = triangle, external = dashed box.
 */

function tokens() {
  const css = getComputedStyle(document.documentElement);
  const v = (name, fallback) => css.getPropertyValue(name).trim() || fallback;
  return {
    up: v("--up", "#1b7f47"),
    down: v("--down", "#c02626"),
    warn: v("--warn", "#93600f"),
    muted: v("--muted", "#5a6672"),
    ink: v("--ink", "#1a232d"),
    panel: v("--panel", "#ffffff"),
    accent: v("--accent", "#1d5db8"),
    font: v("--font-ui", "system-ui, sans-serif"),
  };
}

function stylesheet(t) {
  return [
    {
      selector: "node",
      style: {
        label: "data(label)",
        color: t.ink,
        "font-family": t.font,
        "font-size": 12,
        "text-valign": "bottom",
        "text-margin-y": 6,
        "text-wrap": "ellipsis",
        "text-max-width": 140,
        "text-background-color": t.panel,
        "text-background-opacity": 0.85,
        "text-background-padding": 2,
        width: 30,
        height: 30,
        "border-width": 3,
        "border-color": t.panel,
      },
    },
    { selector: 'node[status = "up"]', style: { shape: "ellipse", "background-color": t.up } },
    {
      selector: 'node[status = "down"]',
      style: { shape: "rectangle", "background-color": t.panel, "border-color": t.down, "border-width": 5 },
    },
    { selector: 'node[status = "warning"]', style: { shape: "triangle", "background-color": t.warn } },
    {
      selector: 'node[status = "external"]',
      style: {
        shape: "round-rectangle",
        "background-color": t.panel,
        "border-color": t.muted,
        "border-style": "dashed",
        "border-width": 2,
        color: t.muted,
      },
    },
    {
      selector: "edge",
      style: {
        width: 3,
        "line-color": t.muted,
        "curve-style": "bezier",
        "source-label": "data(source_port)",
        "target-label": "data(target_port)",
        "source-text-offset": 44,
        "target-text-offset": 44,
        "font-family": t.font,
        "font-size": 10,
        color: t.muted,
        "text-background-color": t.panel,
        "text-background-opacity": 1,
        "text-background-padding": 1,
      },
    },
    { selector: 'edge[status = "down"]', style: { "line-color": t.down, "line-style": "dashed" } },
    { selector: "node:selected", style: { "border-color": t.accent, "border-width": 5 } },
    { selector: "node.highlight", style: { "border-color": t.accent, "border-width": 6 } },
    { selector: "edge.highlight", style: { "line-color": t.accent, width: 6 } },
  ];
}

export function toElements(graph) {
  return [
    ...graph.nodes.map((n) => ({ group: "nodes", data: { id: n.id, label: n.label ?? n.id, status: n.status } })),
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

function runLayout(cy) {
  // Breadth-first from the outside world inwards: ISP at the top, then router, core, access.
  const external = cy.nodes('[status = "external"]');
  const busiest = cy.nodes().max((n) => n.degree()).ele;
  const roots = external.nonempty() ? external : busiest ? cy.collection([busiest]) : undefined;
  cy.layout({ name: "breadthfirst", directed: false, roots, spacingFactor: 1.6, padding: 30, animate: false }).run();
}

export default function TopologyCanvas({ graph, selectedId, highlight, onSelect, label }) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const onSelectRef = useRef(onSelect);
  onSelectRef.current = onSelect;

  useEffect(() => {
    const cy = cytoscape({
      container: containerRef.current,
      style: stylesheet(tokens()),
      minZoom: 0.2,
      maxZoom: 3,
      boxSelectionEnabled: false,
      selectionType: "single",
    });
    cy.on("tap", "node", (event) => onSelectRef.current?.(event.target.id()));
    cy.on("tap", (event) => {
      if (event.target === cy) onSelectRef.current?.(null);
    });
    cyRef.current = cy;

    const restyle = () => cy.style(stylesheet(tokens()));
    const media = window.matchMedia?.("(prefers-color-scheme: dark)");
    media?.addEventListener?.("change", restyle);
    const observer = new MutationObserver(restyle);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    return () => {
      media?.removeEventListener?.("change", restyle);
      observer.disconnect();
      cy.destroy();
      cyRef.current = null;
    };
  }, []);

  // New data every 30 s: update in place, and only lay out again when devices or links
  // were added or removed, so the map doesn't jump around under the user's mouse.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !graph) return;
    const wanted = toElements(graph);
    const ids = new Set(wanted.map((el) => el.data.id));
    const before = new Set(cy.elements().map((el) => el.id()));
    const changed = ids.size !== before.size || [...ids].some((id) => !before.has(id));
    cy.batch(() => {
      cy.elements()
        .filter((el) => !ids.has(el.id()))
        .remove();
      for (const el of wanted) {
        const existing = cy.getElementById(el.data.id);
        if (existing.nonempty()) existing.data(el.data);
        else cy.add(el);
      }
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

  return <div ref={containerRef} className="topology-canvas" role="img" aria-label={label} />;
}
