"""Dependency-free SVG rendering of a simulated attack graph, before and after a control.

The layout is a deterministic layered, top-down drawing: a node's row is its hop distance from
the simulated entry point, and nodes the entry point cannot reach sit in a final row. Pass the
*before* graph as ``layout_from`` when drawing the *after* view so every node keeps its
position and the two figures can be compared by eye. The same inputs always produce the same
bytes, so figures can be hashed.

Meaning is carried by shape, text and line style as well as colour: criticality is printed, the
crown jewel has a star, unreachable assets have a dashed outline and the word "unreachable", the
attack route is thick and the blocked edge is dashed and labelled. The figure therefore remains
readable in greyscale and for colour-blind reviewers.
"""

from __future__ import annotations

from collections import deque
from html import escape
from uuid import UUID

from art_sim.attack.simulated_graph import SimulatedAttackGraph
from art_sim.domain.models import Asset, AssetRelationship, AttackPath

NODE_W, NODE_H = 164, 50
COL_GAP, ROW_GAP = 22, 46
MARGIN = 18
HEADER = 40

STYLE = """
.g{font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;font-size:11px;
 --bg:#ffffff;--fg:#1f2933;--muted:#52606d;--edge:#8896a5;--risk:#c92a2a;--ok:#2b8a3e;
 --low:#f1f3f5;--medium:#fff3bf;--high:#ffd8a8;--critical:#ffc9c9;--line:#616e7c}
@media (prefers-color-scheme:dark){.g{--bg:#12161c;--fg:#e4e7eb;--muted:#b0bac5;--edge:#6b7a8c;
 --risk:#ff8787;--ok:#69db7c;--low:#1f2933;--medium:#4a3f0f;--high:#5a3410;--critical:#5c1a1a;--line:#9aa5b1}}
.g .bg{fill:var(--bg)}.g text{fill:var(--fg)}.g .muted{fill:var(--muted)}
.g .halo{paint-order:stroke;stroke:var(--bg);stroke-width:4px;stroke-linejoin:round}
.g .node{stroke:var(--line);stroke-width:1.2}.g .unreach{stroke-dasharray:4 3;opacity:.62}
.g .reach{stroke-width:2.2}.g .low{fill:var(--low)}.g .medium{fill:var(--medium)}
.g .high{fill:var(--high)}.g .critical{fill:var(--critical)}
.g .edge{stroke:var(--edge);stroke-width:1.2;fill:none}
.g .path{stroke:var(--risk);stroke-width:3}.g .cut{stroke:var(--muted);stroke-dasharray:6 4;stroke-width:2.2}
.g .title{font-size:13px;font-weight:700}.g .safe{fill:var(--ok);font-weight:700}
.g .danger{fill:var(--risk);font-weight:700}
.g .m-edge{fill:var(--edge)}.g .m-path{fill:var(--risk)}.g .m-cut{fill:var(--muted)}
"""


def _depths(graph: SimulatedAttackGraph, source: UUID) -> dict[UUID, int]:
    """Hop distance from ``source`` along modeled relations (BFS, deterministic order)."""
    adjacency: dict[UUID, list[UUID]] = {}
    for edge in graph.relationships:
        adjacency.setdefault(edge.source_asset_id, []).append(edge.target_asset_id)
    depth = {source: 0}
    queue = deque([source])
    while queue:
        node = queue.popleft()
        for target in sorted(adjacency.get(node, ()), key=str):
            if target not in depth:
                depth[target] = depth[node] + 1
                queue.append(target)
    return depth


def _rows(graph: SimulatedAttackGraph, source: UUID) -> list[list[Asset]]:
    depth = _depths(graph, source)
    rows: dict[int, list[Asset]] = {}
    for asset in graph.assets:
        rows.setdefault(depth.get(asset.asset_id, -1), []).append(asset)
    ordered = [sorted(rows[d], key=lambda a: a.name) for d in sorted(k for k in rows if k >= 0)]
    if -1 in rows:
        ordered.append(sorted(rows[-1], key=lambda a: a.name))
    return ordered


def render_graph_svg(
    graph: SimulatedAttackGraph,
    source: UUID,
    *,
    title: str,
    path: AttackPath | None = None,
    removed: AssetRelationship | None = None,
    summary: str = "",
    layout_from: SimulatedAttackGraph | None = None,
) -> str:
    """Render ``graph`` as a standalone SVG string.

    ``path`` is drawn as the highlighted attack route; ``removed`` is drawn as a dashed,
    labelled "blocked" edge (it is absent from ``graph`` in the *after* view). ``layout_from``
    fixes node positions to those of another graph (normally the *before* graph).
    """
    rows = _rows(layout_from or graph, source)
    widest = max(len(row) for row in rows)
    width = MARGIN * 2 + widest * NODE_W + (widest - 1) * COL_GAP
    height = HEADER + len(rows) * NODE_H + (len(rows) - 1) * ROW_GAP + MARGIN
    position: dict[UUID, tuple[float, float]] = {}
    for r, row in enumerate(rows):
        row_width = len(row) * NODE_W + (len(row) - 1) * COL_GAP
        left = (width - row_width) / 2
        for c, asset in enumerate(row):
            position[asset.asset_id] = (left + c * (NODE_W + COL_GAP), HEADER + r * (NODE_H + ROW_GAP))

    reachable = set(_depths(graph, source))
    path_edges = {(s.source_asset_id, s.target_asset_id) for s in (path.steps if path else ())}

    out = [
        (
            f'<svg xmlns="http://www.w3.org/2000/svg" class="g" viewBox="0 0 {width} {height}" '
            f'width="{width}" height="{height}" role="img" aria-label="{escape(title)}">'
        ),
        f"<style>{STYLE}</style>",
        (
            "<defs>"
            + "".join(
                f'<marker id="arrow-{kind}" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" '
                f'markerHeight="7" orient="auto"><path class="m-{kind}" d="M0,0 L8,4 L0,8 z"/></marker>'
                for kind in ("edge", "path", "cut")
            )
            + "</defs>"
        ),
        f'<rect class="bg" width="{width}" height="{height}"/>',
        f'<text class="title" x="{MARGIN}" y="24">{escape(title)}</text>',
    ]
    if summary:
        out.append(f'<text class="muted" x="{width - MARGIN}" y="24" text-anchor="end">{escape(summary)}</text>')

    def edge_line(edge: AssetRelationship, css: str, label: str | None = None) -> None:
        sx, sy = position[edge.source_asset_id]
        tx, ty = position[edge.target_asset_id]
        x1, y1, x2, y2 = sx + NODE_W / 2, sy + NODE_H, tx + NODE_W / 2, ty
        out.append(
            f'<line class="edge {css}" x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
            f'marker-end="url(#arrow-{css or "edge"})"/>'
        )
        text = label or edge.relationship_type.value.replace("_", " ").lower()
        # Anchor the label on the side the edge leans toward, so sibling edges that fan out
        # left and right from one node write away from each other instead of overlapping.
        mid_x, mid_y = (x1 + x2) / 2, (y1 + y2) / 2
        dx = x2 - x1
        anchor, lx = ("start", mid_x + 7) if dx >= -4 else ("end", mid_x - 7)
        weight = ' class="halo danger"' if css == "path" else ' class="halo muted"'
        out.append(f'<text{weight} x="{lx:.1f}" y="{mid_y + 3:.1f}" text-anchor="{anchor}">{escape(text)}</text>')

    for edge in graph.relationships:
        edge_line(edge, "path" if (edge.source_asset_id, edge.target_asset_id) in path_edges else "")
    if removed is not None:
        edge_line(removed, "cut", "✕ blocked by approved control")

    for asset in graph.assets:
        x, y = position[asset.asset_id]
        is_source = asset.asset_id == source
        is_reachable = asset.asset_id in reachable
        classes = f"node {asset.criticality.value}"
        if is_reachable and not is_source:
            classes += " reach"
        if not is_reachable:
            classes += " unreach"
        star = " ★" if asset.is_crown_jewel else ""
        state = "entry point" if is_source else ("reachable" if is_reachable else "unreachable")
        out.append(f'<rect class="{classes}" x="{x:.1f}" y="{y:.1f}" width="{NODE_W}" height="{NODE_H}" rx="8"/>')
        out.append(f'<text x="{x + 9:.1f}" y="{y + 18:.1f}" font-weight="700">{escape(asset.name)}{star}</text>')
        out.append(
            f'<text class="muted" x="{x + 9:.1f}" y="{y + 32:.1f}">'
            f"{escape(asset.asset_type.value.replace('_', ' '))}</text>"
        )
        verdict_class = "danger" if (is_reachable and asset.is_crown_jewel) else (
            "safe" if (asset.is_crown_jewel and not is_reachable) else "muted"
        )
        out.append(
            f'<text class="{verdict_class}" x="{x + 9:.1f}" y="{y + 45:.1f}">'
            f"{asset.criticality.value} · {state}</text>"
        )
    out.append("</svg>")
    return "\n".join(out)
