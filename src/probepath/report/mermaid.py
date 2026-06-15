"""Mermaid / Graphviz renderers for paths and the full graph (README-embeddable visuals)."""

from __future__ import annotations

from ..findings.finding import Finding
from ..model.enums import NodeKind, Verdict
from ..model.graph import ResourceGraph

_VERDICT_CLASS = {
    Verdict.REACHABLE: "reachable",
    Verdict.POTENTIALLY_REACHABLE: "potential",
    Verdict.UNREACHABLE: "safe",
}


def _safe_id(text: str) -> str:
    return "n_" + "".join(c if c.isalnum() else "_" for c in text)


def render_finding(f: Finding) -> str:
    lines = ["flowchart LR"]
    lines.append('  internet([" internet"]):::internet')
    prev = "internet"
    nodes = [(h.to_label, h.why) for h in f.path]
    if not nodes:
        nodes = [(f.sink_address, f.blocked_reason or "")]
    for i, (label, why) in enumerate(nodes):
        nid = _safe_id(label) + f"_{i}"
        is_sink = i == len(nodes) - 1
        shape_l, shape_r = ("[(", ")]") if is_sink else ("[", "]")
        lines.append(f'  {nid}{shape_l}"{label}"{shape_r}')
        edge_label = why.split(";")[0][:48]
        lines.append(f'  {prev} -->|"{edge_label}"| {nid}')
        prev = nid
    klass = _VERDICT_CLASS[f.verdict]
    lines.append(f"  {prev}:::{klass}")
    lines.append("  classDef internet fill:#1f2937,stroke:#60a5fa,color:#fff;")
    lines.append("  classDef reachable fill:#7f1d1d,stroke:#ef4444,color:#fff;")
    lines.append("  classDef potential fill:#78350f,stroke:#f59e0b,color:#fff;")
    lines.append("  classDef safe fill:#14532d,stroke:#22c55e,color:#fff;")
    return "\n".join(lines)


def render_graph(graph: ResourceGraph) -> str:
    lines = ["flowchart LR"]
    for node in graph.nodes():
        nid = _safe_id(node.id)
        if node.kind is NodeKind.INTERNET_SOURCE:
            lines.append(f'  {nid}(["internet"])')
        elif node.is_sink:
            lines.append(f'  {nid}[("{node.label}")]')
        else:
            lines.append(f'  {nid}["{node.label}"]')
    for u, v, d in graph.nx.edges(data=True):
        e = d.get("edge")
        if e is None:
            continue
        label = str(e.constraint.ports)
        lines.append(f'  {_safe_id(u)} -->|"{label}"| {_safe_id(v)}')
    return "\n".join(lines)


def render_dot(graph: ResourceGraph) -> str:
    lines = ["digraph probepath {", "  rankdir=LR;", '  node [shape=box, fontname="monospace"];']
    for node in graph.nodes():
        shape = "ellipse" if node.kind is NodeKind.INTERNET_SOURCE else ("cylinder" if node.is_sink else "box")
        lines.append(f'  "{node.id}" [shape={shape}];')
    for u, v, d in graph.nx.edges(data=True):
        e = d.get("edge")
        if e is None:
            continue
        lines.append(f'  "{u}" -> "{v}" [label="{e.constraint.ports}"];')
    lines.append("}")
    return "\n".join(lines)
