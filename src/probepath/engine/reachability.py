"""ReachabilityEngine — turn the graph into per-sink verdicts (DESIGN.md §2.10).

The verdict falls directly out of path existence + edge confidence, because the conservative
bias already lives in edge *creation*:

* a fully-known path exists                -> REACHABLE
* a path exists but every such path has    -> POTENTIALLY_REACHABLE
  at least one unknown-confidence hop
* no path exists at all (proven closure)   -> UNREACHABLE  (the only suppressing verdict)
"""

from __future__ import annotations

import networkx as nx

from ..findings.finding import Finding, ScanResult
from ..model.edges import Edge, HopExplanation
from ..model.enums import Confidence, ConservativeReason, NodeKind, ReachabilityClass, Verdict
from ..model.graph import ResourceGraph
from ..model.nodes import INTERNET_ID

_RULE_ID = {
    NodeKind.RDS: "probepath/internet-to-rds",
    NodeKind.ELASTICACHE: "probepath/internet-to-elasticache",
    NodeKind.REDSHIFT: "probepath/internet-to-redshift",
    NodeKind.OPENSEARCH: "probepath/internet-to-opensearch",
    NodeKind.S3_BUCKET: "probepath/internet-to-s3",
}
_KNOWN = (Confidence.KNOWN, Confidence.DEFAULT)


class ReachabilityEngine:
    def __init__(self, graph: ResourceGraph) -> None:
        self.graph = graph
        self.g: nx.MultiDiGraph = graph.nx
        self.known_view = nx.subgraph_view(self.g, filter_edge=self._edge_known)

    def _edge_known(self, u: str, v: str, k: int) -> bool:
        edge = self.g[u][v][k].get("edge")
        return edge is not None and edge.confidence in _KNOWN

    def analyze(self) -> ScanResult:
        findings = [self._analyze_sink(sink.id) for sink in self.graph.sinks()]
        findings.sort(key=lambda f: (f.verdict.rank, f.sink_address), reverse=False)
        findings.reverse()  # reachable first, then potential, then suppressed
        return ScanResult(findings)

    def _analyze_sink(self, sink_id: str) -> Finding:
        sink = self.graph.node(sink_id)
        assert sink is not None
        klass = (
            ReachabilityClass.IDENTITY if sink.kind is NodeKind.S3_BUCKET else ReachabilityClass.NETWORK
        )
        rule_id = _RULE_ID.get(sink.kind, "probepath/internet-to-sink")
        has_internet = self.graph.has_internet() and sink_id in self.g

        if has_internet and nx.has_path(self.known_view, INTERNET_ID, sink_id):
            path = nx.shortest_path(self.known_view, INTERNET_ID, sink_id)
            hops = self._explain(path, known_only=True)
            return Finding(rule_id, sink_id, sink.get("config_address", sink.label), sink.sink_label or sink.label,
                           sink.location, Verdict.REACHABLE, klass, hops)

        if has_internet and nx.has_path(self.g, INTERNET_ID, sink_id):
            path = nx.shortest_path(self.g, INTERNET_ID, sink_id)
            hops = self._explain(path, known_only=False)
            return Finding(rule_id, sink_id, sink.get("config_address", sink.label), sink.sink_label or sink.label,
                           sink.location, Verdict.POTENTIALLY_REACHABLE, klass, hops,
                           conservative_reasons=self._collect_reasons(path))

        # No path: proven closure -> UNREACHABLE (the suppression).
        blocked = self.graph.blocked_into(sink_id)
        reason = blocked[0].why if blocked else "no internet-reachable network path to this sink"
        return Finding(rule_id, sink_id, sink.get("config_address", sink.label), sink.sink_label or sink.label,
                       sink.location, Verdict.UNREACHABLE, klass, blocked_reason=reason)

    def _pick_edge(self, u: str, v: str, known_only: bool) -> Edge:
        edges = self.graph.edges_between(u, v)
        if known_only:
            known = [e for e in edges if e.confidence in _KNOWN]
            if known:
                return known[0]
        # lowest confidence-rank (most "known") first for a stable, informative trace
        return min(edges, key=lambda e: 0 if e.confidence in _KNOWN else 1)

    def _explain(self, path: list[str], known_only: bool) -> list[HopExplanation]:
        hops: list[HopExplanation] = []
        for i in range(len(path) - 1):
            u, v = path[i], path[i + 1]
            edge = self._pick_edge(u, v, known_only)
            un, vn = self.graph.node(u), self.graph.node(v)
            hops.append(HopExplanation(
                index=i,
                from_label=un.label if un else u,
                to_label=vn.label if vn else v,
                edge_kind=edge.kind,
                why=edge.rationale,
                location=edge.location,
                confidence=edge.confidence,
            ))
        return hops

    def _collect_reasons(self, path: list[str]) -> list[ConservativeReason]:
        reasons: list[ConservativeReason] = []
        for i in range(len(path) - 1):
            edge = self._pick_edge(path[i], path[i + 1], known_only=False)
            if edge.reason is not None and edge.reason not in reasons:
                reasons.append(edge.reason)
        return reasons


def analyze(graph: ResourceGraph) -> ScanResult:
    return ReachabilityEngine(graph).analyze()
