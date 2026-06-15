"""``ResourceGraph`` — a typed wrapper over ``networkx.MultiDiGraph``.

Two nodes may be joined by multiple distinct rules, hence a multigraph. The graph also
carries the ``BlockedEdge`` ledger (the suppression proofs) and the set of sink node ids.
"""

from __future__ import annotations

from collections.abc import Iterator

import networkx as nx

from .edges import BlockedEdge, Edge
from .nodes import INTERNET_ID, Node


class ResourceGraph:
    def __init__(self) -> None:
        self._g: nx.MultiDiGraph = nx.MultiDiGraph()
        self._nodes: dict[str, Node] = {}
        self._blocked: list[BlockedEdge] = []

    # --- construction -----------------------------------------------------
    def add_node(self, node: Node) -> None:
        self._nodes[node.id] = node
        self._g.add_node(node.id, node=node)

    def add_edge(self, edge: Edge) -> None:
        # Tolerate forward references: ensure endpoints exist as graph nodes.
        for nid in (edge.src, edge.dst):
            if nid not in self._g:
                self._g.add_node(nid)
        self._g.add_edge(edge.src, edge.dst, edge=edge)

    def add_blocked(self, blocked: BlockedEdge) -> None:
        self._blocked.append(blocked)

    # --- access -----------------------------------------------------------
    @property
    def nx(self) -> nx.MultiDiGraph:
        return self._g

    def node(self, node_id: str) -> Node | None:
        return self._nodes.get(node_id)

    def nodes(self) -> Iterator[Node]:
        return iter(self._nodes.values())

    def sinks(self) -> list[Node]:
        return [n for n in self._nodes.values() if n.is_sink]

    def edges_between(self, src: str, dst: str) -> list[Edge]:
        if not self._g.has_edge(src, dst):
            return []
        return [d["edge"] for _, v, d in self._g.out_edges(src, data=True) if v == dst and "edge" in d]

    def out_edges(self, src: str) -> list[Edge]:
        return [data["edge"] for _, _, data in self._g.out_edges(src, data=True) if "edge" in data]

    def in_edges(self, dst: str) -> list[Edge]:
        return [data["edge"] for _, _, data in self._g.in_edges(dst, data=True) if "edge" in data]

    def blocked_into(self, dst: str) -> list[BlockedEdge]:
        return [b for b in self._blocked if b.dst == dst]

    @property
    def blocked(self) -> list[BlockedEdge]:
        return list(self._blocked)

    @property
    def internet_id(self) -> str:
        return INTERNET_ID

    def has_internet(self) -> bool:
        return INTERNET_ID in self._g
