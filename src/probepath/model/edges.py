"""Graph edge carriers and the per-hop explanation type.

An edge ``A --> B`` exists iff a packet can flow from A to B under the modeled AWS semantics
(DESIGN.md §2.2). Crucially, an edge is *omitted only when a gate is definitively closed with
fully-known inputs*; on any doubt the edge is created with a degraded ``confidence`` so the
path stays visible. That is how probepath avoids false negatives.
"""

from __future__ import annotations

from dataclasses import dataclass

from .enums import Confidence, ConservativeReason, Direction, EdgeKind
from .nodes import SourceLocation
from .ports import PortSet


@dataclass(frozen=True)
class EdgeConstraint:
    """The L4 condition this edge admits."""

    ports: PortSet
    direction: Direction = Direction.FORWARD
    # True when the *source side* of this edge is satisfied by the internet (a CIDR rule
    # covering public space). Internet->X edges set this; intra-VPC SG-ref edges do not.
    admits_internet: bool = False


@dataclass
class Edge:
    src: str
    dst: str
    kind: EdgeKind
    constraint: EdgeConstraint
    rationale: str  # the exact allowing rule, rendered hop-by-hop
    location: SourceLocation
    confidence: Confidence = Confidence.KNOWN
    # When confidence is not fully known, why — drives the POTENTIALLY_REACHABLE reason class.
    reason: ConservativeReason | None = None


@dataclass(frozen=True)
class BlockedEdge:
    """A candidate edge that was *definitively closed with fully-known inputs*. These are the
    suppression proofs: they let an UNREACHABLE verdict say exactly which gate shut the path.
    """

    src_label: str
    dst: str
    why: str  # e.g. "subnet private: no 0.0.0.0/0 -> igw route"
    location: SourceLocation


@dataclass(frozen=True)
class HopExplanation:
    index: int
    from_label: str
    to_label: str
    edge_kind: EdgeKind
    why: str
    location: SourceLocation
    confidence: Confidence
