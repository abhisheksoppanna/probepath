"""Graph node carriers.

A ``Node`` is a thin, typed envelope around a normalized AWS resource instance. Kind-specific
normalized fields live in ``attrs`` (documented per kind in ``aws/resource_types.py``); the
engine reads them through small accessor helpers rather than a deep class hierarchy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .enums import Confidence, NodeKind

INTERNET_ID = "__internet__"


@dataclass(frozen=True)
class SourceLocation:
    """Where a node/edge came from, for ``file:line`` rendering and SARIF locations."""

    tf_address: str
    file: str | None = None
    line: int | None = None

    def render(self) -> str:
        if self.file and self.line:
            return f"{self.file}:{self.line}"
        if self.file:
            return self.file
        return self.tf_address


@dataclass
class Node:
    id: str
    kind: NodeKind
    location: SourceLocation
    confidence: Confidence = Confidence.KNOWN
    label: str = ""
    attrs: dict[str, Any] = field(default_factory=dict)
    is_sink: bool = False
    sink_label: str | None = None  # e.g. "PostgreSQL RDS", "Redis ElastiCache"

    def __post_init__(self) -> None:
        if not self.label:
            self.label = self.location.tf_address or self.id

    def get(self, key: str, default: Any = None) -> Any:
        return self.attrs.get(key, default)
