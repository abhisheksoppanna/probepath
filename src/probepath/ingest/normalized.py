"""The canonical intermediate form: ``ResourceRecord``.

Every ingest backend (plan/state/HCL) emits these. The builder reads attributes through
:meth:`ResourceRecord.resolve`, which returns exactly one of three states feeding the
conservative rule (DESIGN.md §3.6): **KNOWN(value)**, **UNKNOWN**, or **ABSENT**. There is
no fourth "default to safe" state — absence of evidence is UNKNOWN, and UNKNOWN always
widens reachability.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..model.nodes import SourceLocation
from .unknown import is_unknown


class ResolveState(Enum):
    KNOWN = "known"
    UNKNOWN = "unknown"  # known-after-apply, HCL-unevaluated, or ref to an unmodeled target
    ABSENT = "absent"  # attribute legitimately unset


@dataclass(frozen=True)
class Resolved:
    state: ResolveState
    value: Any = None

    @property
    def known(self) -> bool:
        return self.state is ResolveState.KNOWN

    @property
    def is_unknown(self) -> bool:
        return self.state is ResolveState.UNKNOWN

    @property
    def absent(self) -> bool:
        return self.state is ResolveState.ABSENT

    def value_or(self, default: Any) -> Any:
        return self.value if self.known else default


@dataclass
class ResourceRecord:
    address: str  # module-qualified + indexed, e.g. module.net.aws_subnet.public[0]
    type: str  # e.g. aws_db_instance
    name: str
    mode: str = "managed"  # managed | data
    index: Any = None
    origin: str = "plan"  # plan | state | hcl
    values: dict[str, Any] = field(default_factory=dict)
    after_unknown: Any = field(default_factory=dict)  # dict | bool, mirrors values' shape
    references: dict[str, list[str]] = field(default_factory=dict)  # attr -> config addresses
    config_address: str = ""  # un-indexed, e.g. aws_subnet.public
    actions: list[str] = field(default_factory=lambda: ["create"])
    location: SourceLocation | None = None

    def loc(self) -> SourceLocation:
        return self.location or SourceLocation(tf_address=self.address)

    def resolve(self, *path: str | int) -> Resolved:
        if is_unknown(self.after_unknown, path):
            return Resolved(ResolveState.UNKNOWN)
        node: Any = self.values
        for key in path:
            if isinstance(node, dict):
                if key not in node:
                    return Resolved(ResolveState.ABSENT)
                node = node[key]
            elif isinstance(node, list):
                if not isinstance(key, int) or key >= len(node):
                    return Resolved(ResolveState.ABSENT)
                node = node[key]
            else:
                return Resolved(ResolveState.ABSENT)
        if node is None:
            # null with no resolvable value: ABSENT unless a reference fills it (caller checks refs)
            return Resolved(ResolveState.ABSENT)
        return Resolved(ResolveState.KNOWN, node)

    def refs(self, attr: str) -> list[str]:
        return self.references.get(attr, [])

    def all_refs(self) -> list[str]:
        out: list[str] = []
        for lst in self.references.values():
            out.extend(lst)
        return out

    @property
    def is_deleted(self) -> bool:
        return self.actions == ["delete"]


class RecordIndex:
    """Lookup helpers over a set of ResourceRecords. Reference resolution is *by config
    address* (un-indexed), which is how topology survives ``known after apply`` ids and how
    ``count``/``for_each`` fan-out is handled (one config address -> many instances)."""

    def __init__(self, records: list[ResourceRecord]) -> None:
        self.records = records
        self.by_address: dict[str, ResourceRecord] = {}
        self.by_config: dict[str, list[ResourceRecord]] = {}
        self.by_type: dict[str, list[ResourceRecord]] = {}
        for r in records:
            if r.is_deleted:
                continue
            self.by_address[r.address] = r
            self.by_config.setdefault(r.config_address, []).append(r)
            self.by_type.setdefault(r.type, []).append(r)

    def of_type(self, *types: str) -> list[ResourceRecord]:
        out: list[ResourceRecord] = []
        for t in types:
            out.extend(self.by_type.get(t, []))
        return out

    def targets(self, record: ResourceRecord, attr: str) -> list[ResourceRecord]:
        """Resolve an attribute's references to concrete records (all expanded instances)."""
        out: list[ResourceRecord] = []
        seen: set[str] = set()
        for ref in record.refs(attr):
            for tgt in self.by_config.get(ref, []):
                if tgt.address not in seen:
                    seen.add(tgt.address)
                    out.append(tgt)
        return out

    def targets_of_type(self, record: ResourceRecord, attr: str, *types: str) -> list[ResourceRecord]:
        return [t for t in self.targets(record, attr) if t.type in types]

    def has_unresolved_ref(self, record: ResourceRecord, attr: str) -> bool:
        """True if a reference on ``attr`` points at something not present in the input
        (remote state / cross-account / unmodeled) — caller must degrade to conservative."""
        for ref in record.refs(attr):
            if ref.startswith(("var.", "local.", "module.")) and ref not in self.by_config:
                return True
            if ref.startswith("aws_") and ref not in self.by_config:
                return True
        return False
