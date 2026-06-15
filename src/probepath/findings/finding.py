"""The :class:`Finding` — one verdict per sink — and the :class:`ScanResult` envelope."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from ..model.edges import HopExplanation
from ..model.enums import ConservativeReason, ReachabilityClass, Verdict
from ..model.nodes import SourceLocation


@dataclass
class Finding:
    rule_id: str  # stable SARIF id, e.g. "probepath/internet-to-rds"
    sink_id: str
    sink_address: str
    sink_label: str
    sink_location: SourceLocation
    verdict: Verdict
    reachability_class: ReachabilityClass
    path: list[HopExplanation] = field(default_factory=list)
    blocked_reason: str | None = None
    conservative_reasons: list[ConservativeReason] = field(default_factory=list)

    @property
    def is_suppressed(self) -> bool:
        return self.verdict is Verdict.UNREACHABLE

    @property
    def conservative_classes(self) -> list[str]:
        seen: list[str] = []
        for r in self.conservative_reasons:
            if r.user_class not in seen:
                seen.append(r.user_class)
        return seen

    @property
    def fingerprint(self) -> str:
        sig = self.sink_address + "|" + "->".join(f"{h.from_label}:{h.to_label}" for h in self.path)
        return hashlib.sha256(sig.encode()).hexdigest()[:16]


@dataclass
class ScanResult:
    findings: list[Finding]

    @property
    def reachable(self) -> list[Finding]:
        return [f for f in self.findings if f.verdict is Verdict.REACHABLE]

    @property
    def potential(self) -> list[Finding]:
        return [f for f in self.findings if f.verdict is Verdict.POTENTIALLY_REACHABLE]

    @property
    def suppressed(self) -> list[Finding]:
        return [f for f in self.findings if f.verdict is Verdict.UNREACHABLE]

    def exit_violation(self, fail_on: str) -> bool:
        if fail_on == "never":
            return False
        if fail_on == "reachable":
            return bool(self.reachable)
        if fail_on == "potential":
            return bool(self.reachable) or bool(self.potential)
        return False
