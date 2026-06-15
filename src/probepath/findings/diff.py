"""Base-vs-head NEW-path detection — the GitHub Action gate (DESIGN.md §4.5).

The Action fails a PR only when it *introduces* a new internet->sink path, not for
pre-existing ones. This mirrors deploy-gating best practice: gate on the delta, so the tool
is adoptable on a messy repo without blocking every build on day one.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..model.enums import Verdict
from .finding import Finding, ScanResult


@dataclass
class Diff:
    added: list[Finding] = field(default_factory=list)  # newly reachable / potential
    resolved: list[Finding] = field(default_factory=list)  # were exposed, now suppressed
    unchanged: list[Finding] = field(default_factory=list)

    def gate_violation(self, fail_on: str) -> bool:
        if fail_on == "never":
            return False
        threshold = Verdict.REACHABLE.rank if fail_on == "reachable" else Verdict.POTENTIALLY_REACHABLE.rank
        return any(f.verdict.rank >= threshold for f in self.added)


def diff_results(base: ScanResult, head: ScanResult) -> Diff:
    base_rank = {f.sink_address: f.verdict.rank for f in base.findings}
    out = Diff()
    for f in head.findings:
        before = base_rank.get(f.sink_address, Verdict.UNREACHABLE.rank)
        if f.verdict.rank > before:
            out.added.append(f)
        elif f.verdict.rank < before:
            out.resolved.append(f)
        else:
            out.unchanged.append(f)
    return out


def load_baseline(path_text: str) -> ScanResult:
    """Reconstruct a minimal ScanResult from a probepath JSON report (verdict per sink)."""
    import json

    from ..model.enums import ReachabilityClass
    from ..model.nodes import SourceLocation

    doc = json.loads(path_text)
    findings: list[Finding] = []
    for f in doc.get("findings", []):
        findings.append(
            Finding(
                rule_id=f.get("rule_id", ""),
                sink_id=f["sink"],
                sink_address=f["sink"],
                sink_label=f.get("sink_label", ""),
                sink_location=SourceLocation(f["sink"]),
                verdict=Verdict(f["verdict"]),
                reachability_class=ReachabilityClass(f.get("reachability_class", "network")),
            )
        )
    return ScanResult(findings)
