"""Canonical, versioned JSON output. The stable machine contract and baseline-diff artifact."""

from __future__ import annotations

import json
from typing import Any

from ..findings.finding import Finding, ScanResult

SCHEMA = "probepath/v1"


def finding_to_dict(f: Finding) -> dict[str, Any]:
    return {
        "rule_id": f.rule_id,
        "sink": f.sink_address,
        "sink_label": f.sink_label,
        "verdict": f.verdict.value,
        "reachability_class": f.reachability_class.value,
        "fingerprint": f.fingerprint,
        "location": f.sink_location.render(),
        "conservative": f.conservative_classes,
        "path": [
            {
                "index": h.index,
                "from": h.from_label,
                "to": h.to_label,
                "edge": h.edge_kind.value,
                "why": h.why,
                "confidence": h.confidence.value,
                "location": h.location.render(),
            }
            for h in f.path
        ],
        "blocked_reason": f.blocked_reason,
    }


def to_dict(result: ScanResult) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "summary": {
            "reachable": len(result.reachable),
            "potentially_reachable": len(result.potential),
            "suppressed": len(result.suppressed),
        },
        "findings": [finding_to_dict(f) for f in result.findings],
    }


def render(result: ScanResult) -> str:
    return json.dumps(to_dict(result), indent=2, sort_keys=False)
