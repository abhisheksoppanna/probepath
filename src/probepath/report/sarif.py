"""SARIF 2.1.0 output for GitHub code scanning (DESIGN.md §4.4).

Reachable/potential findings become ``results`` (error/warning); the hop-by-hop path is
encoded as a ``codeFlows`` threadFlow so GitHub renders the attack path. Unreachable findings
are NOT results (suppression = absence) but are recorded under ``run.properties.suppressions``
for audit.
"""

from __future__ import annotations

import json
from typing import Any

from .. import __version__
from ..findings.finding import Finding, ScanResult
from ..model.enums import Verdict

_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_LEVEL = {Verdict.REACHABLE: "error", Verdict.POTENTIALLY_REACHABLE: "warning"}

_RULES = {
    "probepath/internet-to-rds": "Internet-reachable database",
    "probepath/internet-to-elasticache": "Internet-reachable cache",
    "probepath/internet-to-redshift": "Internet-reachable data warehouse",
    "probepath/internet-to-opensearch": "Internet-reachable search domain",
    "probepath/internet-to-s3": "Internet-exposed S3 bucket",
    "probepath/internet-to-sink": "Internet-reachable sensitive resource",
}


def _location(uri: str | None, line: int | None) -> dict[str, Any]:
    phys: dict[str, Any] = {"artifactLocation": {"uri": uri or "terraform"}}
    if line:
        phys["region"] = {"startLine": line}
    return {"physicalLocation": phys}


def _result(f: Finding) -> dict[str, Any]:
    thread_locations = [
        {
            "location": {
                **_location(h.location.file, h.location.line),
                "message": {"text": f"{h.from_label} → {h.to_label}: {h.why}"},
            }
        }
        for h in f.path
    ]
    msg = f"{f.sink_label} {f.sink_address} is {f.verdict.value} from the internet"
    if f.conservative_classes:
        msg += f" (conservative: {', '.join(f.conservative_classes)})"
    return {
        "ruleId": f.rule_id,
        "level": _LEVEL[f.verdict],
        "message": {"text": msg},
        "locations": [_location(f.sink_location.file, f.sink_location.line)],
        "partialFingerprints": {"probepathPathHash": f.fingerprint},
        "codeFlows": [{"threadFlows": [{"locations": thread_locations}]}] if thread_locations else [],
    }


def to_dict(result: ScanResult) -> dict[str, Any]:
    used_rules = sorted({f.rule_id for f in result.findings})
    rules = [
        {
            "id": rid,
            "name": _RULES.get(rid, rid),
            "shortDescription": {"text": _RULES.get(rid, rid)},
            "defaultConfiguration": {"level": "error"},
        }
        for rid in used_rules
    ]
    results = [_result(f) for f in result.findings if f.verdict is not Verdict.UNREACHABLE]
    suppressions = [
        {"sink": f.sink_address, "reason": f.blocked_reason} for f in result.suppressed
    ]
    return {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "probepath",
                        "version": __version__,
                        "informationUri": "https://github.com/abhisheksoppanna/probepath",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {"suppressions": suppressions},
            }
        ],
    }


def render(result: ScanResult) -> str:
    return json.dumps(to_dict(result), indent=2)
