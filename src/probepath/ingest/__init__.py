"""Terraform ingestion: plan JSON / tfstate / HCL -> normalized ResourceRecords.

No graph logic lives here. The output is a list of :class:`ResourceRecord`, the canonical
intermediate form the engine builds on.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..errors import IngestError, UnsupportedFormatError
from .normalized import ResourceRecord
from .plan import parse_plan_json
from .state import parse_state_json

__all__ = ["ResourceRecord", "detect_format", "ingest", "ingest_paths"]


def detect_format(path: Path) -> str:
    """Return one of ``plan`` | ``state`` | ``hcl`` for a path, by extension then content."""
    name = path.name.lower()
    if name.endswith(".tf"):
        return "hcl"
    if name.endswith(".tfstate"):
        return "state"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:  # pragma: no cover - filesystem edge
        raise IngestError(f"cannot read {path}: {exc}") from exc
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise UnsupportedFormatError(
            f"{path} is not valid JSON and not a .tf file ({exc})"
        ) from exc
    if "planned_values" in doc or "resource_changes" in doc:
        return "plan"
    if "values" in doc and "format_version" not in doc:
        return "state"
    if doc.get("terraform_version") and "resources" in doc:
        return "state"
    if "planned_values" in doc:
        return "plan"
    raise UnsupportedFormatError(
        f"{path}: JSON is neither a Terraform plan (`terraform show -json plan.out`) "
        "nor a state file. Generate plan JSON for best fidelity."
    )


def ingest(path: Path) -> list[ResourceRecord]:
    """Ingest a single input file into ResourceRecords."""
    fmt = detect_format(path)
    if fmt == "plan":
        return parse_plan_json(json.loads(path.read_text(encoding="utf-8")), source_file=str(path))
    if fmt == "state":
        return parse_state_json(json.loads(path.read_text(encoding="utf-8")), source_file=str(path))
    # hcl
    from .hcl import parse_hcl_dir

    return parse_hcl_dir(path)


def ingest_paths(paths: list[Path]) -> list[ResourceRecord]:
    """Ingest one or more inputs. A directory is scanned for plan JSON / state / .tf.

    Multiple inputs merge as a UNION of records (most permissive); resolved sources
    (plan/state) outrank HCL. We never intersect — that would manufacture false negatives.
    """
    records: list[ResourceRecord] = []
    for p in paths:
        if p.is_dir():
            records.extend(_ingest_dir(p))
        else:
            records.extend(ingest(p))
    if not records:
        raise IngestError(
            "no Terraform resources found in the given inputs "
            "(expected plan JSON, .tfstate, or .tf files)"
        )
    return _dedupe(records)


def _ingest_dir(d: Path) -> list[ResourceRecord]:
    # Prefer the highest-fidelity source present in the directory.
    plan_candidates = sorted(d.glob("*.tfplan.json")) + sorted(d.glob("plan.json"))
    for cand in plan_candidates:
        try:
            return ingest(cand)
        except UnsupportedFormatError:
            continue
    states = sorted(d.glob("*.tfstate"))
    if states:
        return ingest(states[0])
    from .hcl import parse_hcl_dir

    tf_files = sorted(d.glob("*.tf"))
    if tf_files:
        return parse_hcl_dir(d)
    return []


def _dedupe(records: list[ResourceRecord]) -> list[ResourceRecord]:
    """Keep the highest-confidence record per address (plan/state outrank HCL)."""
    rank = {"plan": 0, "state": 1, "hcl": 2}
    best: dict[str, ResourceRecord] = {}
    for r in records:
        cur = best.get(r.address)
        if cur is None or rank.get(r.origin, 9) < rank.get(cur.origin, 9):
            best[r.address] = r
    return list(best.values())
