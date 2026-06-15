"""Terraform state parser (secondary input).

State describes *applied* reality (the past), not the change under review, so it is a
fallback — but it is fully concrete (no ``after_unknown``), so value-based id resolution
works. Supports both ``terraform show -json`` state shape and raw ``.tfstate``.
"""

from __future__ import annotations

from typing import Any

from ..model.nodes import SourceLocation
from .normalized import ResourceRecord


def _walk_values(module: dict[str, Any], acc: list[dict[str, Any]]) -> None:
    for res in module.get("resources", []):
        acc.append(res)
    for child in module.get("child_modules", []):
        _walk_values(child, acc)


def parse_state_json(doc: dict[str, Any], source_file: str | None = None) -> list[ResourceRecord]:
    records: list[ResourceRecord] = []

    if "values" in doc:  # `terraform show -json` of state
        resources: list[dict[str, Any]] = []
        _walk_values(doc["values"].get("root_module", {}), resources)
        for res in resources:
            rtype = res.get("type", "")
            if not rtype.startswith("aws_"):
                continue
            records.append(
                ResourceRecord(
                    address=res["address"],
                    type=rtype,
                    name=res.get("name", ""),
                    mode=res.get("mode", "managed"),
                    index=res.get("index"),
                    origin="state",
                    values=res.get("values", {}),
                    after_unknown={},
                    references={},
                    config_address=res["address"].split("[")[0],
                    location=SourceLocation(tf_address=res["address"], file=source_file),
                )
            )
        return records

    # raw .tfstate
    for res in doc.get("resources", []):
        rtype = res.get("type", "")
        if res.get("mode") == "data" or not rtype.startswith("aws_"):
            continue
        module = res.get("module", "")
        prefix = f"{module}." if module else ""
        for inst in res.get("instances", []):
            idx = inst.get("index_key")
            suffix = f"[{idx!r}]" if isinstance(idx, str) else (f"[{idx}]" if idx is not None else "")
            address = f"{prefix}{rtype}.{res['name']}{suffix}"
            records.append(
                ResourceRecord(
                    address=address,
                    type=rtype,
                    name=res["name"],
                    mode="managed",
                    index=idx,
                    origin="state",
                    values=inst.get("attributes", {}),
                    after_unknown={},
                    references={},
                    config_address=f"{prefix}{rtype}.{res['name']}",
                    location=SourceLocation(tf_address=address, file=source_file),
                )
            )
    return records
