"""Terraform plan-JSON parser (the PRIMARY, highest-fidelity input).

Joins three sub-documents (DESIGN.md §3.2):
  * ``planned_values``   -> resolved post-apply values
  * ``resource_changes`` -> ``after_unknown`` (the known-after-apply marker) + actions
  * ``configuration``    -> symbolic ``references`` (topology that survives unknown ids)
"""

from __future__ import annotations

import re
from typing import Any

from .normalized import ResourceRecord

_INDEX_RE = re.compile(r"\[[^\]]*\]")
_NON_RESOURCE_PREFIXES = (
    "var",
    "local",
    "each",
    "count",
    "module",
    "path",
    "terraform",
    "self",
)


def _unindex(address: str) -> str:
    return _INDEX_RE.sub("", address)


def _walk_planned(module: dict[str, Any], acc: dict[str, dict[str, Any]]) -> None:
    for res in module.get("resources", []):
        acc[res["address"]] = res
    for child in module.get("child_modules", []):
        _walk_planned(child, acc)


def _collect_refs(expr: Any, out: list[str]) -> None:
    """Recursively gather every ``references`` entry under a configuration expression."""
    if isinstance(expr, dict):
        for ref in expr.get("references", []):
            out.append(ref)
        for key, val in expr.items():
            if key in ("references", "constant_value"):
                continue
            _collect_refs(val, out)
    elif isinstance(expr, list):
        for item in expr:
            _collect_refs(item, out)


def _ref_to_resource(ref: str, module_prefix: str) -> str:
    parts = ref.split(".")
    head = parts[0]
    if head == "data" and len(parts) >= 3:
        res = ".".join(parts[:3])
    elif head in _NON_RESOURCE_PREFIXES:
        # Not a same-module resource reference (var/local/module-output/etc.).
        return module_prefix + ref if module_prefix else ref
    else:
        res = ".".join(parts[:2])  # aws_<type>.<name>
    return module_prefix + res if module_prefix else res


def _walk_configuration(
    module: dict[str, Any],
    module_prefix: str,
    refs_by_addr: dict[str, dict[str, list[str]]],
) -> None:
    for res in module.get("resources", []):
        cfg_addr = module_prefix + res["address"]  # un-indexed by construction
        attr_refs: dict[str, list[str]] = {}
        for attr, expr in (res.get("expressions") or {}).items():
            collected: list[str] = []
            _collect_refs(expr, collected)
            resolved = []
            for r in collected:
                rr = _ref_to_resource(r, module_prefix)
                if rr not in resolved:
                    resolved.append(rr)
            if resolved:
                attr_refs[attr] = resolved
        if attr_refs:
            refs_by_addr[cfg_addr] = attr_refs
    for name, call in (module.get("module_calls") or {}).items():
        child_prefix = f"{module_prefix}module.{name}."
        child_mod = call.get("module", {})
        _walk_configuration(child_mod, child_prefix, refs_by_addr)


def parse_plan_json(doc: dict[str, Any], source_file: str | None = None) -> list[ResourceRecord]:
    from ..model.nodes import SourceLocation

    planned: dict[str, dict[str, Any]] = {}
    root = doc.get("planned_values", {}).get("root_module", {})
    _walk_planned(root, planned)

    changes: dict[str, dict[str, Any]] = {}
    for ch in doc.get("resource_changes", []):
        changes[ch["address"]] = ch

    refs_by_addr: dict[str, dict[str, list[str]]] = {}
    cfg_root = doc.get("configuration", {}).get("root_module", {})
    _walk_configuration(cfg_root, "", refs_by_addr)

    records: list[ResourceRecord] = []
    # Union of addresses seen in planned_values and resource_changes (a delete-only change
    # has no planned_values entry; a no-op may differ — we take planned_values as truth).
    addresses = set(planned) | {a for a, ch in changes.items() if ch.get("change", {}).get("actions") != ["delete"]}
    for address in sorted(addresses):
        pv = planned.get(address, {})
        ch = changes.get(address, {})
        change = ch.get("change", {})
        rtype = pv.get("type") or ch.get("type")
        if not rtype or not str(rtype).startswith(("aws_",)):
            continue
        values = pv.get("values")
        if values is None:
            values = change.get("after") or {}
        after_unknown = change.get("after_unknown", {})
        actions = change.get("actions", ["create"])
        cfg_addr = _unindex(address)
        records.append(
            ResourceRecord(
                address=address,
                type=rtype,
                name=pv.get("name") or ch.get("name") or "",
                mode=pv.get("mode") or ch.get("mode") or "managed",
                index=pv.get("index", ch.get("index")),
                origin="plan",
                values=values,
                after_unknown=after_unknown,
                references=refs_by_addr.get(cfg_addr, {}),
                config_address=cfg_addr,
                actions=actions,
                location=SourceLocation(tf_address=address, file=source_file),
            )
        )
    return records
