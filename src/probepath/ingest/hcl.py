"""Raw HCL parser (DEGRADED / maximally-conservative input).

HCL is parsed, not evaluated: ``count``/``for_each``/``dynamic`` are unexpanded and
variables/locals are unresolved. We never pretend HCL gives plan-equivalent fidelity — that
would manufacture false negatives. Almost everything resolves to UNKNOWN, so HCL input
over-reports (POTENTIALLY_REACHABLE), which is the safe direction.

Use ``terraform show -json plan.out`` for real analysis; HCL is a zero-setup convenience.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import hcl2

from ..errors import IngestError
from ..model.nodes import SourceLocation
from .normalized import ResourceRecord

# Match a resource/data reference inside an HCL interpolation, e.g. aws_security_group.db
# from "${aws_security_group.db.id}". Reduced to "<type>.<name>" (or "data.<type>.<name>").
_REF_RE = re.compile(r"\b(data\.[a-z0-9_]+\.[a-z0-9_]+|aws_[a-z0-9_]+\.[a-z0-9_]+)")


def _unquote(s: str) -> str:
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1]
    return s


def _normalize(obj: Any) -> Any:
    """python-hcl2 v8 wraps keys/strings in literal quotes and injects ``__is_block__``
    markers. Strip both so downstream code sees clean values."""
    if isinstance(obj, dict):
        return {_unquote(k): _normalize(v) for k, v in obj.items() if k != "__is_block__"}
    if isinstance(obj, list):
        return [_normalize(v) for v in obj]
    if isinstance(obj, str):
        return _unquote(obj)
    return obj

# Attributes whose HCL value is a string starting with "${" or containing interpolation are
# treated as unknown by marking after_unknown True for them. For simplicity and safety we
# mark the WHOLE resource's gating as unknown-friendly: known scalar literals are kept;
# anything referencing a var/resource is dropped to UNKNOWN.


def _is_interpolated(value: Any) -> bool:
    if isinstance(value, str):
        return "${" in value
    if isinstance(value, list):
        return any(_is_interpolated(v) for v in value)
    if isinstance(value, dict):
        return any(_is_interpolated(v) for v in value.values())
    return False


def _split_unknown(values: Any) -> tuple[Any, Any]:
    """Return (kept_values, after_unknown) where interpolated leaves become unknown markers."""
    if isinstance(values, dict):
        kept: dict[str, Any] = {}
        unknown: dict[str, Any] = {}
        for k, v in values.items():
            kv, uv = _split_unknown(v)
            kept[k] = kv
            if uv is not False and uv != {} and uv != []:
                unknown[k] = uv
        return kept, (unknown or {})
    if isinstance(values, list):
        any_unknown = any(_is_interpolated(v) for v in values)
        return values, (True if any_unknown else [])
    if _is_interpolated(values):
        return values, True
    return values, False


def parse_hcl_dir(path: Path) -> list[ResourceRecord]:
    files = [path] if path.is_file() else sorted(path.glob("*.tf"))
    records: list[ResourceRecord] = []
    for f in files:
        try:
            with f.open("r", encoding="utf-8") as fh:
                doc = _normalize(hcl2.load(fh))
        except Exception as exc:  # python-hcl2 raises a variety of lark errors
            raise IngestError(f"failed to parse HCL {f}: {exc}") from exc
        for block in doc.get("resource", []):
            for rtype, named in block.items():
                if not rtype.startswith("aws_"):
                    continue
                for rname, body in named.items():
                    kept, unknown = _split_unknown(body)
                    address = f"{rtype}.{rname}"
                    records.append(
                        ResourceRecord(
                            address=address,
                            type=rtype,
                            name=rname,
                            mode="managed",
                            origin="hcl",
                            values=kept,
                            after_unknown=unknown,
                            references=_extract_refs(body, address),
                            config_address=address,
                            location=SourceLocation(tf_address=address, file=str(f)),
                        )
                    )
    return records


def _extract_refs(body: Any, self_addr: str) -> dict[str, list[str]]:
    """Pull resource references out of HCL interpolations so topology resolves like plan JSON.

    HCL gives us ``vpc_security_group_ids = [aws_security_group.db.id]`` as a string with
    ``${...}``; we reduce each match to its ``<type>.<name>`` resource address."""
    refs: dict[str, list[str]] = {}
    if not isinstance(body, dict):
        return refs
    for attr, value in body.items():
        found: list[str] = []
        for token in _REF_RE.findall(_flatten(value)):
            if token != self_addr and token not in found:
                found.append(token)
        if found:
            refs[attr] = found
    return refs


def _flatten(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(_flatten(v) for v in value)
    if isinstance(value, dict):
        return " ".join(_flatten(v) for v in value.values())
    return ""
