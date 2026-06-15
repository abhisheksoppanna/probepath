"""``is_unknown`` — the conservative linchpin (DESIGN.md §3.3).

Terraform's ``after_unknown`` mirrors the shape of ``after``, with ``true`` at any leaf that
is "known after apply"; known leaves are *omitted* (not ``false``). Asking about a whole
list when only one element is unknown must report UNKNOWN (conservative) — hence the
descendant recursion.

This is the single most important extractor function: if it ever returns "known" for a value
that is actually computed, the engine could prove closure on an open path — a false negative.
"""

from __future__ import annotations

from typing import Any

PathKey = str | int
Path = tuple[PathKey, ...]


def _contains_unknown(node: Any) -> bool:
    if node is True:
        return True
    if isinstance(node, dict):
        return any(_contains_unknown(v) for v in node.values())
    if isinstance(node, list):
        return any(_contains_unknown(v) for v in node)
    return False


def is_unknown(after_unknown: Any, path: Path = ()) -> bool:
    """Return True if the value at ``path`` is computed/known-after-apply, OR any descendant is.

    ``path`` example: ``("vpc_security_group_ids",)`` or ``("ingress", 1, "cidr_blocks")``.
    """
    node = after_unknown
    for key in path:
        if node is True:  # an ancestor is entirely unknown
            return True
        if isinstance(node, dict):
            if key not in node:  # omitted == known
                return False
            node = node[key]
        elif isinstance(node, list):
            if not isinstance(key, int) or key >= len(node):
                return False
            node = node[key]
        else:
            return False
    return node is True or _contains_unknown(node)
