"""Port-interval algebra.

A ``PortSet`` is an immutable, normalized union of inclusive ``[lo, hi]`` intervals over
``0..65535``. The reachability engine threads an *admissible* port set along a candidate
path; the path is viable only while that set stays non-empty (DESIGN.md §4.2).

Implemented in stdlib (no ``portion`` dependency) to keep the runtime supply chain to four
pure-Python packages — an explicit goal for a security tool.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

MIN_PORT = 0
MAX_PORT = 65535


def _normalize(intervals: Iterable[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    """Clamp, drop empties, sort and merge overlapping/adjacent intervals."""
    cleaned: list[tuple[int, int]] = []
    for lo, hi in intervals:
        lo = max(MIN_PORT, min(lo, hi))
        hi = min(MAX_PORT, max(lo, hi))
        if lo <= hi:
            cleaned.append((lo, hi))
    if not cleaned:
        return ()
    cleaned.sort()
    merged: list[tuple[int, int]] = [cleaned[0]]
    for lo, hi in cleaned[1:]:
        last_lo, last_hi = merged[-1]
        if lo <= last_hi + 1:  # overlapping or adjacent -> merge
            merged[-1] = (last_lo, max(last_hi, hi))
        else:
            merged.append((lo, hi))
    return tuple(merged)


class PortSet:
    """Immutable set of TCP/UDP port numbers, stored as sorted disjoint intervals."""

    __slots__ = ("_intervals",)
    _intervals: tuple[tuple[int, int], ...]

    def __init__(self, intervals: Iterable[tuple[int, int]] = ()) -> None:
        object.__setattr__(self, "_intervals", _normalize(intervals))

    # --- constructors -----------------------------------------------------
    @classmethod
    def empty(cls) -> PortSet:
        return cls(())

    @classmethod
    def all(cls) -> PortSet:
        return cls([(MIN_PORT, MAX_PORT)])

    @classmethod
    def single(cls, port: int) -> PortSet:
        return cls([(port, port)])

    @classmethod
    def closed(cls, lo: int, hi: int) -> PortSet:
        return cls([(lo, hi)])

    # --- introspection ----------------------------------------------------
    @property
    def intervals(self) -> tuple[tuple[int, int], ...]:
        return self._intervals

    @property
    def is_empty(self) -> bool:
        return len(self._intervals) == 0

    def __bool__(self) -> bool:
        return not self.is_empty

    def __contains__(self, port: int) -> bool:
        for lo, hi in self._intervals:
            if lo <= port <= hi:
                return True
            if port < lo:
                break
        return False

    # --- algebra ----------------------------------------------------------
    def intersect(self, other: PortSet) -> PortSet:
        out: list[tuple[int, int]] = []
        i = j = 0
        a, b = self._intervals, other._intervals
        while i < len(a) and j < len(b):
            lo = max(a[i][0], b[j][0])
            hi = min(a[i][1], b[j][1])
            if lo <= hi:
                out.append((lo, hi))
            if a[i][1] < b[j][1]:
                i += 1
            else:
                j += 1
        return PortSet(out)

    def union(self, other: PortSet) -> PortSet:
        return PortSet([*self._intervals, *other._intervals])

    def difference(self, other: PortSet) -> PortSet:
        """Ports in self that are not in other."""
        out: list[tuple[int, int]] = []
        for lo, hi in self._intervals:
            cur = lo
            for olo, ohi in other._intervals:
                if ohi < cur or olo > hi:
                    continue
                if olo > cur:
                    out.append((cur, olo - 1))
                cur = max(cur, ohi + 1)
                if cur > hi:
                    break
            if cur <= hi:
                out.append((cur, hi))
        return PortSet(out)

    # --- dunders ----------------------------------------------------------
    def __eq__(self, other: object) -> bool:
        return isinstance(other, PortSet) and self._intervals == other._intervals

    def __hash__(self) -> int:
        return hash(self._intervals)

    def __repr__(self) -> str:
        return f"PortSet({self})"

    def __str__(self) -> str:
        if self.is_empty:
            return "∅"
        if self._intervals == ((MIN_PORT, MAX_PORT),):
            return "0-65535 (all)"
        parts: list[str] = []
        for lo, hi in self._intervals:
            parts.append(str(lo) if lo == hi else f"{lo}-{hi}")
        return ", ".join(parts)


# Constants used throughout the engine.
ALL_PORTS = PortSet.all()
# Widest ephemeral-port superset (Linux/Windows/ELB). Used for the NACL stateless
# return-path check; never narrow this — narrowing is a false-negative vector (DESIGN.md §2.6).
EPHEMERAL = PortSet.closed(1024, 65535)


def ports_from_rule(from_port: int | None, to_port: int | None, protocol: str | None) -> PortSet:
    """Translate an SG/NACL rule's port fields into a PortSet, honoring AWS idioms.

    ``protocol="-1"``/``"all"`` (or ``from=0,to=0,proto=-1``) means *all ports*, not literal
    port 0 (DESIGN.md §2.5). A missing port with an all-protocol rule is also all ports.
    """
    if protocol is not None and str(protocol).lower() in ("-1", "all"):
        return ALL_PORTS
    if from_port is None or to_port is None:
        # Port unspecified on a specific protocol: be conservative, assume all ports.
        return ALL_PORTS
    if from_port == 0 and to_port == 0:
        # The "all traffic" idiom, not literal port 0.
        return ALL_PORTS
    return PortSet.closed(int(from_port), int(to_port))


def merge_ports(sets: Sequence[PortSet]) -> PortSet:
    out = PortSet.empty()
    for s in sets:
        out = out.union(s)
    return out
