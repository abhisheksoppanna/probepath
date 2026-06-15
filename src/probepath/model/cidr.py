"""CIDR algebra and untrusted-source detection.

Untrusted-source detection is **CIDR math, not string matching** (DESIGN.md §2.5, trap
``T09``): ``0.0.0.0/1`` + ``128.0.0.0/1`` together cover the whole internet, and
``"0.0.0.0/0 "`` with stray whitespace must normalize. We decide "does this CIDR admit a
packet from public address space?" by subtracting the non-routable blocks and asking
whether anything is left.

Conservative bias: documentation/test ranges (192.0.2/24, 198.51.100/24, 203.0.113/24) are
treated as **public**, because fixture authors and operators routinely use them to mean "a
public IP," and over-reporting is safe while under-reporting is fatal.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Blocks that can never be an internet (public-unicast) source. Everything else is "public."
_NON_PUBLIC_V4 = tuple(
    ipaddress.IPv4Network(c)
    for c in (
        "0.0.0.0/8",  # "this" network
        "10.0.0.0/8",  # RFC1918
        "100.64.0.0/10",  # CGNAT
        "127.0.0.0/8",  # loopback
        "169.254.0.0/16",  # link-local
        "172.16.0.0/12",  # RFC1918
        "192.168.0.0/16",  # RFC1918
        "224.0.0.0/4",  # multicast (not a unicast source)
        "240.0.0.0/4",  # reserved future (incl. 255.255.255.255)
    )
)
_NON_PUBLIC_V6 = tuple(
    ipaddress.IPv6Network(c)
    for c in (
        "::/128",  # unspecified
        "::1/128",  # loopback
        "fc00::/7",  # unique local
        "fe80::/10",  # link-local
        "ff00::/8",  # multicast
    )
)


def parse_cidr(text: str) -> IPNetwork | None:
    """Parse a CIDR string defensively. Returns None if it cannot be parsed (the caller
    must then treat the source as UNKNOWN, never as restrictive)."""
    if not text:
        return None
    try:
        return ipaddress.ip_network(text.strip(), strict=False)
    except ValueError:
        return None


def _remaining_after_exclude(net: IPNetwork, specials: Iterable[IPNetwork]) -> bool:
    """Return True if any address of ``net`` is NOT covered by the special blocks.

    Relies on the CIDR invariant that two aligned networks are either disjoint or one
    contains the other (never a partial overlap)."""
    work: list[IPNetwork] = [net]
    for sp in specials:
        if sp.version != net.version:
            continue
        nxt: list[IPNetwork] = []
        for n in work:
            if sp.version != n.version:
                nxt.append(n)
                continue
            if sp.supernet_of(n):  # type: ignore[arg-type] # n fully covered -> drop
                continue
            if n.supernet_of(sp):  # type: ignore[arg-type] # n contains sp -> carve sp out
                nxt.extend(n.address_exclude(sp))  # type: ignore[arg-type]
            else:  # disjoint
                nxt.append(n)
        work = nxt
        if not work:
            return False
    return len(work) > 0


def is_untrusted(text: str) -> bool:
    """True iff this CIDR intersects public (internet-routable) address space.

    ``0.0.0.0/0``, ``0.0.0.0/1``, ``::/0``, a real public ``/24`` -> True.
    ``10.0.0.0/16``, ``192.168.1.0/24``, ``fd00::/8`` -> False.
    Unparseable input -> False here; callers treat parse failure as UNKNOWN separately.
    """
    net = parse_cidr(text)
    if net is None:
        return False
    specials = _NON_PUBLIC_V4 if net.version == 4 else _NON_PUBLIC_V6
    return _remaining_after_exclude(net, specials)


def any_untrusted(cidrs: Iterable[str]) -> bool:
    return any(is_untrusted(c) for c in cidrs)


def cidr_contains(outer: str, inner: str) -> bool:
    """True if network ``outer`` fully contains network ``inner`` (same IP version).

    Used for intra-VPC pivots: a sink SG rule whose CIDR covers a compromised host's private
    range admits that host, even without an SG-to-SG reference."""
    o = parse_cidr(outer)
    i = parse_cidr(inner)
    if o is None or i is None or o.version != i.version:
        return False
    return o.supernet_of(i) or o == i  # type: ignore[arg-type]
