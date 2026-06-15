"""Human-readable terminal output via ``rich``."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from ..findings.finding import Finding, ScanResult
from ..model.enums import Confidence, ReachabilityClass, Verdict

_STYLE = {
    Verdict.REACHABLE: "bold red",
    Verdict.POTENTIALLY_REACHABLE: "bold yellow",
    Verdict.UNREACHABLE: "green",
}
_GLYPH = {
    Verdict.REACHABLE: "●",
    Verdict.POTENTIALLY_REACHABLE: "◐",
    Verdict.UNREACHABLE: "✓",
}
_LABEL = {
    Verdict.REACHABLE: "REACHABLE",
    Verdict.POTENTIALLY_REACHABLE: "POTENTIALLY REACHABLE",
    Verdict.UNREACHABLE: "SUPPRESSED (unreachable)",
}


def render(result: ScanResult, resource_count: int, console: Console | None = None) -> None:
    console = console or Console()
    r, p, s = len(result.reachable), len(result.potential), len(result.suppressed)

    summary = Text()
    summary.append(f"Scanned {resource_count} resources · {len(result.findings)} sensitive sinks\n")
    summary.append(f"{_GLYPH[Verdict.REACHABLE]} {r} reachable", style=_STYLE[Verdict.REACHABLE])
    summary.append("    ")
    summary.append(f"{_GLYPH[Verdict.POTENTIALLY_REACHABLE]} {p} potentially reachable",
                   style=_STYLE[Verdict.POTENTIALLY_REACHABLE])
    summary.append("    ")
    summary.append(f"{_GLYPH[Verdict.UNREACHABLE]} {s} suppressed (provably unreachable)",
                   style=_STYLE[Verdict.UNREACHABLE])
    console.print(Panel(summary, title="probepath — internet → sensitive reachability",
                        border_style="cyan", expand=False))

    for f in result.reachable + result.potential:
        _render_open(console, f)
    if result.suppressed:
        console.print()
        console.print(Text("Suppressed — provably unreachable (shown with the gate that closes them):",
                           style="green"))
        for f in result.suppressed:
            _render_suppressed(console, f)


def _render_open(console: Console, f: Finding) -> None:
    console.print()
    head = Text()
    head.append(f"{_GLYPH[f.verdict]} {_LABEL[f.verdict]}  ", style=_STYLE[f.verdict])
    head.append(f"{f.sink_label}  ", style="bold white")
    head.append(f.sink_address, style="white")
    if f.reachability_class is ReachabilityClass.IDENTITY:
        head.append("   [policy/ACL exposure, not a network path]", style="dim")
    console.print(head)
    if f.conservative_classes:
        console.print(Text(f"   conservative: {', '.join(f.conservative_classes)} "
                           "(kept visible because an input on the path is unknown)", style="dim yellow"))
    console.print(Text("   internet", style="dim"))
    for h in f.path:
        line = Text("    └→ ", style="dim")
        line.append(f"{h.to_label}", style="bold")
        known = h.confidence in (Confidence.KNOWN, Confidence.DEFAULT)
        line.append(f"   {h.why}", style="dim" if known else "yellow")
        console.print(line)
        loc = h.location.render()
        if loc:
            console.print(Text(f"        ↳ {loc}", style="dim cyan"))


def _render_suppressed(console: Console, f: Finding) -> None:
    line = Text("  ✓ ", style="green")
    line.append(f"{f.sink_label} {f.sink_address}", style="white")
    line.append(f"  — {f.blocked_reason}", style="dim")
    console.print(line)
