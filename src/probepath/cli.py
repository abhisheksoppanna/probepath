"""probepath command-line interface (Typer).

Commands:
  scan     primary CI/PR command — verdicts + suppressions, exit-code gate
  explain  deep-dive one sink, hop by hop (the demo money-shot)
  graph-export  emit the reachability graph (mermaid/dot)
"""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console

from . import __version__
from .errors import ProbepathError
from .findings.finding import ScanResult

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Prove whether an internet→database attack path exists in your Terraform, pre-apply.",
)
_err = Console(stderr=True)


def _scan(inputs: list[Path]) -> tuple[ScanResult, int]:
    from .engine.builder import build_graph
    from .engine.reachability import analyze
    from .ingest import ingest_paths

    records = ingest_paths(inputs)
    graph = build_graph(records)
    return analyze(graph), len(records)


@app.command()
def scan(
    inputs: list[Path] = typer.Argument(..., help="Terraform plan JSON / tfstate / .tf dir(s)"),
    output_format: str = typer.Option("human", "--format", "-f", help="human | json | sarif"),
    fail_on: str = typer.Option("reachable", "--fail-on", help="reachable | potential | never"),
    out: Path | None = typer.Option(None, "--out", "-o", help="write report to a file"),
    baseline: Path | None = typer.Option(
        None, "--baseline", help="base-ref probepath JSON report; gate only on NEWLY-introduced paths"
    ),
) -> None:
    """Scan Terraform and report which sinks are reachable from the internet."""
    try:
        result, n = _scan(inputs)
    except ProbepathError as exc:
        _err.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(2) from exc

    if output_format == "json":
        from .report import json_report

        text = json_report.render(result)
        _emit(text, out)
    elif output_format == "sarif":
        from .report import sarif

        text = sarif.render(result)
        _emit(text, out)
    elif output_format == "human":
        from .report import human

        console = Console(file=out.open("w") if out else None)
        human.render(result, n, console)
    else:
        _err.print(f"[red]error:[/red] unknown format '{output_format}'")
        raise typer.Exit(2)

    if baseline is not None:
        from .findings.diff import diff_results, load_baseline

        d = diff_results(load_baseline(baseline.read_text()), result)
        if d.added:
            _err.print("[red]NEW exposure introduced by this change:[/red] "
                       + ", ".join(f"{f.sink_address} ({f.verdict.value})" for f in d.added))
        if d.gate_violation(fail_on):
            raise typer.Exit(1)
        return

    if result.exit_violation(fail_on):
        raise typer.Exit(1)


@app.command()
def explain(
    sink: str = typer.Argument(..., help="sink resource address, e.g. aws_db_instance.main"),
    inputs: list[Path] = typer.Argument(..., help="Terraform plan JSON / tfstate / .tf dir(s)"),
    output_format: str = typer.Option("human", "--format", "-f", help="human | mermaid | json"),
) -> None:
    """Explain one sink's verdict in full, hop by hop (including the blocking gate if safe)."""
    try:
        result, n = _scan(inputs)
    except ProbepathError as exc:
        _err.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(2) from exc

    matches = [f for f in result.findings if f.sink_address == sink or f.sink_address.endswith(sink)]
    if not matches:
        _err.print(f"[red]error:[/red] no sink matching '{sink}'. Known sinks: "
                   + ", ".join(f.sink_address for f in result.findings))
        raise typer.Exit(2)

    if output_format == "mermaid":
        from .report import mermaid

        _emit(mermaid.render_finding(matches[0]), None)
    elif output_format == "json":
        from .report import json_report

        _emit(json_report.render(ScanResult(matches)), None)
    else:
        from .report import human

        human.render(ScanResult(matches), n)


@app.command(name="graph-export")
def graph_export(
    inputs: list[Path] = typer.Argument(...),
    output_format: str = typer.Option("mermaid", "--format", "-f", help="mermaid | dot"),
    out: Path | None = typer.Option(None, "--out", "-o"),
) -> None:
    """Export the full reachability graph (mermaid or graphviz dot)."""
    from .engine.builder import build_graph
    from .ingest import ingest_paths
    from .report import mermaid

    try:
        graph = build_graph(ingest_paths(inputs))
    except ProbepathError as exc:
        _err.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(2) from exc
    text = mermaid.render_graph(graph) if output_format == "mermaid" else mermaid.render_dot(graph)
    _emit(text, out)


@app.command()
def version() -> None:
    """Print the probepath version."""
    typer.echo(f"probepath {__version__}")


def _emit(text: str, out: Path | None) -> None:
    if out:
        out.write_text(text + "\n", encoding="utf-8")
    else:
        sys.stdout.write(text + "\n")


if __name__ == "__main__":
    app()
