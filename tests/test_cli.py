"""End-to-end CLI tests via Typer's CliRunner."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from probepath.cli import app

runner = CliRunner()
EX = Path(__file__).resolve().parent.parent / "examples"
P01 = str(EX / "P01_textbook_public_rds" / "plan.tfplan.json")
N01 = str(EX / "N01_private_subnet_suppressed" / "plan.tfplan.json")
DEMO = str(EX / "demo_corp_stack" / "plan.tfplan.json")


def test_scan_human_shows_reachable_path():
    r = runner.invoke(app, ["scan", P01, "--fail-on", "never"])
    assert r.exit_code == 0
    assert "REACHABLE" in r.stdout
    assert "aws_db_instance.main" in r.stdout


def test_scan_gate_freezes_on_reachable():
    r = runner.invoke(app, ["scan", P01, "--fail-on", "reachable"])
    assert r.exit_code == 1


def test_scan_json_contract():
    r = runner.invoke(app, ["scan", P01, "-f", "json", "--fail-on", "never"])
    doc = json.loads(r.stdout)
    assert doc["schema"] == "probepath/v1"
    assert doc["summary"]["reachable"] == 1
    assert doc["findings"][0]["verdict"] == "reachable"
    assert len(doc["findings"][0]["path"]) == 2


def test_scan_sarif_2_1_0():
    r = runner.invoke(app, ["scan", P01, "-f", "sarif", "--fail-on", "never"])
    doc = json.loads(r.stdout)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "probepath"
    assert run["results"], "expected at least one SARIF result"
    assert run["results"][0]["codeFlows"], "expected a hop-by-hop codeFlow"


def test_unreachable_suppressed_and_gate_passes():
    r = runner.invoke(app, ["scan", N01, "--fail-on", "reachable"])
    assert r.exit_code == 0
    assert "suppressed" in r.stdout.lower()


def test_explain_mermaid():
    r = runner.invoke(app, ["explain", "aws_db_instance.main", P01, "-f", "mermaid"])
    assert r.exit_code == 0
    assert "flowchart" in r.stdout


def test_graph_export_mermaid():
    r = runner.invoke(app, ["graph-export", P01])
    assert r.exit_code == 0
    assert "flowchart" in r.stdout


def test_baseline_gates_only_new_paths(tmp_path: Path):
    # Baseline = the clean N01 stack (nothing reachable). Scanning the exposed demo against it
    # should flag a NEW path and fail. Scanning N01 against itself should pass.
    base = tmp_path / "base.json"
    r = runner.invoke(app, ["scan", N01, "-f", "json", "--fail-on", "never", "-o", str(base)])
    assert r.exit_code == 0
    r2 = runner.invoke(app, ["scan", N01, "--baseline", str(base), "--fail-on", "reachable"])
    assert r2.exit_code == 0  # no new path vs itself
    r3 = runner.invoke(app, ["scan", DEMO, "--baseline", str(base), "--fail-on", "reachable"])
    assert r3.exit_code == 1  # demo introduces reachable paths not in the baseline


def test_bad_input_is_exit_2(tmp_path: Path):
    bad = tmp_path / "nope.json"
    bad.write_text("{}")
    r = runner.invoke(app, ["scan", str(bad)])
    assert r.exit_code == 2
