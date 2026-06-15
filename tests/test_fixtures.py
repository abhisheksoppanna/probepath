"""Golden tests over the committed fixture matrix.

Each ``examples/<fixture>/`` ships real ``terraform show -json`` plan output and an
``expected.yaml`` pinning the verdict per sink. A regression that flips a reachable trap to
UNREACHABLE is a release-blocking false negative (DESIGN.md §6.1).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from probepath.engine.builder import build_graph
from probepath.engine.reachability import analyze
from probepath.ingest import ingest_paths

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _fixtures() -> list[Path]:
    return sorted(p.parent for p in EXAMPLES.glob("*/expected.yaml"))


def _scan(plan: Path) -> dict[str, str]:
    result = analyze(build_graph(ingest_paths([plan])))
    return {f.sink_address: f.verdict.value for f in result.findings}


@pytest.mark.parametrize("fixture", _fixtures(), ids=lambda p: p.name)
def test_fixture_verdicts(fixture: Path) -> None:
    plan = fixture / "plan.tfplan.json"
    assert plan.exists(), f"missing plan JSON for {fixture.name} — run scripts/regen_fixtures.sh"
    expected = yaml.safe_load((fixture / "expected.yaml").read_text())["sinks"]
    actual = _scan(plan)
    for sink, want in expected.items():
        assert sink in actual, f"{fixture.name}: sink {sink} not found (got {sorted(actual)})"
        assert actual[sink] == want, (
            f"{fixture.name}: {sink} expected {want!r}, got {actual[sink]!r}"
        )


@pytest.mark.critical
def test_no_reachable_fixture_is_ever_suppressed() -> None:
    """The fatal class: a sink we declared reachable must never come back UNREACHABLE."""
    for fixture in _fixtures():
        plan = fixture / "plan.tfplan.json"
        if not plan.exists():
            continue
        expected = yaml.safe_load((fixture / "expected.yaml").read_text())["sinks"]
        actual = _scan(plan)
        for sink, want in expected.items():
            if want in ("reachable", "potentially_reachable"):
                assert actual.get(sink) != "unreachable", (
                    f"FALSE NEGATIVE: {fixture.name} {sink} was suppressed but is {want}"
                )
