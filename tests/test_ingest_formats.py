"""Coverage for the secondary inputs: raw HCL and Terraform state."""

from __future__ import annotations

from pathlib import Path

from probepath.engine.builder import build_graph
from probepath.engine.reachability import analyze
from probepath.ingest import ingest_paths
from probepath.ingest.state import parse_state_json
from probepath.model.enums import Verdict

_HCL = """
resource "aws_db_instance" "main" {
  publicly_accessible    = true
  port                   = 5432
  engine                 = "postgres"
  vpc_security_group_ids = [aws_security_group.db.id]
}
resource "aws_security_group" "db" {
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""


def test_hcl_open_db_is_never_falsely_suppressed(tmp_path: Path):
    (tmp_path / "main.tf").write_text(_HCL)
    records = ingest_paths([tmp_path])
    assert any(r.type == "aws_db_instance" for r in records)
    # HCL extracts references from interpolations, so the SG resolves and the open DB is seen.
    result = analyze(build_graph(records))
    rds = next(f for f in result.findings if f.sink_address == "aws_db_instance.main")
    assert rds.verdict is not Verdict.UNREACHABLE  # the fatal class must never happen here


def test_state_json_parses_resources():
    state = {
        "format_version": "1.0",
        "values": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_db_instance.main",
                        "mode": "managed",
                        "type": "aws_db_instance",
                        "name": "main",
                        "values": {"port": 5432, "publicly_accessible": True, "engine": "postgres"},
                    },
                    {
                        "address": "aws_security_group.db",
                        "mode": "managed",
                        "type": "aws_security_group",
                        "name": "db",
                        "values": {"ingress": [{"from_port": 5432, "to_port": 5432,
                                                "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]},
                    },
                ]
            }
        },
    }
    records = parse_state_json(state)
    types = {r.type for r in records}
    assert "aws_db_instance" in types and "aws_security_group" in types
    # state values are concrete -> nothing is "unknown"
    db = next(r for r in records if r.type == "aws_db_instance")
    assert db.resolve("publicly_accessible").value is True
