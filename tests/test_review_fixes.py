"""Regression tests for the adversarial-review findings.

Each test below would FAIL against the pre-fix code — they pin the false-negative bugs shut.
"""

from __future__ import annotations

from probepath.aws.network import NaclModel, NaclRule
from probepath.aws.routing import compute_publicness
from probepath.aws.s3 import _principal_is_anonymous
from probepath.engine.builder import build_graph
from probepath.engine.reachability import analyze
from probepath.ingest.normalized import RecordIndex, ResourceRecord
from probepath.model.enums import Confidence, Verdict
from probepath.model.ports import EPHEMERAL, PortSet


def _rec(t, n, values=None, after_unknown=None, references=None):
    return ResourceRecord(address=f"{t}.{n}", type=t, name=n, config_address=f"{t}.{n}",
                          values=values or {}, after_unknown=after_unknown or {}, references=references or {})


# --- PortSet.difference (new primitive behind the NACL fix) ---------------
def test_portset_difference():
    assert PortSet.closed(1024, 65535).difference(PortSet.closed(2000, 3000)).intervals == (
        (1024, 1999), (3001, 65535))
    assert PortSet.single(80).difference(PortSet.single(80)).is_empty
    assert EPHEMERAL.difference(EPHEMERAL).is_empty


# --- FN-1: NACL ephemeral return tested over the full range, not 4 samples ---
def test_nacl_ephemeral_return_midrange_allow_is_open():
    # inbound allows 5432; outbound allows ONLY 2000-3000 — none of the old 4 sample ports
    # (1024/32768/49152/65535) fall in that band, so the old code falsely blocked this.
    nacl = NaclModel("acl", is_default=False, rules=[
        NaclRule(100, False, "allow", "tcp", PortSet.single(5432), "0.0.0.0/0"),
        NaclRule(100, True, "allow", "tcp", PortSet.closed(2000, 3000), "0.0.0.0/0"),
    ])
    assert nacl.allows("0.0.0.0/0", 5432).allowed is True


def test_nacl_ephemeral_return_truly_closed_blocks():
    nacl = NaclModel("acl", is_default=False, rules=[
        NaclRule(100, False, "allow", "tcp", PortSet.single(5432), "0.0.0.0/0"),
        NaclRule(100, True, "allow", "tcp", PortSet.single(80), "0.0.0.0/0"),  # no ephemeral out
    ])
    assert nacl.allows("0.0.0.0/0", 5432).allowed is False


# --- MF-5: legacy aws_security_group_rule resolves the SG-to-SG pivot --------
def test_legacy_security_group_rule_pivot_is_reachable():
    records = [
        _rec("aws_vpc", "main", {"cidr_block": "10.0.0.0/16"}),
        _rec("aws_internet_gateway", "gw", references={"vpc_id": ["aws_vpc.main"]}),
        _rec("aws_route_table", "rt", {"route": [{"cidr_block": "0.0.0.0/0", "gateway_id": ""}]},
             {"route": [{"gateway_id": True}]}, {"route": ["aws_internet_gateway.gw"]}),
        _rec("aws_route_table_association", "a",
             references={"subnet_id": ["aws_subnet.snet"], "route_table_id": ["aws_route_table.rt"]}),
        _rec("aws_subnet", "snet", {"cidr_block": "10.0.1.0/24", "map_public_ip_on_launch": True},
             references={"vpc_id": ["aws_vpc.main"]}),
        _rec("aws_security_group", "web", {"ingress": [{"from_port": 22, "to_port": 22,
             "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": [],
             "prefix_list_ids": [], "security_groups": [], "self": False}]}),
        # db SG with NO inline ingress — the rule lives in a separate aws_security_group_rule
        _rec("aws_security_group", "db", {"ingress": []}),
        _rec("aws_security_group_rule", "db_from_web",
             {"type": "ingress", "from_port": 5432, "to_port": 5432, "protocol": "tcp"},
             references={"security_group_id": ["aws_security_group.db"],
                         "source_security_group_id": ["aws_security_group.web"]}),
        _rec("aws_instance", "web", {"associate_public_ip_address": True},
             references={"subnet_id": ["aws_subnet.snet"], "vpc_security_group_ids": ["aws_security_group.web"]}),
        _rec("aws_db_subnet_group", "dbg", {"subnet_ids": []},
             references={"subnet_ids": ["aws_subnet.snet"]}),
        _rec("aws_db_instance", "main", {"port": 5432, "publicly_accessible": False, "engine": "postgres"},
             references={"vpc_security_group_ids": ["aws_security_group.db"],
                         "db_subnet_group_name": ["aws_db_subnet_group.dbg"]}),
    ]
    findings = {f.sink_address: f.verdict for f in analyze(build_graph(records)).findings}
    assert findings["aws_db_instance.main"] is Verdict.REACHABLE


# --- FN-4: unresolved route table is conservatively public, never KNOWN-private ---
def test_unresolved_route_table_is_conservatively_public():
    records = [
        _rec("aws_vpc", "main", {"cidr_block": "10.0.0.0/16"}),
        _rec("aws_subnet", "orphan", {"cidr_block": "10.0.9.0/24"},
             references={"vpc_id": ["aws_vpc.main"]}),
    ]
    info = compute_publicness(RecordIndex(records))["aws_subnet.orphan"]
    assert info.is_public is True
    assert info.confidence is Confidence.AFTER_APPLY  # NOT a KNOWN-private closure


# --- MF-6/MF-7: a sink whose SG is in a module/remote state is never suppressed ---
def test_unresolved_module_sg_is_not_falsely_suppressed():
    records = [
        _rec("aws_db_instance", "main", {"port": 5432, "publicly_accessible": False, "engine": "postgres"},
             references={"vpc_security_group_ids": ["module.net.db_sg"]}),
    ]
    finding = analyze(build_graph(records)).findings[0]
    assert finding.verdict is Verdict.POTENTIALLY_REACHABLE


# --- NTH-11: S3 anonymous-principal exact match (wildcard account ARN is NOT anon) ---
def test_s3_principal_exact_wildcard_only():
    assert _principal_is_anonymous("*") is True
    assert _principal_is_anonymous({"AWS": "*"}) is True
    assert _principal_is_anonymous({"AWS": ["*", "arn:aws:iam::123:root"]}) is True
    assert _principal_is_anonymous({"AWS": "arn:aws:iam::*:root"}) is False  # account wildcard, not anon
    assert _principal_is_anonymous({"Service": "lambda.amazonaws.com"}) is False
