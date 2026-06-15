"""Property-based tests — the false-negative hunt (DESIGN.md §6.2).

The master invariant is *monotonicity*: making a topology strictly more permissive must
never move a verdict DOWN the lattice ``UNREACHABLE < POTENTIALLY_REACHABLE < REACHABLE``. If
it ever does, the engine could suppress a real path — the one fatal bug class.
"""

from __future__ import annotations

import random

from hypothesis import given, settings
from hypothesis import strategies as st

from probepath.engine.builder import build_graph
from probepath.engine.reachability import analyze
from probepath.ingest.normalized import ResourceRecord
from probepath.model.enums import Verdict

SINK = "aws_db_instance.main"


def _rec(tf_type: str, name: str, values=None, after_unknown=None, references=None) -> ResourceRecord:
    addr = f"{tf_type}.{name}"
    return ResourceRecord(
        address=addr,
        type=tf_type,
        name=name,
        config_address=addr,
        values=values or {},
        after_unknown=after_unknown or {},
        references=references or {},
    )


def _topology(world_open: bool, subnet_public: bool, db_trusts_web: bool) -> list[ResourceRecord]:
    """internet -> web (public EC2) -> RDS, with three independent permissiveness knobs."""
    web_cidr = ["0.0.0.0/0"] if world_open else ["10.0.0.0/8"]
    route = [{"cidr_block": "0.0.0.0/0", "gateway_id": ""}] if subnet_public else []
    rt_au = {"route": [{"gateway_id": True}]} if subnet_public else {}
    rt_refs = {"route": ["aws_internet_gateway.gw"]} if subnet_public else {}

    records = [
        _rec("aws_vpc", "main", {"cidr_block": "10.0.0.0/16"}),
        _rec("aws_internet_gateway", "gw", references={"vpc_id": ["aws_vpc.main"]}),
        _rec("aws_route_table", "rt", {"route": route}, rt_au, rt_refs),
        _rec("aws_route_table_association", "a",
             references={"subnet_id": ["aws_subnet.snet"], "route_table_id": ["aws_route_table.rt"]}),
        _rec("aws_subnet", "snet",
             {"cidr_block": "10.0.1.0/24", "map_public_ip_on_launch": True},
             references={"vpc_id": ["aws_vpc.main"]}),
        _rec("aws_security_group", "web",
             {"ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp",
                           "cidr_blocks": web_cidr, "ipv6_cidr_blocks": [],
                           "prefix_list_ids": [], "security_groups": [], "self": False}]}),
        _rec("aws_instance", "web", {"associate_public_ip_address": True},
             references={"subnet_id": ["aws_subnet.snet"], "vpc_security_group_ids": ["aws_security_group.web"]}),
        _rec("aws_db_subnet_group", "dbg", {"subnet_ids": []},
             references={"subnet_ids": ["aws_subnet.snet"]}),
    ]

    db_ingress = {"from_port": 5432, "to_port": 5432, "protocol": "tcp",
                  "cidr_blocks": [], "ipv6_cidr_blocks": [], "prefix_list_ids": [], "self": False}
    db_refs: dict[str, list[str]] = {"vpc_security_group_ids": ["aws_security_group.db"],
                                     "db_subnet_group_name": ["aws_db_subnet_group.dbg"]}
    if db_trusts_web:
        db_ingress["security_groups"] = ["sg-web"]
        db_sg = _rec("aws_security_group", "db", {"ingress": [db_ingress]},
                     references={"ingress": ["aws_security_group.web"]})
    else:
        db_ingress["security_groups"] = []
        db_sg = _rec("aws_security_group", "db", {"ingress": [db_ingress]})
    records.append(db_sg)
    records.append(_rec("aws_db_instance", "main",
                        {"port": 5432, "publicly_accessible": False, "engine": "postgres"}, {},
                        db_refs))
    return records


def _verdict(records: list[ResourceRecord]) -> Verdict:
    for f in analyze(build_graph(records)).findings:
        if f.sink_address == SINK:
            return f.verdict
    raise AssertionError("sink not found")


@settings(max_examples=40, deadline=None)
@given(st.booleans(), st.booleans(), st.booleans(), st.sampled_from(["world", "subnet", "db"]))
def test_monotone_widening_never_lowers_verdict(world: bool, subnet: bool, db: bool, knob: str) -> None:
    knobs = {"world": world, "subnet": subnet, "db": db}
    base = _verdict(_topology(knobs["world"], knobs["subnet"], knobs["db"]))
    knobs[knob] = True  # widen the chosen knob to its permissive value
    wider = _verdict(_topology(knobs["world"], knobs["subnet"], knobs["db"]))
    assert wider.rank >= base.rank, f"widening {knob} lowered the verdict: {base} -> {wider}"


@settings(max_examples=20, deadline=None)
@given(st.booleans(), st.booleans())
def test_no_untrusted_source_is_never_reachable(subnet: bool, db: bool) -> None:
    # web SG only allows RFC1918; there is no internet entry, so the DB cannot be REACHABLE.
    v = _verdict(_topology(world_open=False, subnet_public=subnet, db_trusts_web=db))
    assert v is not Verdict.REACHABLE


@settings(max_examples=20, deadline=None)
@given(st.booleans(), st.booleans(), st.booleans(), st.integers(min_value=0, max_value=9999))
def test_determinism_under_record_shuffle(world: bool, subnet: bool, db: bool, seed: int) -> None:
    records = _topology(world, subnet, db)
    base = _verdict(records)
    shuffled = records[:]
    random.Random(seed).shuffle(shuffled)
    assert _verdict(shuffled) is base


def test_fully_open_is_reachable_sanity() -> None:
    assert _verdict(_topology(True, True, True)) is Verdict.REACHABLE


def test_fully_closed_is_unreachable_sanity() -> None:
    assert _verdict(_topology(False, False, False)) is Verdict.UNREACHABLE
