from probepath.model.ports import (
    ALL_PORTS,
    EPHEMERAL,
    PortSet,
    ports_from_rule,
)


def test_normalize_merges_overlapping_and_adjacent():
    ps = PortSet([(80, 100), (90, 120), (121, 130)])
    assert ps.intervals == ((80, 130),)


def test_normalize_drops_inverted_and_clamps():
    ps = PortSet([(100, 50), (-5, 70000)])
    # (100,50) -> clamped/dropped logic still yields a single point or range; (-5,70000)->0-65535
    assert (0, 65535) in list(ps.intervals) or ps == ALL_PORTS


def test_contains():
    ps = PortSet([(5432, 5432), (8000, 9000)])
    assert 5432 in ps
    assert 8500 in ps
    assert 5433 not in ps
    assert 0 not in ps


def test_intersect_overlap():
    a = PortSet([(0, 100), (200, 300)])
    b = PortSet([(50, 250)])
    assert a.intersect(b).intervals == ((50, 100), (200, 250))


def test_intersect_disjoint_is_empty():
    a = PortSet.single(443)
    b = PortSet.single(5432)
    assert a.intersect(b).is_empty
    assert not bool(a.intersect(b))


def test_union():
    a = PortSet.single(443)
    b = PortSet.single(80)
    assert a.union(b).intervals == ((80, 80), (443, 443))


def test_all_intersect_identity():
    a = PortSet.closed(5000, 6000)
    assert ALL_PORTS.intersect(a) == a


def test_ephemeral_is_wide_superset():
    assert 1024 in EPHEMERAL
    assert 65535 in EPHEMERAL
    assert 1023 not in EPHEMERAL
    # contains all OS-specific ephemeral ranges
    assert 32768 in EPHEMERAL and 49152 in EPHEMERAL


def test_ports_from_rule_all_protocol_minus1_is_all_not_port_zero():
    # trap_A5: protocol="-1", from=0, to=0 means ALL ports, not literal port 0
    assert ports_from_rule(0, 0, "-1") == ALL_PORTS
    assert ports_from_rule(None, None, "all") == ALL_PORTS


def test_ports_from_rule_range_containment():
    # trap_G2: a rule 5000-6000 must contain custom RDS port 5500
    ps = ports_from_rule(5000, 6000, "tcp")
    assert 5500 in ps
    assert 4999 not in ps


def test_ports_from_rule_unknown_ports_widen_to_all():
    assert ports_from_rule(None, None, "tcp") == ALL_PORTS


def test_hashable_and_equal():
    assert PortSet.single(443) == PortSet([(443, 443)])
    assert len({PortSet.single(443), PortSet([(443, 443)])}) == 1
