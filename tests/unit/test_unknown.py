from probepath.ingest.unknown import is_unknown


def test_scalar_known_when_omitted():
    # after_unknown omits known leaves entirely
    assert not is_unknown({}, ("publicly_accessible",))
    assert not is_unknown({"other": True}, ("publicly_accessible",))


def test_scalar_unknown_true():
    assert is_unknown({"publicly_accessible": True}, ("publicly_accessible",))


def test_whole_list_unknown():
    assert is_unknown({"vpc_security_group_ids": True}, ("vpc_security_group_ids",))


def test_list_element_unknown_marks_whole_membership_unknown():
    # only element [1] unknown, but asking about the whole list must be conservative
    au = {"vpc_security_group_ids": [False, True]}
    # NB: terraform encodes known list elements as omitted; we model [<known>, True]
    assert is_unknown(au, ("vpc_security_group_ids",))


def test_nested_block_list_of_objects():
    au = {"ingress": [{"cidr_blocks": True}, {}]}
    assert is_unknown(au, ("ingress", 0, "cidr_blocks"))
    assert not is_unknown(au, ("ingress", 1, "cidr_blocks"))


def test_ancestor_entirely_unknown_implies_descendant_unknown():
    au = {"ingress": True}
    assert is_unknown(au, ("ingress", 0, "cidr_blocks"))


def test_path_beyond_known_is_known():
    # navigating into a value that is concretely present and not flagged
    assert not is_unknown({}, ("ingress", 0, "cidr_blocks"))


def test_bool_true_root_is_unknown_everywhere():
    assert is_unknown(True, ("anything",))
    assert is_unknown(True, ())
