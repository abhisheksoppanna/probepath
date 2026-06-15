from probepath.model.cidr import any_untrusted, is_untrusted, parse_cidr


def test_quad_zero_is_untrusted():
    assert is_untrusted("0.0.0.0/0")


def test_quad_zero_with_whitespace_normalizes():
    # trap_T09 normalization
    assert is_untrusted(" 0.0.0.0/0 ")


def test_split_range_covers_internet():
    # trap_T09 / P05: 0.0.0.0/1 + 128.0.0.0/1 together cover all of IPv4
    assert is_untrusted("0.0.0.0/1")
    assert is_untrusted("128.0.0.0/1")
    assert any_untrusted(["0.0.0.0/1", "128.0.0.0/1"])


def test_rfc1918_is_not_untrusted():
    assert not is_untrusted("10.0.0.0/8")
    assert not is_untrusted("172.16.0.0/12")
    assert not is_untrusted("192.168.1.0/24")


def test_loopback_linklocal_cgnat_not_untrusted():
    assert not is_untrusted("127.0.0.0/8")
    assert not is_untrusted("169.254.0.0/16")
    assert not is_untrusted("100.64.0.0/10")


def test_real_public_slash24_is_untrusted():
    assert is_untrusted("8.8.8.0/24")
    assert is_untrusted("1.2.3.4/32")


def test_ipv6_default_is_untrusted():
    # trap_A6: ::/0 — we exceed AWS Reachability Analyzer here (it is IPv4-only)
    assert is_untrusted("::/0")


def test_ipv6_ula_and_linklocal_not_untrusted():
    assert not is_untrusted("fd00::/8")
    assert not is_untrusted("fe80::/10")


def test_unparseable_is_false_not_crash():
    assert not is_untrusted("not-a-cidr")
    assert not is_untrusted("")
    assert parse_cidr("garbage") is None


def test_subset_of_private_stays_private():
    assert not is_untrusted("10.1.2.0/24")
    # but a block straddling private + public is untrusted (conservative)
    assert is_untrusted("0.0.0.0/1")  # contains 10/8 AND public space -> untrusted
