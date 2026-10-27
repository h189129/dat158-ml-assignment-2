import pytest

from phishcheck.canonical import canonicalize, path_prefixes


@pytest.mark.parametrize("variant", [
    "https://nrk.no", "https://nrk.no/", "https://www.nrk.no", "https://WWW.NRK.NO/",
    "nrk.no", "www.nrk.no/", "https://nrk.no/?utm=x", "https://nrk.no/#top", "  https://nrk.no  ",
    "https://m.nrk.no/", "https://www2.nrk.no", "https://nrk.no:443/", "https://nrk.no:",
    "https://nrk.no//", "HTTPS://NRK.NO", "//nrk.no", "https:nrk.no", "https:/nrk.no",
    "https://nrk.no?x=1", "https://nrk.no#a", "https://nrk.no。", "https://nrk.no.",
])
def test_cosmetic_variants_share_one_key(variant):
    assert canonicalize(variant).key == "https://nrk.no"


def test_missing_scheme_is_https():
    c = canonicalize("example.com/login")
    assert c.scheme == "https" and not c.had_scheme


def test_query_and_fragment_removed_but_recorded():
    c = canonicalize("https://a.com/x/Login.PHP?session=SECRET#frag")
    assert c.key == "https://a.com/x/login.php" and c.had_query


def test_query_directly_after_host_never_reaches_the_path():
    c = canonicalize("https://example.com?r=https://x.y/z")
    assert c.key == "https://example.com" and c.had_query and not c.double_slash_in_path


def test_backslash_is_a_path_separator_like_in_browsers():
    c = canonicalize("https://login.dnb.no\\@evil.top")
    assert c.host == "login.dnb.no" and not c.had_userinfo


def test_userinfo_and_port_detected():
    c = canonicalize("http://paypal.com@192.168.1.4:8080/a")
    assert c.had_userinfo and c.had_port
    assert c.host == "192.168.1.4" and c.scheme == "http"


@pytest.mark.parametrize("url,port", [
    ("https://a.com:443/", False), ("http://a.com:80/", False), ("https://a.com:80/", True),
    ("https://a.com:8443/", True), ("https://a.com:/", False),
])
def test_only_non_default_ports_count(url, port):
    assert canonicalize(url).had_port is port


@pytest.mark.parametrize("url,host", [
    ("http://3232235777/", "192.168.1.1"), ("http://0x7f000001/", "127.0.0.1"),
    ("http://127.1/", "127.0.0.1"), ("http://0300.0250.0001.0001/", "192.168.1.1"),
])
def test_numeric_ip_forms_are_normalized(url, host):
    assert canonicalize(url).host == host


def test_percent_encoded_host_is_decoded():
    assert canonicalize("https://pay%70al.com/x").host == "paypal.com"


def test_unicode_host_is_idna_encoded():
    c = canonicalize("https://pаypal.com/login")  # Cyrillic 'а'
    assert c.host.startswith("xn--") and not c.idna_failed


def test_prefix_stripping_keeps_a_registrable_host():
    assert canonicalize("https://m.co").host == "m.co"
    assert canonicalize("https://www.com").host == "www.com"


def test_double_slash_inside_path_is_detected():
    assert canonicalize("https://a.com/x//https://b.com").double_slash_in_path


def test_path_prefixes():
    c = canonicalize("https://a.com/x/y/z")
    assert path_prefixes(c) == ["https://a.com", "https://a.com/x", "https://a.com/x/y"]
    assert path_prefixes(canonicalize("https://a.com")) == []
