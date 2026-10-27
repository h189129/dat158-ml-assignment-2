import socket
from pathlib import Path

import numpy as np
import pytest

from phishcheck.domains import group_key, is_shared_platform, is_shortener
from phishcheck.features import BASE_FEATURES, DROPPED_BY_MONTH_AUDIT, URLFeatures, feature_code_hash

TLDS = ("com", "no", "io")


def feats(url):
    t = URLFeatures(TLDS)
    return dict(zip(t.get_feature_names_out(), t.transform([url])[0]))


def test_equivalent_urls_get_identical_features():
    t = URLFeatures(TLDS)
    X = t.transform(["https://www.nrk.no/", "nrk.no", "https://NRK.no?x=1#y", "https://nrk.no:443//"])
    for row in X[1:]:
        assert np.array_equal(X[0], row)


def test_query_string_never_influences_features():
    a = feats("https://shop.example.com/cart")
    assert a == feats("https://shop.example.com/cart?id=123&redirect=https://evil.com")
    assert a == feats("https://shop.example.com/cart#https://evil.com")


def test_shape_and_names():
    t = URLFeatures(TLDS)
    assert t.transform(["a.com", "b.no"]).shape == (2, len(BASE_FEATURES) + len(TLDS) + 1)
    assert not set(DROPPED_BY_MONTH_AUDIT) & set(t.get_feature_names_out())


def test_classic_tricks():
    f = feats("http://user@10.0.0.1:81/secure-login.php")
    assert f["is_ip_host"] == 1 and f["has_userinfo"] == 1 and f["has_port"] == 1
    assert f["is_https"] == 0 and f["ext_php"] == 1 and f["n_generic_keywords"] >= 1
    assert feats("https://[2001:db8::1]/x")["is_ip_host"] == 1
    assert feats("http://3232235777/")["is_ip_host"] == 1
    assert feats("https://bad.cafe/")["is_ip_host"] == 0


def test_embedded_url_detection():
    assert feats("https://a.com/http-status-codes")["http_in_path"] == 0
    assert feats("https://a.com/go/https://evil.com/x")["http_in_path"] == 1
    assert feats("https://a.com/go/http%3a%2f%2fevil.com")["http_in_path"] == 1


@pytest.mark.parametrize("url,is_dom,combo,elsewhere", [
    ("https://www.aftenposten.no/", 0, 0, 0),     # 'posten' inside another word is not a brand
    ("https://www.vipps.no/", 1, 0, 0),           # the site's own brand
    ("https://www.dnb.no/dnb-kort", 1, 0, 0),     # own brand in own path
    ("https://nav-utbetaling-bekreft.com/", 0, 1, 0),  # combosquatting
    ("https://paypal.secure-login.com/", 0, 0, 1),     # brand in sub-domain
    ("https://example.com/microsoft/login", 0, 0, 1),  # brand in path
    ("https://navigate.com/", 0, 0, 0),
])
def test_brand_features(url, is_dom, combo, elsewhere):
    f = feats(url)
    assert (f["brand_is_domain"], f["brand_in_domain_label"], f["brand_in_subdomain_or_path"]) == (is_dom, combo, elsewhere)


def test_hyphens_counted_on_readable_host_not_punycode():
    assert feats("https://blåbær.no")["n_hyphens_host"] == 0
    assert feats("https://bl-å-bær.no")["n_hyphens_host"] == 2


def test_tld_onehot():
    f = feats("https://a.no")
    assert f["tld_no"] == 1 and f["tld_other"] == 0
    assert feats("https://a.xyz")["tld_other"] == 1


def test_platforms_shorteners_and_groups():
    assert is_shared_platform("docs.google.com") and is_shared_platform("foo.gitbook.io")
    assert is_shared_platform("someone.github.io")  # private public-suffix entry
    assert not is_shared_platform("nrk.no")
    assert is_shortener("bit.ly") and is_shortener("acme.app.link") and is_shortener("x.page.link")
    assert not is_shortener("nrk.no") and not is_shortener("notbit.ly")
    assert group_key("a.b.example.co.uk") == "example.co.uk"
    assert group_key("x.gitbook.io") == "x.gitbook.io"


def test_feature_code_hash_is_stable():
    assert feature_code_hash() == feature_code_hash() and len(feature_code_hash()) == 16


def test_no_network_access(monkeypatch):
    def blocked(*a, **k):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    URLFeatures(TLDS).transform(["https://some-new-unseen-domain-123.example.org/path", "http://3232235777/"])


@pytest.mark.parametrize("url,combo", [
    ("https://whatsapp16.com/", 1),           # letters/digits split
    ("https://paypal-verify.com/", 1),
    ("https://paypalverify.com/", 0),         # glued brands are not detected (documented)
    ("https://www.aftenposten.no/", 0),
    ("https://www.vipps.no/", 0),
])
def test_combosquat_features(url, combo):
    assert feats(url)["brand_in_domain_label"] == combo


def test_brand_families_count_as_own_domain():
    for u in ["https://outlook.live.com/mail", "https://outlook.office365.com/", "https://www.instagram.com/facebook"]:
        f = feats(u)
        assert f["brand_is_domain"] == 1 and f["brand_in_subdomain_or_path"] == 0, u


def test_short_generic_keywords_need_whole_token():
    assert feats("https://example.com/author/jane")["n_generic_keywords"] == 0
    assert feats("https://oauth2.googleapis.com/token")["keyword_in_subdomain"] == 0
    assert feats("https://auth.example.com/")["keyword_in_subdomain"] == 1


def test_public_suffix_hosts_keep_their_prefix():
    from phishcheck.canonical import canonicalize
    assert canonicalize("https://www.gov.uk/x").host == "www.gov.uk"
    assert canonicalize("https://www.nhs.uk").host == "www.nhs.uk"


def test_feature_hash_ignores_line_endings(tmp_path, monkeypatch):
    import phishcheck.features as F
    src = Path(F.__file__).resolve().parent
    dst = tmp_path / "phishcheck"
    dst.mkdir()
    for name in ("canonical.py", "domains.py", "features.py", "vocab.py"):
        (dst / name).write_bytes((src / name).read_bytes().replace(b"\n", b"\r\n"))
    monkeypatch.setattr(F, "__file__", str(dst / "features.py"))
    crlf = F.feature_code_hash()
    monkeypatch.setattr(F, "__file__", str(src / "features.py"))
    assert crlf == F.feature_code_hash()


def test_whole_percent_thresholds():
    from phishcheck.evaluation import whole_percent
    assert whole_percent(0.53) == 0.53 and whole_percent(0.5301) == 0.54
    assert whole_percent(float("inf")) == float("inf")


def test_brand_families_not_applied_on_shared_platforms():
    for u in ["https://office365-verify.sharepoint.com/x", "https://amazon-refund.s3.amazonaws.com/x"]:
        assert feats(u)["brand_is_domain"] == 0, u


def test_brands_with_digits_match():
    assert feats("https://evil.com/office365/login")["brand_in_subdomain_or_path"] == 1
    assert feats("https://office365-verify.sharepoint.com/x")["brand_in_subdomain_or_path"] == 1
    assert feats("https://office365-login.com/")["brand_in_domain_label"] == 1
