import json
import shutil
from pathlib import Path

import pytest

from phishcheck.predictor import BAND_HIGH, BAND_LOW, BAND_SUSPICIOUS, BAND_UNKNOWN, Predictor

ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "models" / "model.joblib"
pytestmark = pytest.mark.skipif(not MODEL.exists(), reason="trained model not present")


@pytest.fixture(scope="module")
def p():
    return Predictor()


@pytest.mark.parametrize("bad", [
    "", "   ", "javascript:alert(1)", "ftp://example.com/file", "two urls.com other.com", "x" * 3000,
    "localhost", "tel:+4712345678", "vbscript:msgbox", "about:blank", "intent:foo", "mailto:a@b.no",
    "https://.com", "https://a..b", "data:text/html,hi", "https://",
])
def test_invalid_input_gives_error(p, bad):
    a = p.assess(bad)
    assert a.error and a.score is None and a.band is None


@pytest.mark.parametrize("ok", [
    "example.com:8080/x?u=https://y.com", "user:pw@evil.com/?r=https://x.com", "//evil.com/x",
    "http:/evil.com", "https:evil.com/login", "http://3232235777/", "https://[2001:db8::1]/x",
    "hxxps://evil[.]com/login", "https://blåbær.no",
])
def test_valid_input_is_scored(p, ok):
    a = p.assess(ok)
    assert a.error is None and a.score is not None


def test_ip_forms_are_flagged(p):
    for u in ["http://3232235777/", "http://127.1/", "https://[2001:db8::1]/x"]:
        assert any("IP-adresse" in f for f in p.assess(u).flags)


def test_defanged_input_note(p):
    assert any("defanged" in n.lower() for n in p.assess("hxxps://evil[.]com/login").notes)


def test_shorteners_are_not_scored(p):
    for u in ["https://bit.ly/abc123", "https://acme.app.link/x", "https://x.page.link/y"]:
        a = p.assess(u)
        assert a.band == BAND_UNKNOWN and a.score is None


def test_cosmetic_variants_get_same_score(p):
    urls = ["https://www.nrk.no", "https://nrk.no/", "nrk.no", "https://NRK.no/?a=1", "https://nrk.no:443//"]
    assert len({p.assess(u).score for u in urls}) == 1


def test_no_misleading_red_flags_on_normal_norwegian_urls(p):
    assert not any("bindestrek" in f for f in p.assess("https://blåbær.no").flags)
    assert not any("merkenavn" in f for f in p.assess("https://www.dnb.no/privat/bankid").flags)
    assert not any("merkenavn" in f for f in p.assess("https://www.nrk.no/norge/facebook-nede-1.123").flags)
    assert not any("port" in f for f in p.assess("https://nrk.no:443/").flags)


def test_backslash_trick_shows_the_host_the_browser_opens(p):
    assert p.assess("https://login.dnb.no\\@evil.top").host == "login.dnb.no"


def test_displayed_score_agrees_with_band(p):
    hi, lo = p.meta["thresholds"]["high"], p.meta["thresholds"]["low"]
    assert round(hi * 100) == hi * 100 or abs(hi * 100 - round(hi * 100)) < 1e-9
    urls = ["https://a%d-login-verify.example%d.com/x" % (i, i) for i in range(40)] + \
           ["https://www.site%d.no/side/%d" % (i, i) for i in range(40)]
    for u in urls:
        a = p.assess(u)
        expected = BAND_HIGH if a.score >= round(hi * 100) else BAND_SUSPICIOUS if a.score >= round(lo * 100) else BAND_LOW
        assert a.band == expected, (u, a.score, a.band)


def test_notes_for_query_and_missing_scheme(p):
    a = p.assess("example.com/page?token=abc")
    assert any("https" in n for n in a.notes) and any("?" in n for n in a.notes)


def test_shared_platform_note(p):
    assert any("delt plattform" in n for n in p.assess("https://someone.gitbook.io/x").notes)


def test_model_refuses_mismatched_feature_code(tmp_path):
    meta = json.loads((ROOT / "models" / "metadata.json").read_text())
    meta["feature_code_hash"] = "0000000000000000"
    (tmp_path / "metadata.json").write_text(json.dumps(meta))
    with pytest.raises(RuntimeError):
        Predictor(model_path=MODEL, metadata_path=tmp_path / "metadata.json")


@pytest.mark.parametrize("bad", ["sip:alice@example.com", "xmpp:user@jabber.org", "https://[fe80::1%25eth0]/"])
def test_more_non_web_inputs_rejected(p, bad):
    assert p.assess(bad).error


def test_homograph_host_is_shown_as_punycode(p):
    a = p.assess("https://xn--pypal-4ve.com/signin")
    assert a.host == "xn--pypal-4ve.com"           # the Cyrillic look-alike is NOT rendered
    assert p.assess("https://blåbær.no").host == "xn--blbr-roah.no (blåbær.no)"


def test_brand_family_no_false_flag(p):
    assert not any("merkenavn" in f for f in p.assess("https://outlook.live.com/mail").flags)
    assert not any("login" in f for f in p.assess("https://oauth2.googleapis.com/token").flags)
