"""Qualitative check on hand-made URL lists.

Two lists:
- DEV list (below): first run on model v1 after it was frozen. It revealed the brand-keyword
  bug, so it has influenced development (v2) and is reported as a development check only.
- HOLD-OUT list (scripts/holdout_urls.py): frozen before the v2 iteration (its sha256 is in
  reports/holdout_list.sha256), run only after model v2 was frozen, never used for tuning.

The legitimate URLs are well-known Norwegian sites (the app's audience is Norwegian, and .no
sites are rare in the training data). The phishing-style URLs are CONSTRUCTED (made-up
domains), not real phishing links.

Usage: python scripts/sanity_check.py  -> reports/sanity_check.md
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import hashlib  # noqa: E402

from phishcheck.predictor import Predictor  # noqa: E402
from scripts.holdout_urls import HOLDOUT_LEGIT, HOLDOUT_PHISH_STYLE  # noqa: E402

LEGIT = [
    "https://www.nrk.no", "https://www.nrk.no/nyheter/", "https://www.vg.no", "https://www.vg.no/nyheter",
    "https://www.aftenposten.no/", "https://www.dnb.no/", "https://www.dnb.no/privat/kort",
    "https://www.vipps.no/", "https://www.posten.no/sporing", "https://www.nav.no/",
    "https://www.skatteetaten.no/person/skatt/", "https://www.hvl.no/", "https://www.hvl.no/studier/",
    "https://www.uib.no/", "https://www.finn.no/", "https://www.finn.no/bap/forsale/search.html",
    "https://www.regjeringen.no/no/id4/", "https://www.helsenorge.no/", "https://www.yr.no/nb",
    "https://www.altinn.no/", "https://www.bankid.no/", "https://www.elkjop.no/", "https://www.komplett.no/",
    "https://www.sparebank1.no/nb/bank/privat.html", "https://www.telenor.no/", "https://www.ruter.no/",
    "https://www.vy.no/", "https://www.norwegian.no/", "https://www.husqvarna.com/no/", "https://github.com/",
]
PHISH_STYLE = [
    "http://secure-dnb-login.verify-account.xyz/bankid",
    "https://vipps-refund-claim.webflow.io/",
    "http://192.168.10.5/posten/tracking.php",
    "https://posten-no-sporing-pakke.top/betal",
    "https://nav-utbetaling-bekreft.com/login",
    "https://dnb.no.secure-auth-session.click/",
    "https://xn--pypal-4ve.com/signin",
    "http://apple-id-unlock-support.info/account/verify",
    "https://helsenorge-innlogging.shop/bankid",
    "https://microsoft365-mailbox-upgrade.vercel.app/",
]


def table(p: Predictor, lists) -> list[str]:
    lines = ["| Type | URL | Bånd | Score |", "|---|---|---|---|"]
    for kind, urls in lists:
        for u in urls:
            a = p.assess(u)
            lines.append(f"| {kind} | `{u.replace('.', '[.]')}` | {a.band} | {a.score if a.score is not None else '-'} |")
    return lines


def main() -> None:
    expected = (ROOT / "reports" / "holdout_list.sha256").read_text().split()[0]
    actual = hashlib.sha256((ROOT / "scripts" / "holdout_urls.py").read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    if actual != expected:
        sys.exit("scripts/holdout_urls.py was changed after it was frozen. Refusing to run.")
    p = Predictor()
    lines = ["# Kvalitativ sjekk av modell " + p.meta.get("model_version", "v1"), "",
             "## Skjult liste (frosset før v2-iterasjonen, kjørt etter at v2 var låst, aldri brukt til tuning)", ""]
    lines += table(p, [("Legitim", HOLDOUT_LEGIT), ("Konstruert phishing", HOLDOUT_PHISH_STYLE)])
    lines += ["", "## Utviklingsliste (avdekket merkenavn-feilen i v1, har derfor påvirket utviklingen)", ""]
    lines += table(p, [("Legitim", LEGIT), ("Konstruert phishing", PHISH_STYLE)])
    (ROOT / "reports" / "sanity_check.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
