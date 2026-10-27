"""Held-out qualitative check list (frozen 2026-10-26, BEFORE the v2 bug-fix iteration).

Why a second list: the first list in scripts/sanity_check.py (the "dev list") revealed the
brand-keyword bug in model v1, so it has influenced development and is no longer an unbiased
check. This list was written before any v2 change, uses different sites, and is run only once,
after model v2 is frozen. It is never used for tuning.

Legitimate URLs: well-known Norwegian (and a few Nordic/international) sites that are NOT on
the dev list. Phishing-style URLs: CONSTRUCTED for this check (made-up domains), not real links.
"""

HOLDOUT_LEGIT = [
    "https://www.dagbladet.no/",
    "https://www.e24.no/",
    "https://www.bt.no/",
    "https://www.tv2.no/nyheter",
    "https://www.nordea.no/privat/",
    "https://www.storebrand.no/",
    "https://www.gjensidige.no/privat/forsikring",
    "https://www.if.no/",
    "https://www.lanekassen.no/",
    "https://www.udir.no/",
    "https://www.ntnu.no/studier",
    "https://www.uio.no/",
    "https://www.oslo.kommune.no/",
    "https://www.bergen.kommune.no/",
    "https://www.politiet.no/",
    "https://www.brreg.no/",
    "https://www.statensvegvesen.no/",
    "https://www.xxl.no/",
    "https://www.power.no/",
    "https://www.zalando.no/",
    "https://www.kiwi.no/",
    "https://www.obos.no/",
    "https://www.prisjakt.no/",
    "https://www.sas.no/",
    "https://www.flytoget.no/",
    "https://www.ikea.com/no/no/",
    "https://www.spotify.com/no/",
    "https://www.microsoft.com/nb-no/",
    "https://www.apple.com/no/",
    "https://www.netflix.com/no/",
]

HOLDOUT_PHISH_STYLE = [
    "https://nordea-kunde-verifisering.top/login",
    "http://bankid-fornyelse.info/oppdater",
    "https://lanekassen-tilbakebetaling.click/refund",
    "https://gjensidige.no.claim-payment.xyz/",
    "http://45.13.22.101/storebrand/secure/login.php",
    "https://politiet-bot-betaling.shop/",
    "https://netflix-account-suspended.vercel.app/update",
    "https://apple-icloud-locked.web.app/unlock",
    "https://xn--nrdea-ppa.com/login",
    "https://postnord-pakke-toll.buzz/betal",
]
