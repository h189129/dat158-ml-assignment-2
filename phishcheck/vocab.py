"""Hand-curated vocabularies, frozen before model training.

How they were made (documented for the report). scripts/inspect_vocab.py was written
afterwards to reconstruct the candidate lists so the curation can be checked; its filters
mirror the rules below.
- All lists were derived from the TRAIN_CORE split only (train data dated before 2025-07-01).
  Validation and test data were not used.
- SHARED_PLATFORM_DOMAINS: registrable domains with >= 20 distinct hostnames in train_core were
  listed and then filtered BY HAND to services where anyone can publish content under a
  sub-domain or path (site builders, hosting, forms, file storage, IPFS gateways). Domains that
  look attacker-owned (e.g. '*.shop' clusters, 'pl-oferta-id…top') were deliberately excluded,
  as were multi-tenant business SaaS where only paying organisations publish. A few well-known
  platforms that are not in the public suffix list were added.
- URL_SHORTENERS: hosts in train_core with >= 15 URLs where >= 90 % had a single path segment
  (median path <= 12 characters, host name <= 14 characters), filtered by hand to genuine link shorteners / QR-redirect services, plus
  well-known shorteners. Shortened links hide their destination, so they cannot be judged
  from the URL; they are removed from training/evaluation and the app reports them separately.
- BRAND_KEYWORDS: the most frequent phishing `target` brands in train_core, written as the
  token that would appear in a URL. Generic labels ('other', 'unknown', 'generic …'),
  tokens of <= 3 letters and tokens that are common substrings of ordinary words
  (e.g. 'meta', 'visa', 'steam', 'orange') were excluded. A few brands were added by hand
  without looking at any data: crypto wallets that dominate the 'other' target
  (metamask, trezor, ledger, binance), Microsoft/Apple product names (office365, outlook,
  icloud) and Norwegian brands for the app's target audience (posten, postnord, dnb, vipps,
  bankid, nav).
- BRAND_OWNER_DOMAINS: registrable domains that belong to a brand's owner, so that e.g.
  'outlook.live.com' is not treated as a brand used on someone else's domain. Written by hand
  from general knowledge (no data used).
- Matching (see features.py): URLs are split into tokens at every non-alphanumeric character
  AND at letter/digit boundaries ('whatsapp16' -> 'whatsapp', '16').
  * Brands match whole tokens only ('posten' does not fire inside 'aftenposten', 'nav' not
    inside 'navigate'). Brands glued to other words ('paypalverify') are therefore not
    detected as brands; a substring feature for them was tried and dropped (no gain on
    validation data, false alarms on legitimate names).
  * Generic keywords of >= 5 characters match as substrings ('secureupdate'); shorter ones
    ('auth', 'gift') only as whole tokens, so 'auth' does not fire on 'author' or 'oauth2'.
"""

SHARED_PLATFORM_DOMAINS = frozenset({
    # site builders / hosting where every sub-domain is a different publisher
    "gitbook.io", "weeblysite.com", "weebly.com", "godaddysites.com", "webcindario.com",
    "studio.site", "surge.sh", "mybluehost.me", "teachable.com", "webwave.dev",
    "codeanyapp.com", "ubpages.com", "wcomhost.com", "hubside.fr", "serv00.net",
    "mystrikingly.com", "sviluppo.host", "mmm.page", "teemill.com", "crazydomains.com",
    "daftpage.com", "squarespace.com", "freewebhostmost.com", "000.pe", "myportfolio.com",
    "mytemp.website", "filesusr.com", "000webhostapp.com", "hs-sites.com", "mypixieset.com",
    "wordpress.com", "rf.gd", "b12sites.com", "fleek.co", "tiiny.site", "tempisite.com",
    "pory.app", "peraichi.com", "free.nf", "temporary.site", "temporary-demo.site",
    "systeme.io", "secureserver.net", "myftpupload.com", "inmotionhosting.com", "webydo.com",
    "tumblr.com", "substack.com", "fandom.com", "wixsite.com", "wix.com", "jimdosite.com",
    "blogspot.com", "blogspot.ch", "blogspot.fr", "sites.google.com",
    # link-in-bio / landing-page builders
    "flow.page", "beacons.ai", "linkin.bio", "campsite.bio", "keepo.io", "hootbio.com",
    "kytelink.com", "heyflow.id", "flowcv.me",
    # forms / docs / file storage / object storage / IPFS gateways
    "formstack.com", "forms.app", "activehosted.com", "gorgias.help", "atlassian.net",
    "sharepoint.com", "myqcloud.com", "windows.net", "backblazeb2.com", "ipfs.cf-ipfs.com",
    "arcgis.com", "odoo.com", "dynamics.com", "site.com", "oortech.com",
})

# Specific hosts on large company domains that serve user-published content.
SHARED_PLATFORM_HOSTS = frozenset({
    "docs.google.com", "sites.google.com", "drive.google.com", "script.google.com",
    "forms.gle", "storage.googleapis.com", "firebasestorage.googleapis.com",
    "express.adobe.com", "new.express.adobe.com", "onedrive.live.com", "1drv.ms",
    "dropbox.com", "dl.dropboxusercontent.com", "canva.site", "notion.site",
})

# Large company domains whose sub-domains are separate services; grouped by hostname in CV.
HOST_GROUPED_DOMAINS = frozenset({
    "google.com", "googleapis.com", "microsoft.com", "live.com", "adobe.com", "amazonaws.com",
    "dropbox.com", "yahoo.com", "yahoo.co.jp",
})

URL_SHORTENERS = frozenset({
    "t.co", "qrco.de", "q-r.to", "l.ead.me", "bit.ly", "urlz.fr", "tinyurl.com", "cutt.ly",
    "rebrand.ly", "rb.gy", "shorturl.at", "is.gd", "s.id", "t.ly", "l.wl.co", "linkr.it",
    "flowto.it", "snip.ly", "qr-codes.io", "did.li", "ln.run", "shorter.me", "surl.li",
    "ja.cat", "u.to", "ow.ly", "uqr.to", "tyny.to", "pixelfy.me", "parg.co",
    "goo.gl", "page.link", "app.link", "onelink.me", "tiny.cc", "buff.ly", "lnkd.in",
    "shorturl.asia", "v.gd", "x.co", "bl.ink", "short.io",
})

GENERIC_KEYWORDS = (
    "login", "log-in", "signin", "sign-in", "logon", "verify", "verification", "secure",
    "account", "update", "confirm", "wallet", "password", "support", "recover", "unlock",
    "billing", "invoice", "auth", "suspend", "webmail", "payment", "refund", "reward",
    "claim", "bonus", "gift", "delivery", "parcel", "customs", "tracking", "helpdesk",
)

BRAND_KEYWORDS = (
    "facebook", "instagram", "whatsapp", "usps", "microsoft", "office365", "outlook",
    "allegro", "rakuten", "dhl", "jojobet", "holiganbet", "netflix", "apple", "icloud",
    "swisspass", "amazon", "coinbase", "zoetis", "bancaribe", "docusign", "optus", "adobe",
    "tiktok", "citadel", "bankofamerica", "yahoo", "wepink", "hsbc", "mastercard", "lloyds",
    "swisscom", "ebay", "correios", "paypal", "santander", "twint", "barclays", "norton",
    "spotify", "bradesco", "xfinity", "comcast", "sicoob", "metamask", "trezor", "ledger",
    "binance", "postnord", "posten", "dnb", "vipps", "bankid", "nav",
)

_MICROSOFT = {"microsoft.com", "live.com", "office.com", "office365.com", "outlook.com",
              "microsoftonline.com", "sharepoint.com", "onedrive.com", "msn.com"}
_META = {"facebook.com", "fb.com", "instagram.com", "whatsapp.com", "whatsapp.net", "meta.com", "messenger.com"}
_APPLE = {"apple.com", "icloud.com", "me.com"}
BRAND_OWNER_DOMAINS = {
    "microsoft": _MICROSOFT, "office365": _MICROSOFT, "outlook": _MICROSOFT,
    "facebook": _META, "instagram": _META, "whatsapp": _META,
    "apple": _APPLE, "icloud": _APPLE,
    "amazon": {"amazon.com", "amazonaws.com", "amazon.co.uk", "amazon.de", "amazon.se", "amazon.co.jp"},
    "posten": {"posten.no", "bring.no", "postenbring.no"}, "postnord": {"postnord.no", "postnord.se", "postnord.dk"},
    "dnb": {"dnb.no", "dnb.com"}, "vipps": {"vipps.no", "vippsmobilepay.com"}, "bankid": {"bankid.no", "bankid.com"},
    "nav": {"nav.no"}, "paypal": {"paypal.com", "paypal.me"}, "netflix": {"netflix.com"},
    "adobe": {"adobe.com", "adobelogin.com"}, "docusign": {"docusign.com", "docusign.net"},
    "yahoo": {"yahoo.com", "yahoo.co.jp"}, "ebay": {"ebay.com", "ebay.co.uk", "ebay.de"},
    "rakuten": {"rakuten.co.jp", "rakuten.com"}, "tiktok": {"tiktok.com"}, "coinbase": {"coinbase.com"},
    "usps": {"usps.com"}, "dhl": {"dhl.com", "dhl.de"}, "spotify": {"spotify.com"},
}
