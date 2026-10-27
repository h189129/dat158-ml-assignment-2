"""Lexical URL features as a scikit-learn transformer.

The transformer takes raw URL strings and returns a numeric feature matrix. It is the first
step of the saved model pipeline, so the web app calls exactly the same code as training.
Only the URL string is used: no page download, no DNS/WHOIS lookups.
"""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import idna
import numpy as np
import tldextract
from sklearn.base import BaseEstimator, TransformerMixin

from .canonical import CanonicalURL, canonicalize, readable_host
from .domains import host_parts, is_shared_platform
from .vocab import BRAND_KEYWORDS, BRAND_OWNER_DOMAINS, GENERIC_KEYWORDS

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_IPV6_RE = re.compile(r"^\[[0-9a-f:.]+\]$")
_EMBEDDED_URL_RE = re.compile(r"https?(:|%3a)")
_TOKEN_RE = re.compile(r"[a-z]+|[0-9]+")  # split at non-alphanumerics AND letter/digit boundaries
_SPECIAL = "~!$*,;:+="
_VOWELS = set("aeiou")
_BRANDS = frozenset(BRAND_KEYWORDS)

# Removed by the month audit (scripts/audit_months.py, reports/month_audit.json): their class
# signal flips sign between collection months, i.e. it reflects WHEN data was collected rather
# than phishing. They are still computed by url_features() for the audit, but not used.
DROPPED_BY_MONTH_AUDIT = ["len_domain", "entropy_domain"]

ALL_BASE_FEATURES = [
    "len_host", "len_path", "len_subdomain", "len_domain",
    "n_dots_host", "n_hyphens_host", "n_digits_host", "n_subdomain_levels",
    "path_depth", "n_hyphens_path", "n_underscores_path", "n_digits_path",
    "n_special_path", "n_percent_path", "digit_ratio",
    "entropy_host", "entropy_path", "entropy_domain",
    "is_https", "has_userinfo", "has_port", "is_ip_host", "is_punycode", "idna_failed",
    "double_slash_in_path", "http_in_path", "is_shared_platform", "is_private_suffix",
    "tld_length", "ext_php", "ext_html", "ext_pdf",
    "n_generic_keywords", "keyword_in_subdomain",
    "brand_is_domain", "brand_in_domain_label", "brand_in_subdomain_or_path",
    "longest_token", "n_tokens", "vowel_ratio_domain",
]
BASE_FEATURES = [f for f in ALL_BASE_FEATURES if f not in DROPPED_BY_MONTH_AUDIT]

_FEATURE_SOURCES = ("canonical.py", "domains.py", "features.py", "vocab.py")


def feature_code_hash() -> str:
    """Fingerprint of everything that determines the features (code + PSL/IDNA library versions).

    Stored in models/metadata.json at training time; the app refuses to load a model whose
    fingerprint differs from the running code (protection against training-serving skew).
    """
    h = hashlib.sha256()
    here = Path(__file__).resolve().parent
    for name in _FEATURE_SOURCES:
        # Normalize line endings so a Windows checkout (CRLF) gives the same fingerprint.
        h.update((here / name).read_bytes().replace(b"\r\n", b"\n"))
    h.update(f"tldextract={tldextract.__version__};idna={idna.__version__}".encode())
    return h.hexdigest()[:16]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _tokens(s: str) -> set[str]:
    return set(_TOKEN_RE.findall(s))


def _brand_tokens(s: str) -> set[str]:
    """Tokens for brand matching: both split ('whatsapp16' -> 'whatsapp') and unsplit
    alphanumeric runs (so brands containing digits, e.g. 'office365', can match)."""
    return _tokens(s) | set(re.findall(r"[a-z0-9]+", s))


def generic_keywords_found(text: str) -> list[str]:
    """Generic action words in `text`: >= 5 characters as substrings (phishers glue words:
    'secureupdate'), shorter ones ('auth', 'gift') only as whole tokens."""
    tokens = _tokens(text)
    return [k for k in GENERIC_KEYWORDS if ((k in text) if len(k) >= 5 else (k in tokens))]


def count_generic_keywords(text: str) -> int:
    return len(generic_keywords_found(text))


@dataclass(frozen=True)
class BrandMatch:
    """Where known brand names occur.

    Brands match WHOLE tokens only ('posten' does not match inside 'aftenposten'; 'nav' does
    not match 'navigate'). A substring feature for brands glued into the domain label
    ('paypalverify') was tried and removed: it gave no gain on validation data and re-created
    false alarms on legitimate names such as 'aftenposten' (see README)."""
    is_domain: bool             # the site's own brand: label is a brand (dnb.no, paypal.com - but
                                # also dnb.xyz!) or the host is on the brand owner's domain
                                # (outlook.live.com). Owner families are NOT applied on shared
                                # platforms (office365-verify.sharepoint.com).
    in_domain_label: frozenset  # brand tokens inside a longer label: nav-utbetaling.com, whatsapp16.com
    in_subdomain: frozenset     # brand tokens in the sub-domain: paypal.secure-login.com
    in_path: frozenset          # brand tokens in the path, other than the site's own brand


def brand_match(c: CanonicalURL) -> BrandMatch:
    hp = host_parts(c.host)
    label = hp.domain
    # Brands owned by this site: its own label, plus brand families on the owner's domains
    # (outlook.live.com mentions 'outlook' on a Microsoft domain).
    own = {label} if label in _BRANDS else set()
    if not is_shared_platform(c.host) and hp.registrable != "amazonaws.com":
        own |= {b for b, domains in BRAND_OWNER_DOMAINS.items() if hp.registrable in domains}
    is_domain = label in _BRANDS or bool(own - {label})
    label_tokens = _brand_tokens(label)
    in_label = frozenset() if is_domain else frozenset(label_tokens & _BRANDS)
    return BrandMatch(
        is_domain=is_domain,
        in_domain_label=in_label,
        in_subdomain=frozenset((_brand_tokens(hp.subdomain) & _BRANDS) - own),
        in_path=frozenset((_brand_tokens(c.path) & _BRANDS) - own),
    )


def url_features(c: CanonicalURL) -> dict[str, float]:
    """All base features for one canonical URL."""
    host, path = c.host, c.path
    hp = host_parts(host)
    text = host + path
    tokens = _tokens(text)
    dom_text = hp.domain
    brands = brand_match(c)
    n_generic_sub = count_generic_keywords(hp.subdomain)
    return {
        "len_host": len(host),
        "len_path": len(path),
        "len_subdomain": len(hp.subdomain),
        "len_domain": len(hp.domain),
        "n_dots_host": host.count("."),
        "n_hyphens_host": readable_host(host).count("-"),
        "n_digits_host": sum(ch.isdigit() for ch in host),
        "n_subdomain_levels": len([s for s in hp.subdomain.split(".") if s]),
        "path_depth": len([p for p in path.split("/") if p]),
        "n_hyphens_path": path.count("-"),
        "n_underscores_path": path.count("_"),
        "n_digits_path": sum(ch.isdigit() for ch in path),
        "n_special_path": sum(path.count(ch) for ch in _SPECIAL),
        "n_percent_path": path.count("%"),
        "digit_ratio": sum(ch.isdigit() for ch in text) / max(1, len(text)),
        "entropy_host": _entropy(host),
        "entropy_path": _entropy(path),
        "entropy_domain": _entropy(dom_text),
        "is_https": float(c.scheme == "https"),
        "has_userinfo": float(c.had_userinfo),
        "has_port": float(c.had_port),
        "is_ip_host": float(bool(_IPV4_RE.match(host) or _IPV6_RE.match(host))),
        "is_punycode": float("xn--" in host),
        "idna_failed": float(c.idna_failed),
        "double_slash_in_path": float(c.double_slash_in_path),
        "http_in_path": float(bool(_EMBEDDED_URL_RE.search(path))),
        "is_shared_platform": float(is_shared_platform(host)),
        "is_private_suffix": float(hp.is_private_suffix),
        "tld_length": len(hp.suffix),
        "ext_php": float(".php" in path),
        "ext_html": float(bool(re.search(r"\.html?($|/)", path))),
        "ext_pdf": float(path.endswith(".pdf")),
        "n_generic_keywords": count_generic_keywords(text),
        "keyword_in_subdomain": float(n_generic_sub + len(brands.in_subdomain)),
        "brand_is_domain": float(brands.is_domain),
        "brand_in_domain_label": float(len(brands.in_domain_label)),
        "brand_in_subdomain_or_path": float(len(brands.in_subdomain | brands.in_path)),
        "longest_token": max((len(t) for t in tokens), default=0),
        "n_tokens": len(tokens),
        "vowel_ratio_domain": sum(ch in _VOWELS for ch in dom_text) / max(1, len(dom_text)),
    }


class URLFeatures(BaseEstimator, TransformerMixin):
    """Transform raw URL strings into a numeric feature matrix.

    Parameters
    ----------
    tlds : tuple of str
        Top-level domains (ICANN public suffixes) that get their own one-hot column.
        Learned from the training data by scripts/prepare.py and frozen in the model.
    """

    def __init__(self, tlds: tuple[str, ...] = ()):
        self.tlds = tlds

    def fit(self, X, y=None):
        self.n_features_in_ = 1
        return self

    def get_feature_names_out(self, input_features=None):
        return np.array(BASE_FEATURES + [f"tld_{t}" for t in self.tlds] + ["tld_other"], dtype=object)

    def transform_one(self, url: str) -> np.ndarray:
        c = canonicalize(url)
        f = url_features(c)
        suffix = host_parts(c.host).suffix
        onehot = [float(suffix == t) for t in self.tlds]
        onehot.append(float(suffix not in self.tlds))
        return np.array([f[k] for k in BASE_FEATURES] + onehot, dtype=np.float32)

    def transform(self, X):
        urls = np.asarray(X, dtype=object).ravel()
        return np.vstack([self.transform_one(u) for u in urls]) if len(urls) else np.empty(
            (0, len(self.get_feature_names_out())), dtype=np.float32
        )
