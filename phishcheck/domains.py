"""Domain helpers built on the Public Suffix List (tldextract, bundled snapshot, no network)."""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

import tldextract

from .vocab import HOST_GROUPED_DOMAINS, SHARED_PLATFORM_DOMAINS, SHARED_PLATFORM_HOSTS, URL_SHORTENERS

# suffix_list_urls=() -> use the PSL snapshot bundled with the pinned tldextract version.
# cache_dir=False -> never write a cache file (read-only file systems on hosting platforms).
_ICANN = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=False, include_psl_private_domains=False)
_PRIVATE = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=False, include_psl_private_domains=True)


@dataclass(frozen=True)
class HostParts:
    subdomain: str        # e.g. 'secure-login' for secure-login.example.co.uk
    domain: str           # 'example'
    suffix: str           # ICANN public suffix, 'co.uk'
    registrable: str      # 'example.co.uk' (ICANN), or the host itself if none
    registrable_private: str  # same, but private PSL entries count as suffixes (user.github.io)
    is_private_suffix: bool   # host sits under a private PSL suffix such as github.io


@lru_cache(maxsize=500_000)
def host_parts(host: str) -> HostParts:
    e = _ICANN(host)
    p = _PRIVATE(host)
    registrable = e.top_domain_under_public_suffix or host
    registrable_private = p.top_domain_under_public_suffix or registrable
    return HostParts(
        subdomain=e.subdomain,
        domain=e.domain,
        suffix=e.suffix,
        registrable=registrable,
        registrable_private=registrable_private,
        is_private_suffix=p.suffix != e.suffix,
    )


def is_shared_platform(host: str) -> bool:
    """True if anyone can publish content on this host (site builders, hosting, forms...)."""
    hp = host_parts(host)
    return (
        host in SHARED_PLATFORM_HOSTS
        or hp.registrable in SHARED_PLATFORM_DOMAINS
        or hp.registrable_private in SHARED_PLATFORM_DOMAINS
        or hp.is_private_suffix
    )


def is_shortener(host: str) -> bool:
    """Link shorteners / deep-link redirectors. Matches the service itself and its sub-domains
    (e.g. 'acme.app.link', 'x.page.link')."""
    return any(host == s or host.endswith("." + s) for s in URL_SHORTENERS)


def group_key(host: str) -> str:
    """Group id for cross-validation (GroupKFold) to prevent leakage between folds.

    URLs from the same site must stay in the same fold, otherwise the model is rewarded for
    memorising sites instead of learning patterns. A 'site' is the registrable domain, except on
    shared platforms and large multi-service domains, where each hostname is a separate site.
    """
    hp = host_parts(host)
    if (
        host in SHARED_PLATFORM_HOSTS
        or hp.registrable in SHARED_PLATFORM_DOMAINS
        or hp.registrable in HOST_GROUPED_DOMAINS
    ):
        return host
    return hp.registrable_private
