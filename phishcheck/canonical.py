"""URL canonicalization: the single place where raw URL strings are normalized.

Why this exists (see README, "Viktige valg om data"):
- Benign URLs in PhreshPhish never carry a query string or fragment, phishing URLs often do.
  A model would learn "has '?' => phishing", which does not hold in real use. We therefore
  drop query and fragment for every URL, in training and in the app alike.
- Cosmetic differences (trailing slash, 'www.', upper/lower case, missing scheme, default
  port, percent-encoded host, alternative IP notations) must not change the prediction. They
  are removed here so that equivalent URLs get identical features.
- The parsing follows what browsers do for http(s) URLs (WHATWG URL standard, simplified):
  a backslash counts as '/', the host ends at the first '/', '?' or '#', and 'https:host'
  or 'https:/host' mean 'https://host'. Otherwise the app could show a different host than
  the one the browser would actually open.

The same function is used by training, evaluation and the web app (no training-serving skew).
It never performs network access.
"""
from __future__ import annotations

import re
import socket
from dataclasses import dataclass
from urllib.parse import unquote

import idna

_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):(.*)$", re.DOTALL)
_AUTHORITY_RE = re.compile(r"^([^/?#]*)(.*)$", re.DOTALL)
_HOST_PORT_RE = re.compile(r"^(\[[^\]]*\]|[^:]*)(?::(\d*))?$")
_NUMERIC_HOST_RE = re.compile(r"^(0x[0-9a-f]*|\d+)(\.(0x[0-9a-f]*|\d+)){0,3}$")
_HOST_PREFIX_RE = re.compile(r"^(www\d*|m)\.")
DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class CanonicalURL:
    scheme: str          # 'http', 'https' or another scheme (other schemes are rejected by the app)
    host: str            # lower-case, IDNA (punycode) encoded, without www./m. prefix
    path: str            # lower-case, no query/fragment, no trailing '/', '' for the root
    had_scheme: bool     # False if the input had no scheme (we then assume https)
    had_userinfo: bool   # 'user@host' form, a classic obfuscation trick
    had_port: bool       # a NON-default port was given (':443' on https is not counted)
    had_query: bool      # informational only (shown in the app); never used as a feature
    idna_failed: bool    # host contained characters that could not be IDNA-encoded
    double_slash_in_path: bool

    @property
    def key(self) -> str:
        """Identity of the URL after canonicalization (used for de-duplication)."""
        return f"{self.scheme}://{self.host}{self.path}"

    @property
    def is_root(self) -> bool:
        return self.path == ""


def _encode_host(host: str) -> tuple[str, bool]:
    if host.isascii():
        return host, False
    try:
        return idna.encode(host, uts46=True).decode("ascii"), False
    except idna.IDNAError:
        try:  # e.g. a trailing ideographic full stop: map, then encode label by label
            mapped = idna.uts46_remap(host).rstrip(".")
            return idna.encode(mapped).decode("ascii"), False
        except (idna.IDNAError, UnicodeError):
            return host, True  # keep the text; the failure itself becomes a feature


def _normalize_numeric_ip(host: str) -> str:
    """'3232235777', '0x7f000001', '127.1', '0300.0250.1.1' -> dotted quad (as browsers do)."""
    if _NUMERIC_HOST_RE.match(host) and any(ch.isdigit() for ch in host):
        try:
            return socket.inet_ntoa(socket.inet_aton(host))  # pure parsing, no network access
        except OSError:
            return host
    return host


def _strip_host_prefix(host: str) -> str:
    """'www.nrk.no' -> 'nrk.no', but only if a registrable domain remains
    ('www.gov.uk' stays, because 'gov.uk' is a public suffix; 'm.co' stays)."""
    from .domains import host_parts  # local import: domains does not depend on canonical

    stripped = _HOST_PREFIX_RE.sub("", host)
    if stripped != host and host_parts(stripped).domain:
        return stripped
    return host


def canonicalize(url: str) -> CanonicalURL:
    """Normalize a raw URL string. Never performs any network access."""
    raw = (url or "").strip().replace("\\", "/")

    m = _SCHEME_RE.match(raw)
    if m and m.group(1).lower() in DEFAULT_PORTS:          # http:x, http:/x, http://x
        scheme, rest, had_scheme = m.group(1).lower(), m.group(2).lstrip("/"), True
    elif m and m.group(2).startswith("//"):                # other-scheme://...
        scheme, rest, had_scheme = m.group(1).lower(), m.group(2)[2:], True
    else:                                                  # no scheme (also 'host:port/...')
        scheme, had_scheme = "https", False
        rest = raw[2:] if raw.startswith("//") else raw   # scheme-relative '//host'

    authority, tail = _AUTHORITY_RE.match(rest).groups()
    had_query = "?" in tail or "#" in tail
    path = re.split(r"[?#]", tail, maxsplit=1)[0]

    had_userinfo = "@" in authority
    host = authority.rsplit("@", 1)[-1]
    port = None
    hp = _HOST_PORT_RE.match(host)
    if hp:
        host, port = hp.group(1), hp.group(2)
    had_port = bool(port) and int(port) != DEFAULT_PORTS.get(scheme, -1)

    host = unquote(host).lower()
    host, idna_failed = _encode_host(host)
    host = host.rstrip(".")
    host = _normalize_numeric_ip(host)
    host = _strip_host_prefix(host)

    path = path.rstrip("/")
    double_slash = "//" in path
    path = path.lower()
    return CanonicalURL(
        scheme=scheme,
        host=host,
        path=path,
        had_scheme=had_scheme,
        had_userinfo=had_userinfo,
        had_port=had_port,
        had_query=had_query,
        idna_failed=idna_failed,
        double_slash_in_path=double_slash,
    )


def readable_host(host: str) -> str:
    """Punycode host decoded back to Unicode for display/counting ('xn--blbr-roa1f.no' -> 'blåbær.no')."""
    if "xn--" not in host:
        return host
    try:
        return idna.decode(host)
    except (idna.IDNAError, UnicodeError):
        return host


def path_prefixes(c: CanonicalURL) -> list[str]:
    """All proper prefixes of the URL path, as canonical keys (root included).

    'https://a.com/x/y/z' -> ['https://a.com', 'https://a.com/x', 'https://a.com/x/y']
    Used for data augmentation of benign URLs (see phishcheck/augment.py).
    """
    segments = [s for s in c.path.split("/") if s]
    base = f"{c.scheme}://{c.host}"
    return [base + "".join("/" + s for s in segments[:k]) for k in range(len(segments))]
