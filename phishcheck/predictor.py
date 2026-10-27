"""Prediction logic for the web app (kept separate from the UI so it can be unit-tested).

The app never opens, downloads or resolves the URL: only the text of the URL is analysed.
"""
from __future__ import annotations

import ipaddress
import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path

import joblib

from .canonical import canonicalize, readable_host
from .domains import host_parts, is_shared_platform, is_shortener
from .features import brand_match, feature_code_hash, generic_keywords_found, url_features

ROOT = Path(__file__).resolve().parents[1]
MAX_LEN = 2048

BAND_HIGH, BAND_SUSPICIOUS, BAND_LOW, BAND_UNKNOWN = "Høy risiko", "Mistenkelig", "Lav risiko", "Kan ikke vurderes"

ERR_SCHEME = "Bare http- og https-lenker kan vurderes."
ERR_HOST = "Fant ikke et gyldig domenenavn i lenken."

_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):(.*)$", re.DOTALL)
_NON_WEB_SCHEMES = {
    "mailto", "tel", "sms", "javascript", "vbscript", "data", "file", "about", "intent", "blob",
    "ftp", "ftps", "sftp", "ws", "wss", "chrome", "market", "itms", "skype", "callto", "geo",
    "sip", "sips", "xmpp", "im", "irc", "ircs", "magnet", "tg", "whatsapp", "viber", "ssh",
    "telnet", "git", "svn", "ldap", "news", "nntp", "rtsp", "rtmp", "webcal", "bitcoin",
    "ethereum", "facetime", "maps", "zoommtg", "slack", "msteams", "spotify", "steam", "fax",
}
_PLAIN_LATIN = set("abcdefghijklmnopqrstuvwxyz0123456789.-_æøåäöüéèêáàâíìóòôúùñç")
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


@dataclass
class Assessment:
    band: str | None = None
    score: int | None = None          # 0-100, a risk SCORE (not a probability)
    host: str = ""
    flags: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    error: str | None = None


def refang(text: str) -> tuple[str, bool]:
    """Undo common 'defanging' used in security reports: hxxp://, [.], (.), [:]."""
    out = re.sub(r"^hxxp(s?)(\[?:\]?)//", r"http\1://", text, flags=re.IGNORECASE)
    out = out.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    return out, out != text


def _web_url_problem(url: str) -> str | None:
    """None if `url` is an http(s) URL or a scheme-less host, otherwise an error message."""
    m = _SCHEME_RE.match(url)
    if not m:
        return None
    scheme, after = m.group(1).lower(), m.group(2)
    if scheme in ("http", "https"):
        return None
    if scheme in _NON_WEB_SCHEMES or after.startswith("//"):
        return ERR_SCHEME
    if re.match(r"^\d*([/?#]|$)", after):          # 'example.com:8080/x' -> host and port
        return None
    if "@" in re.split(r"[/?#]", url, maxsplit=1)[0]:  # 'user:password@host/...'
        return None
    return ERR_SCHEME


def _valid_host(host: str) -> bool:
    if host.startswith("[") and host.endswith("]"):
        if "%" in host:  # IPv6 zone ids are not allowed in URLs (browsers reject them)
            return False
        try:
            ipaddress.IPv6Address(host[1:-1])
            return True
        except ValueError:
            return False
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        return all(int(p) <= 255 for p in host.split("."))
    labels = host.split(".")
    return (
        len(host) <= 253 and len(labels) >= 2 and all(_LABEL_RE.match(l) for l in labels)
        and not labels[-1].isdigit()
    )


def display_host(host: str) -> str:
    """Host as shown to the user. Punycode is shown as punycode (so look-alike characters are
    NOT rendered as the brand they imitate); the readable form is added only if it consists
    of plain Latin letters (e.g. Norwegian æøå)."""
    readable = readable_host(host)
    if readable != host and set(readable) <= _PLAIN_LATIN:
        return f"{host} ({readable})"
    return host


def red_flags(url: str) -> list[str]:
    """Human-readable observations about the URL (rule-based, NOT the model's reasoning).
    Every message must be factually true for the URL it is shown for."""
    c = canonicalize(url)
    f = url_features(c)
    hp = host_parts(c.host)
    brands = brand_match(c)
    out = []
    if f["is_ip_host"]:
        out.append("Lenken bruker en IP-adresse i stedet for et domenenavn.")
    if f["has_userinfo"]:
        out.append("Lenken inneholder «@» foran domenet. Nettleseren ignorerer alt før «@».")
    if f["has_port"]:
        out.append("Lenken angir et eget portnummer, noe vanlige nettsider sjelden gjør.")
    if f["is_punycode"] or f["idna_failed"]:
        out.append("Domenet inneholder tegn utenfor det engelske alfabetet. Det er vanlig for norske navn "
                   "med æ, ø og å, men brukes også til å etterligne kjente domener med like bokstaver.")
    if not f["is_https"]:
        out.append("Lenken bruker ukryptert http.")
    if brands.in_domain_label:
        out.append("Domenenavnet kombinerer et kjent merkenavn med andre ord "
                   f"(«{sorted(brands.in_domain_label)[0]}»). Ekte nettsteder bruker sjelden slike navn.")
    if brands.in_subdomain:
        out.append(f"Et kjent merkenavn («{sorted(brands.in_subdomain)[0]}») står i underdomenet, "
                   "ikke i selve domenenavnet.")
    words = generic_keywords_found(hp.subdomain)
    if words:
        out.append(f"Underdomenet inneholder ordet «{words[0]}», som ofte brukes i phishing-lenker.")
    if f["n_subdomain_levels"] >= 3:
        out.append("Lenken har mange nivåer med underdomener.")
    if readable_host(c.host).count("-") >= 3:
        out.append("Domenet inneholder mange bindestreker.")
    if f["http_in_path"] or f["double_slash_in_path"]:
        out.append("Lenken inneholder en ny adresse inni seg (mulig videresending).")
    if len(hp.subdomain) > 30:
        out.append("Uvanlig langt underdomene.")
    return out


class Predictor:
    def __init__(self, model_path: Path | None = None, metadata_path: Path | None = None):
        self.meta = json.loads((metadata_path or ROOT / "models" / "metadata.json").read_text())
        expected = self.meta.get("feature_code_hash")
        if expected != feature_code_hash():
            raise RuntimeError(
                "The feature code differs from the code the model was trained with "
                f"(model: {expected}, code: {feature_code_hash()}). Retrain the model."
            )
        self.pipe = joblib.load(model_path or ROOT / "models" / "model.joblib")
        # Thresholds are whole percentages, so the displayed score (floor of 100*score) always
        # agrees with the band.
        self.high = round(self.meta["thresholds"]["high"] * 100)
        self.low = round(self.meta["thresholds"]["low"] * 100)

    def assess(self, text: str) -> Assessment:
        url = (text or "").strip()
        if not url:
            return Assessment(error="Lim inn en lenke først.")
        if len(url) > MAX_LEN:
            return Assessment(error=f"Lenken er for lang (over {MAX_LEN} tegn).")
        if re.search(r"\s", url):
            return Assessment(error="Lim inn én lenke uten mellomrom.")
        url, defanged = refang(url)
        problem = _web_url_problem(url)
        if problem:
            return Assessment(error=problem)
        c = canonicalize(url)
        if not _valid_host(c.host):
            return Assessment(error=ERR_HOST)

        a = Assessment(host=display_host(c.host))
        if defanged:
            a.notes.append("Lenken var «defanged» (hxxp, [.]). Den er gjort om til en vanlig adresse før vurderingen.")
        if not c.had_scheme:
            a.notes.append("Lenken manglet http(s)://, så den er tolket som https.")
        if c.had_query:
            a.notes.append("Alt etter «?» eller «#» er ignorert. Treningsdataene har ikke slike "
                           "parametere for legitime lenker, så modellen kan ikke bruke dem rettferdig.")
        if is_shortener(c.host):
            a.band = BAND_UNKNOWN
            a.notes.append("Dette er en lenkeforkorter. Den skjuler hvor lenken egentlig går, så "
                           "adressen alene sier ingenting om målet. Vær forsiktig.")
            return a

        score = float(self.pipe.predict_proba([url])[0, 1])
        a.score = min(100, math.floor(score * 100 + 1e-9))
        a.band = BAND_HIGH if a.score >= self.high else BAND_SUSPICIOUS if a.score >= self.low else BAND_LOW
        a.flags = red_flags(url)
        if is_shared_platform(c.host):
            a.notes.append("Lenken ligger på en delt plattform der hvem som helst kan publisere "
                           "(for eksempel nettstedbyggere, skjema- eller dokumenttjenester). "
                           "Treningsdataene har nesten bare phishing fra slike plattformer, så "
                           "vurderingen er usikker her.")
        return a
