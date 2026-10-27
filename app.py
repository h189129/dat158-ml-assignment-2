"""Phishing-lenkesjekk: Gradio web app (DAT158, ML assignment 2).

Run locally:  python app.py   -> http://127.0.0.1:7860
The app never opens or downloads the URL that is checked; only the URL text is analysed.
"""
from __future__ import annotations

import hashlib
import html
import json
import re
from pathlib import Path

import gradio as gr

from phishcheck.canonical import canonicalize
from phishcheck.domains import host_parts, is_shared_platform
from phishcheck.predictor import (
    BAND_HIGH, BAND_LOW, BAND_SUSPICIOUS, BAND_UNKNOWN, Assessment, Predictor, display_host, refang,
)

ROOT = Path(__file__).resolve().parent
predictor = Predictor()
# Warm-up: the first prediction loads the Public Suffix List and initialises scikit-learn.
# Doing it at start-up keeps the first real user request fast.
predictor.assess("https://www.example.com/")
T_LOW, T_HIGH = predictor.low, predictor.high

BAND_CLASS = {BAND_HIGH: "high", BAND_SUSPICIOUS: "mid", BAND_LOW: "low", BAND_UNKNOWN: "unknown"}
SUMMARY = {
    BAND_HIGH: "Adressen ligner sterkt på phishing-lenker. Ikke åpne den, og ikke oppgi passord, "
               "BankID eller kortinformasjon.",
    BAND_SUSPICIOUS: "Adressen har trekk som er vanlige i phishing. Sjekk hvem som sendte lenken før du åpner den.",
    BAND_LOW: "Modellen fant få trekk som er typiske for phishing. Det betyr ikke at lenken er trygg, "
              "så vær fortsatt kritisk til uventede meldinger.",
    BAND_UNKNOWN: "Denne lenken kan ikke vurderes ut fra adressen alene.",
}

# Inline SVG icons (decorative; the band name is always shown as text next to them).
_SVG = '<svg viewBox="0 0 24 24" width="28" height="28" aria-hidden="true" focusable="false" fill="none" ' \
       'stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">{}</svg>'
ICONS = {
    "high": _SVG.format('<path d="M12 3 2.5 20h19L12 3z"/><path d="M12 10v4.5"/><path d="M12 17.5h.01"/>'),
    "mid": _SVG.format('<circle cx="12" cy="12" r="9.5"/><path d="M12 7.5v5.5"/><path d="M12 16.5h.01"/>'),
    "low": _SVG.format('<circle cx="12" cy="12" r="9.5"/><path d="m8 12.5 2.8 2.8L16.5 9.5"/>'),
    "unknown": _SVG.format('<circle cx="12" cy="12" r="9.5"/><path d="M9.6 9.3a2.6 2.6 0 1 1 3.4 2.5c-.6.3-1 .8-1 1.5v.4"/>'
                           '<path d="M12 17h.01"/>'),
    "error": _SVG.format('<circle cx="12" cy="12" r="9.5"/><path d="m15 9-6 6M9 9l6 6"/>'),
}

EXAMPLES_SAFE = [
    ("NRK nyheter", "https://www.nrk.no/nyheter/"),
    ("HVL studier", "https://www.hvl.no/studier/"),
]
EXAMPLES_PHISH = [  # constructed examples (not real links)
    ("Falsk DNB-innlogging", "http://secure-dnb-login.verify-account.xyz/bankid"),
    ("Vipps-svindel på nettstedbygger", "https://vipps-refund-claim.webflow.io/"),
    ("IP-adresse i stedet for domene", "http://192.168.10.5/posten/tracking.php"),
    ("Etterlignet PayPal", "https://xn--pypal-4ve.com/signin"),
    ("Lenkeforkorter", "bit.ly/3abcXYZ"),
]

ERROR_HELP = {
    "Bare http- og https-lenker kan vurderes.":
        "Lenker til telefon, e-post, apper eller filer kan ikke sjekkes her. Lim inn en nettadresse, "
        "for eksempel https://www.nrk.no/nyheter/",
    "Lim inn én lenke uten mellomrom.":
        "Fjern mellomrom og tekst rundt lenken, og lim inn én adresse om gangen.",
}

EMPTY_STATE = (
    "<div class='pc-empty'><p><strong>Resultatet vises her.</strong></p>"
    "<p>Tips: Ikke klikk på en mistenkelig lenke for å kopiere den. Trykk og hold (mobil) eller "
    "høyreklikk (PC) og velg «Kopier lenkeadresse».</p></div>"
)


def _e(s: str) -> str:
    return html.escape(s, quote=True)


def _url(s: str) -> str:
    """Escaped URL fragment with soft line-break opportunities after '.', '/' and '-'."""
    return re.sub(r"([./-])", r"\1<wbr>", _e(s))


def anatomy(text: str) -> str:
    """The URL split into parts with the owning domain emphasised (never a clickable link)."""
    c = canonicalize(refang(text.strip())[0])
    hp = host_parts(c.host)
    owner = hp.registrable_private if is_shared_platform(c.host) else hp.registrable
    if c.host.startswith("[") or hp.domain == "":  # IP addresses and hosts without a public suffix
        owner = c.host
    prefix = c.host[: len(c.host) - len(owner)] if c.host.endswith(owner) else ""
    owner_shown = display_host(owner)
    url = (f"<span class='pc-dim'>{_e(c.scheme)}://<wbr></span>"
           f"<span class='pc-dim'>{_url(prefix)}</span>"
           f"<span class='pc-owner'>{_url(owner)}</span>"
           f"<span class='pc-dim'>{_url(c.path)}</span>")
    if owner == c.host and (c.host[0].isdigit() or c.host.startswith("[")):
        hint = "Uten et domenenavn finnes det ingen synlig eier av adressen."
    elif is_shared_platform(c.host):
        hint = (f"Siden ligger på plattformen <strong>{_e(hp.registrable)}</strong>, der hvem som helst kan "
                f"publisere. Navnet <strong>{_e(owner_shown)}</strong> er valgt av den som laget siden.")
    elif prefix:
        hint = (f"Det er <strong>{_e(owner_shown)}</strong> som eier denne adressen. "
                f"Alt foran er underdomener som eieren selv har valgt.")
    else:
        hint = f"Domenet som eier adressen er <strong>{_e(owner_shown)}</strong>."
    return (f"<div class='pc-anatomy'><p class='pc-sub'>Adressen slik den ble vurdert</p>"
            f"<p class='pc-url' translate='no'>{url}</p><p class='pc-hint'>{hint}</p></div>")


def scale(score: int) -> str:
    pos = max(0.0, min(100.0, float(score)))
    return (
        f"<div class='pc-scale' role='img' aria-label='Risikoscore {score} av 100. Mistenkelig fra {T_LOW}, "
        f"høy risiko fra {T_HIGH}.'>"
        f"<div class='pc-track'><span class='pc-seg low' style='width:{T_LOW}%'></span>"
        f"<span class='pc-seg mid' style='width:{T_HIGH - T_LOW}%'></span>"
        f"<span class='pc-seg high' style='width:{100 - T_HIGH}%'></span>"
        f"<span class='pc-marker' style='left:{pos}%'></span></div>"
        f"<div class='pc-ticks' aria-hidden='true'><span style='left:0%'>0</span>"
        f"<span style='left:{T_LOW}%'>{T_LOW}</span><span style='left:{T_HIGH}%'>{T_HIGH}</span>"
        f"<span style='left:100%'>100</span></div></div>"
    )


def render(text: str) -> str:
    a: Assessment = predictor.assess(text)
    if a.error:
        if not (text or "").strip():
            return EMPTY_STATE
        help_text = ERROR_HELP.get(a.error, "Eksempel på en gyldig lenke: https://www.nrk.no/nyheter/")
        return (f"<section class='pc-result error' role='alert'><div class='pc-head'>"
                f"<span class='pc-icon'>{ICONS['error']}</span><h2 class='pc-band'>{_e(a.error)}</h2></div>"
                f"<p class='pc-summary'>{_e(help_text)}</p></section>")
    cls = BAND_CLASS[a.band]
    parts = [f"<section class='pc-result {cls}' role='status' aria-live='polite'>",
             f"<div class='pc-head'><span class='pc-icon'>{ICONS[cls]}</span>",
             f"<h2 class='pc-band'>{_e(a.band)}</h2>"]
    if a.score is not None:
        parts.append(f"<span class='pc-score'><strong>{a.score}</strong> av 100</span>")
    parts.append("</div>")
    if a.score is not None:
        parts.append(scale(a.score))
    parts.append(f"<p class='pc-summary'>{_e(SUMMARY[a.band])}</p>")
    parts.append(anatomy(text))
    if a.flags:
        parts.append("<h3>Dette la vi merke til i adressen</h3><ul class='pc-list'>")
        parts += [f"<li>{_e(f)}</li>" for f in a.flags]
        parts.append("</ul><p class='pc-fine'>Observasjonene er enkle regler som forklarer adressen. "
                     "De er ikke modellens begrunnelse.</p>")
    if a.notes:
        parts.append("<h3>Godt å vite</h3><ul class='pc-list'>")
        parts += [f"<li>{_e(n)}</li>" for n in a.notes]
        parts.append("</ul>")
    parts.append("</section>")
    return "".join(parts)


FEATURE_LABELS = {
    "len_host": "Lengden på domenenavnet", "len_path": "Lengden på stien", "len_subdomain": "Lengden på underdomenet",
    "n_dots_host": "Antall punktum i domenenavnet", "n_hyphens_host": "Bindestreker i domenenavnet",
    "n_digits_host": "Siffer i domenenavnet", "n_subdomain_levels": "Antall nivåer med underdomener",
    "path_depth": "Antall nivåer i stien", "n_hyphens_path": "Bindestreker i stien", "n_underscores_path": "Understreker i stien",
    "n_digits_path": "Siffer i stien", "n_special_path": "Spesialtegn i stien", "n_percent_path": "Prosentkoding i stien",
    "digit_ratio": "Andel siffer i adressen", "entropy_host": "Hvor tilfeldig domenenavnet ser ut",
    "entropy_path": "Hvor tilfeldig stien ser ut", "is_https": "Bruker https", "has_userinfo": "«@» foran domenet",
    "has_port": "Eget portnummer", "is_ip_host": "IP-adresse i stedet for domene", "is_punycode": "Spesialtegn (punycode)",
    "idna_failed": "Ugyldige tegn i domenet", "double_slash_in_path": "Dobbel skråstrek i stien",
    "http_in_path": "Ny adresse inni stien", "is_shared_platform": "Delt plattform (nettstedbygger o.l.)",
    "is_private_suffix": "Underdomene hos en tjenesteleverandør", "tld_length": "Lengden på toppdomenet",
    "ext_php": "Stien ender på .php", "ext_html": "Stien ender på .html", "ext_pdf": "Stien ender på .pdf",
    "n_generic_keywords": "Ord som «login» og «verify»", "keyword_in_subdomain": "Slike ord i underdomenet",
    "brand_is_domain": "Domenet er et kjent merkenavn", "brand_in_domain_label": "Merkenavn kombinert med andre ord",
    "brand_in_subdomain_or_path": "Merkenavn i underdomenet eller stien", "longest_token": "Lengste ord i adressen",
    "n_tokens": "Antall ord og tall i adressen", "vowel_ratio_domain": "Andel vokaler i domenenavnet",
    "tld_other": "Sjeldent toppdomene",
}


def _feature_label(name: str) -> str:
    if name.startswith("tld_") and name != "tld_other":
        return f"Toppdomenet .{name[4:]}"
    return FEATURE_LABELS.get(name, name)


def _int_no(n: int) -> str:
    return f"{n:,}".replace(",", "\u00a0")


def confusion_html(h: dict) -> str:
    """Confusion matrix at the 'high risk' threshold as an accessible HTML table."""
    return (
        "<table class='pc-cm'><caption>Testdata, terskel «Høy risiko»</caption>"
        "<thead><tr><th scope='col'></th><th scope='col'>Vurdert: Høy risiko</th>"
        "<th scope='col'>Vurdert: ikke Høy risiko</th></tr></thead><tbody>"
        f"<tr><th scope='row'>Faktisk phishing</th><td class='ok'>{_int_no(h['tp'])}<small>fanget</small></td>"
        f"<td class='bad'>{_int_no(h['fn'])}<small>sluppet gjennom</small></td></tr>"
        f"<tr><th scope='row'>Faktisk legitim</th><td class='bad'>{_int_no(h['fp'])}<small>falsk alarm</small></td>"
        f"<td class='ok'>{_int_no(h['tn'])}<small>riktig sluppet</small></td></tr></tbody></table>"
    )


def importance_html(rows: list[dict], top: int = 10) -> str:
    """Permutation importance as labelled bars (relative to the most important feature)."""
    rows = rows[:top]
    mx = max(r["mean"] for r in rows) or 1.0
    items = "".join(
        f"<li><span class='pc-imp-label'>{_e(_feature_label(r['feature']))}</span>"
        f"<span class='pc-imp-bar' style='width:{max(2.0, 100 * r['mean'] / mx):.1f}%'></span></li>"
        for r in rows)
    return (f"<p class='pc-sub'>De {top} viktigste kjennetegnene på valideringsdata, målt med permutation "
            f"importance (hvor mye ROC-AUC faller når kjennetegnet stokkes). Lengre stolpe betyr viktigere.</p>"
            f"<ol class='pc-imp'>{items}</ol>")


def _no(x: float, decimals: int) -> str:
    """Norwegian number format: decimal comma."""
    return f"{x:.{decimals}f}".replace(".", ",")


MODEL_NAMES = {
    "hist_gradient_boosting": "gradient boosting med beslutningstrær",
    "random_forest": "random forest",
    "logistic_regression": "logistisk regresjon",
}
# Set to the public GitHub URL once the repo is pushed; the About tab links to it when set.
REPO_URL = "https://github.com/h189129/dat158-ml-assignment-2"


def about_markdown() -> str:
    meta = predictor.meta
    lines = [
        "### Modellen",
        f"- Modelltype: **{MODEL_NAMES.get(meta['model'], meta['model'])}** "
        f"(scikit-learn {meta['versions']['scikit-learn']}).",
        "- Input: kun teksten i URL-en. Rundt 40 leksikalske kjennetegn (lengder, tegn, underdomener, "
        "toppdomene, nøkkelord og merkenavn), beregnet etter at adressen er normalisert.",
        f"- Trent på {format(meta['training_rows'], ',').replace(',', ' ')} URL-er fra datasettet PhreshPhish "
        "(juli 2024 – juni 2025), inkludert utvidede legitime eksempler (forsider og korte stier).",
        f"- Terskler: *Høy risiko* fra score {T_HIGH} (høyst 1 % falske alarmer) og "
        f"*Mistenkelig* fra score {T_LOW} (høyst 5 % falske alarmer) blant "
        "legitime lenker i valideringsdataene.",
    ]
    m_path = ROOT / "reports" / "test_metrics.json"
    m = json.loads(m_path.read_text()) if m_path.exists() else None
    # Only show test results that belong to the loaded model.
    model_sha = hashlib.sha256((ROOT / "models" / "model.joblib").read_bytes()).hexdigest()
    if m and m.get("model_sha256") == model_sha == meta.get("model_sha256") and m.get("thresholds") == meta["thresholds"]:
        t = m["test"]
        h = t["at_t_high"]
        lines += [
            "",
            "### Resultater på testdata",
            "September – desember 2025. Ikke brukt til trening, modellvalg eller terskler.",
            "",
            "| Mål | Verdi |", "|---|---|",
            f"| ROC-AUC | {_no(t['roc_auc'], 3)} |",
            f"| Andel phishing som får *Høy risiko* (recall) | {_no(h['recall'] * 100, 1)} % |",
            f"| Andel legitime som får *Høy risiko* (FPR) | {_no(h['fpr'] * 100, 1)} % |",
            f"| Presisjon når 5 % av lenkene er phishing | {_no(m['benchmarks']['5%']['precision_mean'] * 100, 0)} % |",
            f"| Presisjon når 1 % av lenkene er phishing | {_no(m['benchmarks']['1%']['precision_mean'] * 100, 0)} % |",
            "",
            "Presisjonen faller når phishing er sjeldent. Selv få falske alarmer blir mange når nesten "
            "alle lenker er legitime.",
        ]
    lines += [
        "",
        "### Begrensninger",
        "- Modellen ser bare adressen. Phishing på **kompromitterte, ekte nettsteder** (for eksempel "
        "falske PDF-er lastet opp på offentlige nettsteder) er i praksis usynlig.",
        "- **Delte plattformer** (nettstedbyggere, Google Docs/Forms o.l.) har nesten bare phishing i "
        "treningsdataene. Legitime sider der kan få for høy score.",
        "- **Norske nettsteder** er sjeldne i dataene. Vurderingen er derfor mindre sikker for .no-adresser.",
        "- Ukryptert **http** gir høy score, fordi nesten alle legitime lenker i dataene bruker https.",
        "- **Korte domenenavn med tall** (for eksempel tv2.no) kan få for høy score.",
        "- Domener med **etterlignede bokstaver** (punycode) får ikke alltid *Høy risiko*. Se etter «xn--» i domenet.",
        "- **Lenkeforkortere** kan ikke vurderes. Adressen skjuler målet.",
        "- Phishing endrer seg raskt. Modellen må trenes på nytt med nye data for å holde følge.",
        "",
        "### Personvern",
        "Appen åpner aldri lenken, og vi lagrer ikke det du limer inn. Teksten sendes likevel via "
        "Hugging Face sine servere. Ikke lim inn lenker som inneholder innloggingskoder eller "
        "personlige opplysninger.",
        "",
        "### Kilder",
        "Data: *PhreshPhish* (Dalton mfl., 2025), CC BY 4.0, "
        "[huggingface.co/datasets/phreshphish/phreshphish](https://huggingface.co/datasets/phreshphish/phreshphish). "
        "Kun URL-feltet er brukt."
        + (f" Kode og dokumentasjon: [GitHub-repoet]({REPO_URL})." if REPO_URL else ""),
    ]
    return "\n".join(lines)


SCROLL_TO_RESULT = """() => {
  const el = document.querySelector('#pc-out');
  if (!el) return;
  const r = el.getBoundingClientRect();
  if (r.top > window.innerHeight * 0.6 || r.top < 0) {
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    el.scrollIntoView({behavior: reduce ? 'auto' : 'smooth', block: 'start'});
  }
}"""

THEME = gr.themes.Base(
    primary_hue=gr.themes.colors.cyan,
    neutral_hue=gr.themes.colors.slate,
    font=[gr.themes.GoogleFont("Public Sans"), "system-ui", "Segoe UI", "sans-serif"],
    font_mono=[gr.themes.GoogleFont("JetBrains Mono"), "ui-monospace", "Consolas", "monospace"],
    radius_size=gr.themes.sizes.radius_md,
).set(
    body_background_fill="#F4F6F8",
    body_background_fill_dark="#0E1419",
    body_text_color="#1C2430",
    body_text_color_dark="#E6EBF0",
    block_background_fill="#FFFFFF",
    block_background_fill_dark="#161E25",
    block_border_width="1px",
    block_shadow="none",
    input_background_fill="#FFFFFF",
    input_background_fill_dark="#0E1419",
    input_border_color_focus="#0F4C5C",
    input_border_color_focus_dark="#6FC3D6",
    button_primary_background_fill="#0F4C5C",
    button_primary_background_fill_hover="#0B3A46",
    button_primary_background_fill_dark="#6FC3D6",
    button_primary_background_fill_hover_dark="#8FD3E2",
    button_primary_text_color="#FFFFFF",
    button_primary_text_color_dark="#0E1419",
    button_secondary_background_fill="#FFFFFF",
    button_secondary_background_fill_hover="#EAF2F4",
    button_secondary_background_fill_dark="#161E25",
    button_secondary_background_fill_hover_dark="#1F2A33",
    link_text_color="#0F4C5C",
    link_text_color_dark="#6FC3D6",
)

CSS = """
.gradio-container { max-width: 760px !important; margin: 0 auto !important; padding: 0 16px !important; }
.gradio-container .main { padding-left: 0 !important; padding-right: 0 !important; }
:root, .light {
  --pc-ink: #1C2430; --pc-muted: #5B6675; --pc-line: #D9DFE5; --pc-surface: #FFFFFF;
  --pc-high: #B42318; --pc-high-bg: #FEF3F2; --pc-mid: #B54708; --pc-mid-bg: #FFFAEB;
  --pc-low: #067647; --pc-low-bg: #ECFDF3; --pc-unknown: #475467; --pc-unknown-bg: #F2F4F7;
  --pc-owner-bg: #E3EEF1; --pc-owner: #0F4C5C;
}
.dark {
  --pc-ink: #E6EBF0; --pc-muted: #9AA6B2; --pc-line: #2A3540; --pc-surface: #161E25;
  --pc-high: #FDA29B; --pc-high-bg: #3A1714; --pc-mid: #FEC84B; --pc-mid-bg: #3A2A0E;
  --pc-low: #75E0A7; --pc-low-bg: #0F2E21; --pc-unknown: #CDD5DF; --pc-unknown-bg: #222B33;
  --pc-owner-bg: #12343D; --pc-owner: #9BDCEB;
}
#pc-header h1 { font-size: clamp(1.7rem, 4.5vw, 2.2rem); font-weight: 700; letter-spacing: -0.01em; margin: 28px 0 6px; }
#pc-header p { color: var(--pc-muted); font-size: 1.02rem; line-height: 1.5; margin: 0 0 4px; max-width: 62ch; }
#pc-input textarea, #pc-input input { font-family: var(--font-mono); font-size: 1rem; font-variant-ligatures: none; }
#pc-check { min-height: 44px; border-radius: 8px !important; }
#pc-input { border: 1px solid var(--pc-line) !important; border-radius: 8px !important; background: var(--pc-surface) !important; }
#pc-input:focus-within { border-color: var(--pc-owner) !important; box-shadow: 0 0 0 3px var(--pc-owner-bg) !important; }
.pc-examples-label p { font-size: .88rem; color: var(--pc-muted); margin: 10px 0 2px; }
.pc-chips { flex-wrap: wrap !important; gap: 8px !important; }
.pc-chips > button, .pc-chips button.pc-example { flex: 0 0 auto !important; width: auto !important; min-width: 0 !important;
  white-space: nowrap; font-weight: 500 !important; font-size: .88rem !important; min-height: 38px; padding: 0 14px !important;
  border: 1px solid var(--pc-line) !important; border-radius: 999px !important; box-shadow: none !important; }
.pc-chips button.pc-example:hover { border-color: var(--pc-owner) !important; }
.pc-chips button.pc-example:focus-visible, #pc-check:focus-visible { outline: 3px solid var(--pc-owner) !important; outline-offset: 2px; }
#pc-out { padding: 0 !important; margin-top: 8px; }
#pc-out .html-container { padding: 0 !important; }
button[role="tab"][aria-selected="true"] { color: var(--pc-owner) !important; border-color: var(--pc-owner) !important; font-weight: 600; }
button[role="tab"] { font-size: .98rem !important; }
#pc-about, #pc-about-bottom { font-size: .95rem; line-height: 1.55; }
#pc-about :is(p, li), #pc-about-bottom :is(p, li) { font-size: .95rem !important; line-height: 1.55 !important; }
#pc-about h3, #pc-about-bottom h3, .pc-about-h { font-size: 1.1rem !important; font-weight: 700 !important;
  line-height: 1.3 !important; margin: 28px 0 8px !important; color: var(--pc-ink); }
#pc-about h3:first-child { margin-top: 20px !important; }
#pc-about-bottom h3:first-child, .pc-about-h { margin-top: 12px !important; }
#pc-about td { font-size: .95rem !important; }
#pc-about h3 + p, #pc-about-bottom h3 + p { margin-top: 0 !important; }
#pc-about ul, #pc-about-bottom ul, .pc-list { list-style: disc !important; padding-left: 1.25em !important; }
#pc-about li, #pc-about-bottom li { margin: 4px 0 !important; }
#pc-about li::marker, #pc-about-bottom li::marker, .pc-list li::marker { color: var(--pc-muted); }
#pc-about table { width: 100%; border-collapse: collapse !important; border: 0 !important; margin: 8px 0 12px !important; }
#pc-about :is(th, td) { border: 1px solid var(--pc-line) !important; padding: 10px 12px !important;
  background: var(--pc-surface) !important; color: var(--pc-ink); }
#pc-about thead th { font-weight: 600; font-size: .88rem !important; color: var(--pc-muted) !important; }
#pc-about td:last-child, #pc-about th:last-child { white-space: nowrap; text-align: right; font-variant-numeric: tabular-nums; }
#pc-about-bottom { margin-top: 4px; }
footer .divider { display: none !important; }
.pc-nw { white-space: nowrap; color: inherit !important; }
.pc-result { border: 1px solid var(--pc-line); border-left-width: 6px; border-radius: 10px; padding: 18px 20px;
  background: var(--pc-surface); color: var(--pc-ink); }
.pc-result.high { border-left-color: var(--pc-high); } .pc-result.mid { border-left-color: var(--pc-mid); }
.pc-result.low { border-left-color: var(--pc-low); } .pc-result.unknown, .pc-result.error { border-left-color: var(--pc-unknown); }
.pc-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.pc-icon { display: inline-flex; width: 40px; height: 40px; border-radius: 999px; align-items: center; justify-content: center; flex: none; }
.high .pc-icon { color: var(--pc-high); background: var(--pc-high-bg); } .mid .pc-icon { color: var(--pc-mid); background: var(--pc-mid-bg); }
.low .pc-icon { color: var(--pc-low); background: var(--pc-low-bg); }
.unknown .pc-icon, .error .pc-icon { color: var(--pc-unknown); background: var(--pc-unknown-bg); }
.pc-band { font-size: 1.45rem !important; font-weight: 700; margin: 0 !important; line-height: 1.2; flex: 1 1 0; min-width: 0; }
.high .pc-band { color: var(--pc-high); } .mid .pc-band { color: var(--pc-mid); } .low .pc-band { color: var(--pc-low); }
.error .pc-band { font-size: 1.1rem !important; color: var(--pc-ink); }
.pc-score { color: var(--pc-muted); font-size: .95rem; white-space: nowrap; }
.pc-score strong { color: var(--pc-ink); font-size: 1.35rem; font-variant-numeric: tabular-nums; }
.pc-scale { margin: 14px 0 22px; position: relative; }
.pc-track { position: relative; display: flex; height: 10px; border-radius: 999px; overflow: visible; }
.pc-seg { height: 100%; opacity: .85; }
.pc-seg.low { background: var(--pc-low); border-radius: 999px 0 0 999px; }
.pc-seg.mid { background: var(--pc-mid); } .pc-seg.high { background: var(--pc-high); border-radius: 0 999px 999px 0; }
.pc-marker { position: absolute; top: 50%; width: 18px; height: 18px; border-radius: 999px; transform: translate(-50%, -50%);
  background: var(--pc-surface); border: 3px solid var(--pc-ink); box-shadow: 0 0 0 2px var(--pc-surface); }
.pc-ticks { position: relative; height: 16px; margin-top: 6px; font-size: .75rem; color: var(--pc-muted); font-variant-numeric: tabular-nums; }
.pc-ticks span { position: absolute; transform: translateX(-50%); }
.pc-ticks span:first-child { transform: none; } .pc-ticks span:last-child { transform: translateX(-100%); }
.pc-summary { font-size: 1.02rem; line-height: 1.55; margin: 0 0 14px; max-width: 65ch; }
.pc-anatomy { border-top: 1px solid var(--pc-line); padding-top: 14px; margin-top: 4px; }
.pc-sub { font-size: .88rem; line-height: 1.5; color: var(--pc-muted); margin: 0 0 8px; }
.pc-url { font-family: var(--font-mono); font-size: .98rem; line-height: 1.7; margin: 0 0 8px; overflow-wrap: anywhere;
  font-variant-ligatures: none; font-feature-settings: "calt" 0, "liga" 0; }
.pc-dim { color: var(--pc-muted); }
.pc-owner { color: var(--pc-owner); background: var(--pc-owner-bg); font-weight: 700; border-radius: 3px;
  box-shadow: 0 0 0 2px var(--pc-owner-bg); -webkit-box-decoration-break: clone; box-decoration-break: clone; }
.pc-hint { font-size: .95rem; line-height: 1.5; margin: 0; max-width: 65ch; }
.pc-result h3 { font-size: 1rem !important; font-weight: 700; margin: 18px 0 6px !important; }
.pc-list { margin: 0 !important; padding-left: 1.2em !important; line-height: 1.5; }
.pc-list li { margin: 4px 0; }
.pc-fine { font-size: .82rem; color: var(--pc-muted); margin: 8px 0 0; }
.pc-empty { border: 1px dashed var(--pc-line); border-radius: 10px; padding: 16px 20px; color: var(--pc-muted); line-height: 1.5; }
.pc-empty p { margin: 0 0 6px; } .pc-empty p:last-child { margin: 0; }
#pc-footer p { font-size: .8rem; color: var(--pc-muted); margin: 18px 0 8px; }
@media (max-width: 520px) {
  .pc-result { padding: 14px 14px; }
  .pc-band { font-size: 1.25rem !important; }
  .pc-score { width: 100%; padding-left: 50px; margin-top: -6px; }
}
@media (prefers-reduced-motion: reduce) { * { transition: none !important; animation: none !important; } }

.pc-head + .pc-summary { margin-top: 12px; }
.pc-about-block, .pc-about-block .html-container { padding: 0 !important; }
.pc-cm { width: 100%; border-collapse: collapse; font-variant-numeric: tabular-nums; table-layout: fixed; }
.pc-cm caption { text-align: left; color: var(--pc-muted); font-size: .88rem; padding-bottom: 8px; }
.pc-cm th, .pc-cm td { border: 1px solid var(--pc-line); padding: 10px 12px; text-align: left; vertical-align: top; }
.pc-cm thead th { font-weight: 600; font-size: .88rem; color: var(--pc-muted); }
.pc-cm tbody th { font-weight: 600; font-size: .92rem; }
.pc-cm td { font-size: 1.15rem; font-weight: 700; }
.pc-cm td small { display: block; font-size: .78rem; font-weight: 400; color: var(--pc-muted); }
.pc-cm td.ok { background: var(--pc-low-bg); } .pc-cm td.bad { background: var(--pc-high-bg); }
.pc-imp { list-style: none; margin: 0 !important; padding: 0 !important; }
.pc-imp li { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); align-items: center; gap: 12px; margin: 6px 0; }
.pc-imp-label { font-size: .95rem; line-height: 1.35; }
.pc-imp-bar { display: block; height: 12px; border-radius: 3px; background: var(--pc-owner); opacity: .85; }
@media (max-width: 520px) {
  .pc-imp li { grid-template-columns: 1fr; gap: 3px; margin: 10px 0; }
  .pc-cm th, .pc-cm td { padding: 8px; }
  .pc-cm thead th { font-size: .78rem; }
}
"""

with gr.Blocks(title="Phishing-lenkesjekk", analytics_enabled=False) as demo:
    gr.Markdown(
        "# Phishing-lenkesjekk\n"
        "Fikk du en lenke i en SMS eller <span class='pc-nw'>e-post</span>? Lim den inn, så vurderer en maskinlæringsmodell "
        "adressen. Lenken blir aldri åpnet.",
        elem_id="pc-header",
    )
    with gr.Tab("Sjekk lenke"):
        with gr.Row(equal_height=True):
            inp = gr.Textbox(
                label="Lenke", show_label=False, placeholder="Lim inn lenken her",
                max_length=2048, lines=1, max_lines=1, scale=5, min_width=240, container=False,
                elem_id="pc-input", autofocus=False,
                html_attributes=gr.InputHTMLAttributes(autocapitalize="off", autocorrect="off", spellcheck=False,
                                                       autocomplete="off", enterkeyhint="go", lang="en"),
            )
            btn = gr.Button("Sjekk lenke", variant="primary", scale=1, min_width=130, elem_id="pc-check")
        example_buttons = []
        for group, items in [("Prøv ekte nettsteder", EXAMPLES_SAFE),
                             ("Prøv oppdiktede phishing-lenker (fører ingen steder)", EXAMPLES_PHISH)]:
            gr.Markdown(group, elem_classes=["pc-examples-label"])
            with gr.Row(elem_classes=["pc-chips"]):
                for label, url in items:
                    example_buttons.append((gr.Button(label, size="sm", variant="secondary", min_width=0,
                                                      scale=0, elem_classes=["pc-example"]), url))
        out = gr.HTML(EMPTY_STATE, elem_id="pc-out")
        events = [btn.click(render, inputs=inp, outputs=out, api_visibility="private"),
                  inp.submit(render, inputs=inp, outputs=out, api_visibility="private")]
        for b, url in example_buttons:
            events.append(b.click(lambda u=url: (u, render(u)), inputs=None, outputs=[inp, out],
                                  api_visibility="private"))
        for ev in events:  # bring the result into view when it is below the fold (mainly on phones)
            ev.then(None, None, None, js=SCROLL_TO_RESULT, api_visibility="private")
    with gr.Tab("Om modellen"):
        _about_top, _about_bottom = about_markdown().split("\n### Begrensninger", 1)
        gr.Markdown(_about_top, elem_id="pc-about")
        _tm = ROOT / "reports" / "test_metrics.json"
        _va = ROOT / "reports" / "val_analysis.json"
        _model_sha = hashlib.sha256((ROOT / "models" / "model.joblib").read_bytes()).hexdigest()
        if _tm.exists():
            _m = json.loads(_tm.read_text())
            if _m.get("model_sha256") == _model_sha:
                gr.HTML("<h3 class='pc-about-h'>Forvekslingsmatrise</h3>" + confusion_html(_m["test"]["at_t_high"]),
                        elem_classes=["pc-about-block"])
        if _va.exists():
            _v = json.loads(_va.read_text())
            if _v.get("model") == predictor.meta["model"] and "permutation_importance_top20" in _v:
                gr.HTML("<h3 class='pc-about-h'>Viktigste kjennetegn</h3>"
                        + importance_html(_v["permutation_importance_top20"]), elem_classes=["pc-about-block"])
        gr.Markdown("### Begrensninger" + _about_bottom, elem_id="pc-about-bottom")
    gr.Markdown("DAT158 Maskinlæring, HVL. Studentprosjekt, ikke en sikkerhetstjeneste.", elem_id="pc-footer")

if __name__ == "__main__":
    demo.launch(theme=THEME, css=CSS, footer_links=["gradio"])
