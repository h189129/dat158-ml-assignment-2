"""Validation analysis of the chosen model (lifecycle: evaluate, analyse mistakes, feature importance).

Uses the VALIDATION set only. Produces material for report section 3:
  reports/figures/val_roc_pr.png          ROC and precision-recall curves, all candidate models
  reports/figures/val_confusion_matrix.png
  reports/figures/permutation_importance.png
  reports/figures/learning_curve.png
  reports/val_errors.md                   worst false positives / false negatives (defanged)
  reports/val_analysis.json               breakdowns, importance, learning curve, band shares

Usage: python scripts/analyze_val.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import matplotlib
import numpy as np
import pandas as pd

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from sklearn.base import clone  # noqa: E402
from sklearn.inspection import permutation_importance  # noqa: E402
from sklearn.metrics import ConfusionMatrixDisplay, precision_recall_curve, roc_curve  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from phishcheck import datasets  # noqa: E402
from phishcheck.domains import is_shared_platform  # noqa: E402
from phishcheck.evaluation import at_threshold, precision_at_base_rate, summary  # noqa: E402

FIG = ROOT / "reports" / "figures"
SEED = 42
PRETTY = {"logistic_regression": "Logistisk regresjon", "decision_tree": "Beslutningstre",
          "random_forest": "Random forest", "hist_gradient_boosting": "Gradient boosting (HGB)"}


def defang(url: str) -> str:
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def main() -> None:
    FIG.mkdir(parents=True, exist_ok=True)
    meta = json.loads((ROOT / "models" / "metadata.json").read_text())
    t_high, t_low = meta["thresholds"]["high"], meta["thresholds"]["low"]
    pipe = joblib.load(ROOT / "models" / "model.joblib")
    model = pipe.named_steps["model"]
    data = datasets.load_urls()
    tlds = datasets.load_tlds()
    core = data[data["set"] == "core"]
    train = datasets.training_frame(core)
    val = datasets.evaluation_frame(data[data["set"] == "val"], train).copy()
    X_val = datasets.features(val["url"], tlds, "val")
    y_val = val["y"].to_numpy()
    val["score"] = model.predict_proba(X_val)[:, 1]
    out: dict = {"model": meta["model"]}

    # ROC / PR curves for all candidates ---------------------------------------------------
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))
    for name, label in PRETTY.items():
        p = ROOT / "models" / f"_candidate_{name}.joblib"
        if not p.exists():
            continue
        s = joblib.load(p).named_steps["model"].predict_proba(X_val)[:, 1]
        fpr, tpr, _ = roc_curve(y_val, s)
        prec, rec, _ = precision_recall_curve(y_val, s)
        ax1.plot(fpr, tpr, label=label)
        ax2.plot(rec, prec, label=label)
    ax1.set_xscale("log"); ax1.set_xlim(1e-3, 1); ax1.axvline(0.01, ls=":", c="grey")
    ax1.set_xlabel("False positive rate (log)"); ax1.set_ylabel("Recall (TPR)"); ax1.set_title("ROC, valideringsdata")
    ax2.set_xlabel("Recall"); ax2.set_ylabel("Precision"); ax2.set_title(f"Precision-recall (phishing-andel {y_val.mean():.0%})")
    ax1.legend(fontsize=8); fig.tight_layout(); fig.savefig(FIG / "val_roc_pr.png", dpi=150); plt.close(fig)

    # Confusion matrix at the high-risk threshold -------------------------------------------
    pred = (val["score"] >= t_high).astype(int)
    disp = ConfusionMatrixDisplay.from_predictions(y_val, pred, display_labels=["Legitim", "Phishing"],
                                                   values_format=",d", cmap="Blues")
    disp.ax_.set_title("Valideringsdata, terskel «Høy risiko»")
    disp.figure_.tight_layout(); disp.figure_.savefig(FIG / "val_confusion_matrix.png", dpi=150); plt.close(disp.figure_)
    out["val_summary"] = summary(y_val, val["score"].to_numpy())
    out["val_at_t_high"] = at_threshold(y_val, val["score"], t_high)
    out["val_at_t_low"] = at_threshold(y_val, val["score"], t_low)
    h = out["val_at_t_high"]
    out["expected_precision_at_base_rate"] = {
        f"{br:.0%}": precision_at_base_rate(h["recall"], h["fpr"], br) for br in (0.5, 0.05, 0.01)}
    band = np.where(val["score"] >= t_high, "high", np.where(val["score"] >= t_low, "suspicious", "low"))
    out["band_share_by_class"] = pd.crosstab(val["label"], band, normalize="index").round(4).to_dict(orient="index")

    # Error analysis -----------------------------------------------------------------------
    val["pred"] = pred
    val["shared_platform"] = val["host"].map(is_shared_platform)
    def rates(g):
        b, p = g[g["y"] == 0], g[g["y"] == 1]
        return pd.Series({"n_benign": len(b), "fpr": (b["pred"] == 1).mean() if len(b) else np.nan,
                          "n_phish": len(p), "recall": (p["pred"] == 1).mean() if len(p) else np.nan})
    out["by_shared_platform"] = val.groupby("shared_platform").apply(rates, include_groups=False).round(4).to_dict(orient="index")
    out["by_is_root"] = val.groupby("is_root").apply(rates, include_groups=False).round(4).to_dict(orient="index")
    top_tld = val["suffix"].value_counts().head(15).index
    out["by_tld"] = val[val["suffix"].isin(top_tld)].groupby("suffix").apply(rates, include_groups=False).round(4).to_dict(orient="index")
    ph = val[val["y"] == 1]
    top_targets = ph["target"].fillna("").value_counts().head(12).index
    out["recall_by_target"] = (ph[ph["target"].isin(top_targets)].groupby("target")["pred"]
                               .agg(["size", "mean"]).round(4).rename(columns={"size": "n", "mean": "recall"})
                               .to_dict(orient="index"))
    fp = val[(val["y"] == 0)].nlargest(25, "score")
    fn = val[(val["y"] == 1)].nsmallest(25, "score")
    lines = ["# Feilanalyse, valideringsdata", "",
             "URL-ene er «defanged» (hxxp, [.]) så de ikke blir klikkbare.", "",
             "## 25 legitime URL-er med høyest score (falske positive)", "", "| score | url |", "|---|---|"]
    lines += [f"| {s:.3f} | `{defang(u)}` |" for u, s in zip(fp["url"], fp["score"])]
    lines += ["", "## 25 phishing-URL-er med lavest score (falske negative)", "", "| score | target | url |", "|---|---|---|"]
    lines += [f"| {s:.3f} | {t} | `{defang(u)}` |" for u, s, t in zip(fn["url"], fn["score"], fn["target"].fillna(""))]
    (ROOT / "reports" / "val_errors.md").write_text("\n".join(lines) + "\n")

    # Permutation importance (model step, on the feature matrix) -----------------------------
    rng = np.random.default_rng(SEED)
    idx = rng.choice(len(val), size=min(20000, len(val)), replace=False)
    names = meta["feature_names"]
    pi = permutation_importance(model, X_val[idx], y_val[idx], scoring="roc_auc", n_repeats=5,
                                random_state=SEED, n_jobs=2)
    imp = pd.DataFrame({"feature": names, "mean": pi.importances_mean, "std": pi.importances_std})
    imp = imp.sort_values("mean", ascending=False)
    out["permutation_importance_top20"] = imp.head(20).round(5).to_dict(orient="records")
    top = imp.head(15).iloc[::-1]
    fig, ax = plt.subplots(figsize=(7, 5))
    ax.barh(top["feature"], top["mean"], xerr=top["std"], color="#2e90fa")
    ax.set_xlabel("Fall i ROC-AUC når kjennetegnet stokkes"); ax.set_title("Permutation importance (valideringsdata)")
    fig.tight_layout(); fig.savefig(FIG / "permutation_importance.png", dpi=150); plt.close(fig)

    # Learning curve: share of train_core sites (groups) vs validation performance ---------
    X_train = datasets.features(train["url"], tlds, "train_core_aug")
    groups = train["group"].unique()
    curve = []
    for share in (0.05, 0.1, 0.25, 0.5, 1.0):
        chosen = set(rng.choice(groups, size=int(len(groups) * share), replace=False)) if share < 1 else set(groups)
        mask = train["group"].isin(chosen).to_numpy()
        m = clone(model).fit(X_train[mask], train["y"].to_numpy()[mask])
        s = m.predict_proba(X_val)[:, 1]
        r = summary(y_val, s)
        curve.append({"share_of_sites": share, "train_rows": int(mask.sum()),
                      "val_roc_auc": r["roc_auc"], "val_recall_at_fpr_0.01": r["recall_at_fpr_0.01"]})
        print("learning curve", curve[-1], flush=True)
    out["learning_curve"] = curve
    lc = pd.DataFrame(curve)
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.plot(lc["train_rows"], lc["val_roc_auc"], "o-", label="ROC-AUC")
    ax.plot(lc["train_rows"], lc["val_recall_at_fpr_0.01"], "s-", label="Recall ved 1 % FPR")
    ax.set_xscale("log"); ax.set_xlabel("Antall treningsrader (log)"); ax.set_title("Læringskurve (valideringsdata)")
    ax.legend(); fig.tight_layout(); fig.savefig(FIG / "learning_curve.png", dpi=150); plt.close(fig)

    (ROOT / "reports" / "val_analysis.json").write_text(json.dumps(out, indent=2, default=str))
    print(json.dumps({k: out[k] for k in ["val_summary", "val_at_t_high", "expected_precision_at_base_rate",
                                         "by_shared_platform", "by_is_root"]}, indent=2, default=str))


if __name__ == "__main__":
    main()
