"""Final, one-time evaluation of the deployed model on the held-out TEST data.

Run this ONCE, after model, features and thresholds are frozen. The script refuses to run again
if reports/test_metrics.json exists (pass --force only to reproduce the exact same run).

Measures (all at the frozen thresholds chosen on the validation set):
  - overall: ROC-AUC, average precision, recall at FPR 1 %, precision/recall/F1/FPR at
    the "high risk" threshold, confusion matrix
  - base-rate benchmarks from the dataset authors: 1 % and 5 % phishing (mean +- std)
  - per month (drift), sites never seen in training (per class), real benign home pages
  - URL shorteners (not scored by the app) are counted separately

Usage: python scripts/evaluate_test.py
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
from sklearn.metrics import ConfusionMatrixDisplay, average_precision_score, precision_recall_curve, roc_curve  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from phishcheck import datasets  # noqa: E402
from phishcheck.evaluation import at_threshold, summary  # noqa: E402

OUT = ROOT / "reports" / "test_metrics.json"
# Run 1 (model v1, 2026-10-25) is archived in reports/archive_v1/. Run 2 evaluates model v2 after
# the bug-fix iteration described in the README ("Åpenhet om metode").
RUN = 2
FIG = ROOT / "reports" / "figures"
BENCH = ROOT / "data" / "raw" / "benchmarks"


def benchmark(test: pd.DataFrame, folder: str, t_high: float) -> dict:
    benign = set((BENCH / "benign.txt").read_text().split())
    rows = []
    for f in sorted((BENCH / folder).glob("*.txt")):
        keep = benign | set(f.read_text().split())
        sub = test[test["sha256"].isin(keep)]
        r = at_threshold(sub["y"], sub["score"], t_high)
        rows.append({"file": f.name, "n": len(sub), "phish_share": float(sub["y"].mean()),
                     "average_precision": float(average_precision_score(sub["y"], sub["score"])),
                     "precision": r["precision"], "recall": r["recall"]})
    df = pd.DataFrame(rows)
    return {"n_benchmarks": len(df), "phish_share_mean": float(df["phish_share"].mean()),
            **{f"{c}_mean": float(df[c].mean()) for c in ["average_precision", "precision", "recall"]},
            **{f"{c}_std": float(df[c].std()) for c in ["average_precision", "precision", "recall"]}}


def main() -> None:
    if OUT.exists() and "--force" not in sys.argv:
        sys.exit("Test set already evaluated (reports/test_metrics.json exists). Refusing to run again. "
                 "Use --force only to REPRODUCE the documented run with the same model.")
    meta = json.loads((ROOT / "models" / "metadata.json").read_text())
    t_high, t_low = meta["thresholds"]["high"], meta["thresholds"]["low"]
    model = joblib.load(ROOT / "models" / "model.joblib").named_steps["model"]
    data = datasets.load_urls()
    tlds = datasets.load_tlds()
    core = data[data["set"] == "core"]
    train = datasets.training_frame(core)
    test_all = data[data["set"] == "test"]
    test = datasets.evaluation_frame(test_all, train).copy()
    X = datasets.features(test["url"], tlds, "test")
    test["score"] = model.predict_proba(X)[:, 1]
    y = test["y"].to_numpy()

    res: dict = {"model": meta["model"], "model_version": meta.get("model_version", "v1"),
                 "feature_code_hash": meta.get("feature_code_hash"), "model_sha256": meta.get("model_sha256"),
                 "thresholds": meta["thresholds"], "run": RUN,
                 "rows_removed_same_as_augmented_training_url": int(len(test_all) - len(test))}
    res["test"] = summary(y, test["score"].to_numpy())
    res["test"]["at_t_high"] = at_threshold(y, test["score"], t_high)
    res["test"]["at_t_low"] = at_threshold(y, test["score"], t_low)
    res["benchmarks"] = {"1%": benchmark(test, "benchmark-100", t_high),
                         "5%": benchmark(test, "benchmark-500", t_high)}

    test["month"] = test["date"].dt.to_period("M").astype(str)
    per_month = {}
    for m, g in test.groupby("month"):
        b, p = g[g["y"] == 0], g[g["y"] == 1]
        per_month[m] = {"n_benign": len(b), "n_phish": len(p),
                        "fpr": float((b["score"] >= t_high).mean()) if len(b) else None,
                        "recall": float((p["score"] >= t_high).mean()) if len(p) else None,
                        "mean_score_benign": float(b["score"].mean()) if len(b) else None}
    res["per_month"] = per_month

    seen_groups = set(core["group"])
    test["unseen_site"] = ~test["group"].isin(seen_groups)
    res["unseen_sites"] = {}
    for unseen, g in test.groupby("unseen_site"):
        b, p = g[g["y"] == 0], g[g["y"] == 1]
        res["unseen_sites"]["unseen" if unseen else "seen_in_training"] = {
            "n_benign": len(b), "fpr": float((b["score"] >= t_high).mean()),
            "n_phish": len(p), "recall": float((p["score"] >= t_high).mean())}

    rb = test[test["y"] == 0]
    res["robustness"] = {
        "real_benign_root": {"n": int(rb["is_root"].sum()),
                             "fpr_high": float((rb.loc[rb["is_root"], "score"] >= t_high).mean())},
        "real_benign_depth1": {"n": int((rb["path_depth"] == 1).sum()),
                               "fpr_high": float((rb.loc[rb["path_depth"] == 1, "score"] >= t_high).mean())},
    }
    sh = pd.read_parquet(ROOT / "data" / "processed" / "shorteners.parquet")
    res["shorteners_not_scored"] = sh[sh["split"] == "test"]["label"].value_counts().to_dict()

    FIG.mkdir(parents=True, exist_ok=True)
    disp = ConfusionMatrixDisplay.from_predictions(y, (test["score"] >= t_high).astype(int),
                                                   display_labels=["Legitim", "Phishing"],
                                                   values_format=",d", cmap="Blues")
    disp.ax_.set_title("Testdata, terskel «Høy risiko»")
    disp.figure_.tight_layout(); disp.figure_.savefig(FIG / "test_confusion_matrix.png", dpi=150); plt.close(disp.figure_)
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(11, 4.5))
    fpr, tpr, _ = roc_curve(y, test["score"]); prec, rec, _ = precision_recall_curve(y, test["score"])
    a1.plot(fpr, tpr); a1.set_xscale("log"); a1.set_xlim(1e-3, 1); a1.axvline(0.01, ls=":", c="grey")
    a1.set_xlabel("False positive rate (log)"); a1.set_ylabel("Recall"); a1.set_title("ROC, testdata")
    a2.plot(rec, prec); a2.set_xlabel("Recall"); a2.set_ylabel("Precision"); a2.set_title(f"Precision-recall (phishing-andel {y.mean():.0%})")
    fig.tight_layout(); fig.savefig(FIG / "test_roc_pr.png", dpi=150); plt.close(fig)

    test[["sha256", "date", "y", "score", "unseen_site"]].to_parquet(ROOT / "data" / "features" / "test_scores.parquet")
    OUT.write_text(json.dumps(res, indent=2, default=str))
    print(json.dumps(res, indent=2, default=str))


if __name__ == "__main__":
    main()
