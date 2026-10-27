"""Simulated production monitoring (lifecycle: monitor and update models and data).

The deployed app stores nothing about its users, so live monitoring is not possible. Instead we
replay the test months in date order as if they were new production traffic, and compute what
a monitoring job would track each month:
  - share of URLs per risk band (label-free: available in production without any feedback),
  - mean risk score (label-free drift signal),
  - recall and FPR at the "high risk" threshold (needs labels, e.g. from user reports or
    threat-intelligence feeds such as PhishTank).

Retraining trigger (fixed in advance): retrain when, in any month,
  FPR at "high risk" > 2x the validation FPR, or
  recall at "high risk" < validation recall - 0.10.

Requires scripts/evaluate_test.py to have run (uses data/features/test_scores.parquet).
Usage: python scripts/monitor.py  -> reports/monitoring.json, reports/figures/monitoring.png
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib
import pandas as pd

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    meta = json.loads((ROOT / "models" / "metadata.json").read_text())
    t_high, t_low = meta["thresholds"]["high"], meta["thresholds"]["low"]
    val = meta["val_at_thresholds"]["high"]
    s = pd.read_parquet(ROOT / "data" / "features" / "test_scores.parquet")
    s["month"] = s["date"].dt.to_period("M").astype(str)
    rows = []
    for m, g in s.groupby("month"):
        b, p = g[g["y"] == 0], g[g["y"] == 1]
        row = {"month": m, "n": len(g),
               "share_high": float((g["score"] >= t_high).mean()),
               "share_suspicious": float(((g["score"] >= t_low) & (g["score"] < t_high)).mean()),
               "mean_score": float(g["score"].mean()),
               "fpr_high": float((b["score"] >= t_high).mean()) if len(b) >= 500 else None,
               "recall_high": float((p["score"] >= t_high).mean()) if len(p) >= 500 else None}
        row["retrain_trigger"] = bool(
            (row["fpr_high"] is not None and row["fpr_high"] > 2 * val["fpr"])
            or (row["recall_high"] is not None and row["recall_high"] < val["recall"] - 0.10))
        rows.append(row)
    df = pd.DataFrame(rows)
    result = {"validation_reference": val, "trigger_rule": "FPR > 2x val FPR or recall < val recall - 0.10",
              "months": rows}
    (ROOT / "reports" / "monitoring.json").write_text(json.dumps(result, indent=2))

    fig, ax = plt.subplots(figsize=(7, 4))
    ax.plot(df["month"], df["recall_high"], "o-", label="Recall («Høy risiko»)")
    ax.plot(df["month"], df["fpr_high"], "s-", label="FPR («Høy risiko»)")
    ax.plot(df["month"], df["share_high"], "^--", label="Andel «Høy risiko» (uten fasit)")
    ax.axhline(val["recall"], c="C0", ls=":", lw=1); ax.axhline(val["fpr"], c="C1", ls=":", lw=1)
    ax.set_title("Simulert overvåking per måned (testperioden)"); ax.legend(fontsize=8)
    fig.tight_layout(); fig.savefig(ROOT / "reports" / "figures" / "monitoring.png", dpi=150); plt.close(fig)
    print(df.to_string(index=False))


if __name__ == "__main__":
    sys.exit(main())
