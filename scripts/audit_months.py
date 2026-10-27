"""Month audit: is a feature's class signal stable over time, or an artifact of when data was collected?

PhreshPhish was collected over 17 months and the classes were not collected evenly (no benign
URLs at all between Nov 2024 and May 2025). A feature can therefore separate the classes in the
training data only because phishing and benign URLs come from different months.

Rule (fixed before modelling): for every month with at least 1,000 URLs of each class (train_core
and val months only, never test), compute the standardized mean difference
    d = (mean_phish - mean_benign) / pooled_std.
A feature is FLAGGED if it has |d| >= 0.2 in at least one month in each direction (the sign flips),
i.e. its direction of evidence depends on the month. Flagged features are removed from the model.

Usage: python scripts/audit_months.py   -> reports/month_audit.csv, reports/month_audit.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from phishcheck.canonical import canonicalize  # noqa: E402
from phishcheck.features import ALL_BASE_FEATURES, url_features  # noqa: E402

MIN_PER_CLASS = 1000
THRESHOLD = 0.2


def main() -> None:
    data = pd.read_parquet(ROOT / "data" / "processed" / "urls.parquet")
    data = data[data["set"].isin(["core", "val"])].copy()
    feats = pd.DataFrame(
        [url_features(canonicalize(u)) for u in data["url"]], index=data.index
    )[ALL_BASE_FEATURES]
    month = data["date"].dt.to_period("M").astype(str)

    rows = []
    for m, idx in data.groupby(month).groups.items():
        y = data.loc[idx, "y"]
        if (y == 1).sum() < MIN_PER_CLASS or (y == 0).sum() < MIN_PER_CLASS:
            continue
        f = feats.loc[idx]
        p, b = f[y == 1], f[y == 0]
        pooled = np.sqrt((p.var() + b.var()) / 2).replace(0, np.nan)
        d = ((p.mean() - b.mean()) / pooled).fillna(0)
        for name, val in d.items():
            rows.append({"month": m, "feature": name, "d": round(float(val), 3)})
    table = pd.DataFrame(rows).pivot(index="feature", columns="month", values="d")
    flagged = table[(table >= THRESHOLD).any(axis=1) & (table <= -THRESHOLD).any(axis=1)]
    table.to_csv(ROOT / "reports" / "month_audit.csv")
    result = {
        "months_used": list(table.columns),
        "threshold": THRESHOLD,
        "flagged_features": list(flagged.index),
    }
    (ROOT / "reports" / "month_audit.json").write_text(json.dumps(result, indent=2))
    pd.set_option("display.width", 200)
    print(table.round(2).to_string())
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
