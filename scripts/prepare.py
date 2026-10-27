"""Clean the raw URL data and create the train_core / val / test sets.

Steps (each count is written to reports/data_summary.json for the report):
 1. Canonicalize every URL (phishcheck/canonical.py).
 2. Set aside URL shorteners (destination hidden; 0 benign examples) -> reported separately.
 3. Train split: drop canonical keys with conflicting labels, then de-duplicate keys
    (keep the earliest). Because the earliest copy is kept, no validation URL duplicates a
    train_core URL.
 4. Split train by date: train_core < 2025-07-01 <= val (temporal hold-out).
 5. Test split (authors' split): drop conflicts and duplicates, and drop URLs whose canonical
    key also occurs in the train split.
 6. Learn the TLD vocabulary (30 most frequent ICANN suffixes) from train_core only.

Usage: python scripts/prepare.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from phishcheck.canonical import canonicalize  # noqa: E402
from phishcheck.domains import group_key, host_parts, is_shortener  # noqa: E402

VAL_START = pd.Timestamp("2025-07-01")
N_TLDS = 30
RAW = ROOT / "data" / "raw" / "phreshphish_urls.parquet"
OUT = ROOT / "data" / "processed"


def dedupe(df: pd.DataFrame, summary: dict, name: str) -> pd.DataFrame:
    n0 = len(df)
    conflicting = df.groupby("key")["y"].nunique()
    conflicting = set(conflicting[conflicting > 1].index)
    df = df[~df["key"].isin(conflicting)]
    n1 = len(df)
    df = df.sort_values(["date", "sha256"]).drop_duplicates("key", keep="first")
    summary[f"{name}_conflicting_keys"] = len(conflicting)
    summary[f"{name}_rows_dropped_conflict"] = n0 - n1
    summary[f"{name}_rows_dropped_duplicate"] = n1 - len(df)
    return df


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    raw = pd.read_parquet(RAW)
    summary: dict = {"raw_rows": len(raw)}

    canon = [canonicalize(u) for u in raw["url"]]
    raw["key"] = [c.key for c in canon]
    raw["host"] = [c.host for c in canon]
    raw["is_root"] = [c.is_root for c in canon]
    raw["path_depth"] = [len([p for p in c.path.split("/") if p]) for c in canon]
    raw["had_query"] = [c.had_query for c in canon]
    raw["y"] = (raw["label"] == "phish").astype(int)
    raw["group"] = [group_key(h) for h in raw["host"]]
    raw["suffix"] = [host_parts(h).suffix for h in raw["host"]]

    short = raw["host"].map(is_shortener)
    raw.loc[short].to_parquet(OUT / "shorteners.parquet", index=False)
    summary["shortener_rows_by_split_label"] = {
        f"{s}/{l}": int(n) for (s, l), n in raw.loc[short].groupby(["split", "label"]).size().items()
    }
    raw = raw.loc[~short]

    train = dedupe(raw[raw["split"] == "train"].copy(), summary, "train")
    test = dedupe(raw[raw["split"] == "test"].copy(), summary, "test")
    n = len(test)
    test = test[~test["key"].isin(set(train["key"]))]
    summary["test_rows_dropped_seen_in_train"] = n - len(test)

    train["set"] = (train["date"] >= VAL_START).map({False: "core", True: "val"})
    test["set"] = "test"
    data = pd.concat([train, test], ignore_index=True)

    tlds = list(data.loc[data["set"] == "core", "suffix"].value_counts().head(N_TLDS).index)
    (OUT / "tld_vocab.json").write_text(json.dumps(tlds, indent=2))

    cols = ["sha256", "url", "key", "host", "group", "suffix", "is_root", "path_depth",
            "had_query", "y", "label", "date", "target", "set"]
    data[cols].to_parquet(OUT / "urls.parquet", index=False)

    counts = data.groupby(["set", "label"]).size().unstack()
    summary["rows_by_set_label"] = {s: {l: int(v) for l, v in r.items()} for s, r in counts.iterrows()}
    summary["phish_share_by_set"] = data.groupby("set")["y"].mean().round(4).to_dict()
    summary["date_range_by_set"] = {
        s: [str(g["date"].min().date()), str(g["date"].max().date())] for s, g in data.groupby("set")
    }
    summary["tld_vocab"] = tlds
    (ROOT / "reports").mkdir(exist_ok=True)
    (ROOT / "reports" / "data_summary.json").write_text(json.dumps(summary, indent=2, default=str))
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
