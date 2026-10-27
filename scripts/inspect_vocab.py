"""List CANDIDATES for the hand-curated vocabularies in phishcheck/vocab.py (train_core only).

Prints (1) registrable domains with >= 20 distinct hostnames (shared-platform candidates),
(2) hosts whose URLs are almost all a single short path segment (shortener candidates) and
(3) the most frequent phishing `target` brands. The final lists in vocab.py were filtered by
hand from this output; see the docstring there for the rules.

Usage: python scripts/inspect_vocab.py   (requires scripts/prepare.py to have run)
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from phishcheck.domains import host_parts  # noqa: E402


def main() -> None:
    d = pd.read_parquet(ROOT / "data" / "processed" / "urls.parquet")
    core = d[d["set"] == "core"].copy()
    core["reg"] = [host_parts(h).registrable_private for h in core["host"]]
    g = core.groupby("reg").agg(hosts=("host", "nunique"), rows=("y", "size"), phish=("y", "sum"))
    pd.set_option("display.width", 160)
    pd.set_option("display.max_rows", 400)
    print("== Shared-platform candidates (>= 20 hostnames)")
    print(g[g["hosts"] >= 20].sort_values("hosts", ascending=False).to_string())

    core["depth1"] = core["path_depth"] == 1
    core["plen"] = core["key"].str.len() - core["host"].str.len() - len("https://")
    s = core.groupby("host").agg(rows=("y", "size"), d1=("depth1", "mean"), plen=("plen", "median"), phish=("y", "mean"))
    s = s[(s["rows"] >= 15) & (s["d1"] >= 0.9) & (s["plen"] <= 12) & (s.index.str.len() <= 14)]
    print("== Shortener candidates")
    print(s.sort_values("rows", ascending=False).head(60).to_string())

    print("== Most frequent phishing targets")
    print(core.loc[core["y"] == 1, "target"].fillna("").str.strip().value_counts().head(80).to_string())


if __name__ == "__main__":
    main()
