"""Download the URL-level columns of PhreshPhish at a pinned dataset revision.

Only the columns we use are read from the remote parquet files (column projection),
so the ~190 GB of HTML in the dataset is never downloaded.

Output:
    data/raw/phreshphish_urls.parquet   one row per sample: sha256, url, label, date, target, split
    data/raw/benchmarks/...             the authors' base-rate benchmark hash lists (subset of test)
    data/MANIFEST.json                  revision, row counts and a content checksum

Usage:
    python scripts/download.py
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
import urllib.request
from pathlib import Path

import fsspec
import pandas as pd
import pyarrow.parquet as pq

REPO_ID = "phreshphish/phreshphish"
# Pinned dataset revision (Hugging Face commit). The dataset repo changes over time,
# so results are only reproducible against this exact revision.
REVISION = "eca603e0ecd4f698f8d4d226c088659e72681239"
EXPECTED_ROWS = 666_315
COLUMNS = ["sha256", "url", "label", "date", "target"]
# Benchmark folders we use: 1 % and 5 % phishing base rate (29 and 5 benchmark sets).
BENCHMARK_DIRS = ["benchmark-100", "benchmark-500"]

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
BASE = f"https://huggingface.co/datasets/{REPO_ID}/resolve/{REVISION}"
API = f"https://huggingface.co/api/datasets/{REPO_ID}/tree/{REVISION}"


def list_files(subdir: str) -> list[str]:
    with urllib.request.urlopen(f"{API}/{subdir}") as resp:
        return sorted(item["path"] for item in json.load(resp) if item["type"] == "file")


def read_url_columns(path: str, fs) -> pd.DataFrame:
    with fs.open(f"{BASE}/{path}", "rb", block_size=2**20) as f:
        table = pq.ParquetFile(f).read(columns=COLUMNS)
    df = table.to_pandas()
    df["split"] = "train" if "/train-" in path else "test"
    return df


def content_checksum(df: pd.DataFrame) -> str:
    h = hashlib.sha256()
    for sha, url, label in df.sort_values("sha256")[["sha256", "url", "label"]].itertuples(index=False):
        h.update(f"{sha}\t{url}\t{label}\n".encode("utf-8"))
    return h.hexdigest()


def main() -> int:
    RAW.mkdir(parents=True, exist_ok=True)
    fs = fsspec.filesystem("https")
    files = list_files("data")
    print(f"Reading {len(files)} parquet files (URL columns only) at revision {REVISION[:10]}...")
    t0 = time.time()
    parts = []
    for i, path in enumerate(files, 1):
        parts.append(read_url_columns(path, fs))
        print(f"  [{i:2d}/{len(files)}] {path}", flush=True)
    df = pd.concat(parts, ignore_index=True)
    df["date"] = pd.to_datetime(df["date"])

    if len(df) != EXPECTED_ROWS:
        print(f"ERROR: expected {EXPECTED_ROWS} rows, got {len(df)}", file=sys.stderr)
        return 1
    out = RAW / "phreshphish_urls.parquet"
    df.to_parquet(out, index=False)

    bench_dir = RAW / "benchmarks"
    bench_files = ["benchmark/benign.txt", "benchmark/phish.txt"]
    for sub in BENCHMARK_DIRS:
        bench_files += list_files(f"benchmark/{sub}")
    for path in bench_files:
        target = bench_dir / Path(path).relative_to("benchmark")
        target.parent.mkdir(parents=True, exist_ok=True)
        with fs.open(f"{BASE}/{path}", "rb") as src:
            target.write_bytes(src.read())

    manifest = {
        "dataset": REPO_ID,
        "revision": REVISION,
        "license": "CC BY 4.0",
        "columns": COLUMNS,
        "rows": int(len(df)),
        "rows_by_split_label": {f"{s}/{l}": int(n) for (s, l), n in df.groupby(["split", "label"]).size().items()},
        "content_sha256": content_checksum(df),
        "benchmark_files": len(bench_files),
        "download_seconds": round(time.time() - t0, 1),
    }
    (ROOT / "data" / "MANIFEST.json").write_text(json.dumps(manifest, indent=2))
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
