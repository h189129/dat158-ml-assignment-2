"""Data augmentation for benign URLs (training data only).

Problem: the benign URLs in PhreshPhish are mostly deep links (long paths). Home pages and
short section pages are rare (about 7 % of benign URLs are root URLs vs 45 % of phishing URLs).
A model trained on this learns "short URL => phishing" and flags e.g. https://nrk.no.

Fix (label-preserving augmentation, cf. Géron ch. 3 exercise on data augmentation):
if https://site/a/b/c is a legitimate page, then https://site, https://site/a and
https://site/a/b are legitimate pages on the same legitimate site, so they are added as benign
examples.

The assumption does NOT hold where phishing pages live next to legitimate content:
- hosts that also have phishing URLs in the training data (compromised or abused sites), and
- shared platforms where anyone can publish (gitbook.io, docs.google.com, ...).
Those hosts are therefore never augmented.

Augmented rows inherit the CV group of their parent URL, so they always end up in the same
fold as the original (no leakage between folds). Validation and test data are never augmented.
"""
from __future__ import annotations

import pandas as pd

from .canonical import canonicalize, path_prefixes
from .domains import is_shared_platform


def augment_benign_prefixes(train: pd.DataFrame) -> pd.DataFrame:
    """Return NEW benign rows (path prefixes) for a training frame.

    `train` must have columns: url, key, host, group, y. Returned rows have the same columns
    plus is_augmented=True; keys that already exist in `train` are not returned.
    """
    phish_hosts = set(train.loc[train.y == 1, "host"])
    existing = set(train["key"])
    seen: set[str] = set()
    rows = []
    benign = train.loc[train.y == 0, ["url", "host", "group"]]
    for url, host, group in benign.itertuples(index=False):
        if host in phish_hosts or is_shared_platform(host):
            continue
        for key in path_prefixes(canonicalize(url)):
            if key in existing or key in seen:
                continue
            seen.add(key)
            rows.append((key, key, host, group))
    out = pd.DataFrame(rows, columns=["url", "key", "host", "group"])
    out["y"] = 0
    out["is_augmented"] = True
    return out
