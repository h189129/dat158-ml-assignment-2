"""Loading the prepared data and building (cached) feature matrices."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .augment import augment_benign_prefixes
from .features import URLFeatures, feature_code_hash

ROOT = Path(__file__).resolve().parents[1]
PROCESSED = ROOT / "data" / "processed"
CACHE = ROOT / "data" / "features"


def load_urls() -> pd.DataFrame:
    return pd.read_parquet(PROCESSED / "urls.parquet")


def load_tlds() -> tuple[str, ...]:
    return tuple(json.loads((PROCESSED / "tld_vocab.json").read_text()))


def evaluation_frame(df: pd.DataFrame, train: pd.DataFrame) -> pd.DataFrame:
    """Validation/test rows whose canonical URL does not occur in the (augmented) training data.

    prepare.py already removes exact duplicates of ORIGINAL training URLs; this also removes
    rows that coincide with an AUGMENTED training URL (typically the home page of a site seen
    in training), so no evaluated URL was itself a training example.
    """
    return df[~df["key"].isin(set(train["key"]))]


def training_frame(core: pd.DataFrame) -> pd.DataFrame:
    """train_core plus augmented benign path prefixes (see phishcheck/augment.py)."""
    base = core[["url", "key", "host", "group", "y"]].copy()
    base["is_augmented"] = False
    aug = augment_benign_prefixes(base)
    return pd.concat([base, aug], ignore_index=True)


def features(urls: pd.Series, tlds: tuple[str, ...], name: str) -> np.ndarray:
    """Feature matrix for a list of URLs, cached on disk (keyed by content + feature code)."""
    CACHE.mkdir(parents=True, exist_ok=True)
    code = feature_code_hash().encode()
    h = hashlib.sha256(code + "\n".join(urls).encode() + ",".join(tlds).encode()).hexdigest()[:16]
    path = CACHE / f"{name}_{h}.npy"
    if path.exists():
        return np.load(path)
    X = URLFeatures(tlds).transform(urls)
    np.save(path, X)
    return X
