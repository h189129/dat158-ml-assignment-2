"""Model selection on train_core / val and export of the deployed model.

Lifecycle step "Modelling": baselines -> explore models -> fine-tune (random search with grouped
CV) -> evaluate on the validation set -> choose model and decision thresholds.

The TEST set is not used here. Selection rule (decided before running):
  1. eligible models: size <= 50 MB and latency <= 100 ms per URL (deployment requirement),
  2. highest recall at FPR <= 1 % on val,
  3. if two models are within 0.01 recall, the one with fewer false alarms on real benign
     home pages wins.

Outputs: models/model.joblib (features + classifier pipeline), models/metadata.json,
         reports/val_model_comparison.json, reports/search_results.json

Usage: python scripts/train.py   (about 30-40 minutes on 2 CPU cores)
"""
from __future__ import annotations

import hashlib
import json
import math
import platform
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from scipy.stats import loguniform, randint
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupKFold, RandomizedSearchCV
from sklearn.pipeline import Pipeline, make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from phishcheck import datasets  # noqa: E402
from phishcheck.baselines import RuleBaseline  # noqa: E402
from phishcheck.evaluation import at_threshold, summary, threshold_at_fpr, whole_percent  # noqa: E402
from phishcheck.features import URLFeatures, feature_code_hash  # noqa: E402

SEED = 42
SEARCH_GROUP_SHARE = 0.33       # share of train_core groups used for the hyper-parameter search
MAX_SIZE_MB, MAX_LATENCY_MS = 50, 100
FPR_HIGH, FPR_LOW = 0.01, 0.05  # thresholds for the "high risk" and "suspicious" bands
MODELS_DIR, REPORTS = ROOT / "models", ROOT / "reports"


def candidates():
    return {
        "logistic_regression": (
            make_pipeline(StandardScaler(), LogisticRegression(max_iter=3000)),
            {"logisticregression__C": loguniform(1e-3, 1e2)}, 8),
        "decision_tree": (
            DecisionTreeClassifier(random_state=SEED),
            {"max_depth": randint(4, 31), "min_samples_leaf": randint(1, 201)}, 10),
        "random_forest": (
            RandomForestClassifier(n_estimators=100, n_jobs=2, random_state=SEED),
            {"max_depth": [16, 24, 32], "min_samples_leaf": [3, 10, 30],
             "max_features": ["sqrt", 0.3]}, 5),
        # early_stopping=False: HGB's built-in early stopping holds out a RANDOM 10 % of rows,
        # which would put URLs of the same site on both sides (leakage). The number of
        # boosting iterations is tuned by the grouped CV instead.
        "hist_gradient_boosting": (
            HistGradientBoostingClassifier(early_stopping=False, random_state=SEED),
            {"learning_rate": loguniform(0.03, 0.3), "max_iter": [150, 300, 600],
             "max_leaf_nodes": [15, 31, 63, 127], "min_samples_leaf": [20, 50, 100, 200],
             "l2_regularization": loguniform(1e-3, 10)}, 12),
    }


def grouped_cv_indices(frame: pd.DataFrame, n_splits: int = 3):
    """GroupKFold on ORIGINAL rows; augmented rows only ever join the training folds."""
    orig = np.flatnonzero(~frame["is_augmented"].to_numpy())
    groups = frame["group"].to_numpy()
    splits = []
    for _, test_o in GroupKFold(n_splits=n_splits).split(orig, groups=groups[orig]):
        test_idx = orig[test_o]
        test_groups = set(groups[test_idx])
        train_idx = np.flatnonzero(~np.isin(groups, list(test_groups)))
        splits.append((train_idx, test_idx))
    return splits


def latency_ms(pipe: Pipeline, urls: list[str]) -> float:
    pipe.predict_proba([urls[0]])
    t0 = time.perf_counter()
    for u in urls:
        pipe.predict_proba([u])
    return (time.perf_counter() - t0) / len(urls) * 1000


def size_mb(obj, path: Path) -> float:
    joblib.dump(obj, path, compress=3)
    return path.stat().st_size / 1e6


def main() -> None:
    t_start = time.time()
    MODELS_DIR.mkdir(exist_ok=True)
    REPORTS.mkdir(exist_ok=True)
    rng = np.random.default_rng(SEED)
    data = datasets.load_urls()
    tlds = datasets.load_tlds()
    core, val_all = data[data["set"] == "core"], data[data["set"] == "val"]
    train = datasets.training_frame(core)
    val = datasets.evaluation_frame(val_all, train)
    print(f"train_core {len(core)} rows + {train['is_augmented'].sum()} augmented benign prefixes; "
          f"val {len(val)} rows ({len(val_all) - len(val)} removed: same URL as an augmented training row)")

    X_train = datasets.features(train["url"], tlds, "train_core_aug")
    X_val = datasets.features(val["url"], tlds, "val")
    y_train, y_val = train["y"].to_numpy(), val["y"].to_numpy()
    names = list(URLFeatures(tlds).get_feature_names_out())

    # Robustness sets from REAL validation URLs (not synthetic): benign home pages and benign
    # one-segment paths whose canonical key is not in the (augmented) training data.
    train_keys = set(train["key"])
    vb = val[(val["y"] == 0) & ~val["key"].isin(train_keys)]
    robust = {"real_benign_root": vb["is_root"].to_numpy(),
              "real_benign_depth1": (vb["path_depth"] == 1).to_numpy()}
    vb_pos = val.index.get_indexer(vb.index)
    root_phish = (val["y"] == 1) & val["is_root"]

    results = {"rows": {"train_core_original": int(len(core)),
                        "train_augmented_rows": int(train["is_augmented"].sum()),
                        "val": int(len(val)),
                        "val_removed_same_as_augmented": int(len(val_all) - len(val)),
                        "robust_real_benign_root": int(robust["real_benign_root"].sum()),
                        "robust_real_benign_depth1": int(robust["real_benign_depth1"].sum())},
               "models": {}}

    def evaluate(name, scores, model_obj=None, pipe=None, extra=None):
        s = summary(y_val, scores, FPR_HIGH)
        # Same rounding as the deployed thresholds (whole percentages), so the numbers here
        # match metadata.json and analyze_val.py.
        t_high = whole_percent(threshold_at_fpr(y_val, scores, FPR_HIGH)[0])
        s["at_t_high"] = at_threshold(y_val, scores, t_high)
        sb = scores[vb_pos]
        for key, mask in robust.items():
            s[f"fpr_{key}"] = float(np.mean(sb[mask] >= t_high))
        s["recall_root_phish"] = float(np.mean(scores[root_phish.to_numpy()] >= t_high))
        s["recall_nonroot_phish"] = float(np.mean(scores[((val["y"] == 1) & ~val["is_root"]).to_numpy()] >= t_high))
        if model_obj is not None:
            s["size_mb"] = size_mb(pipe, MODELS_DIR / f"_candidate_{name}.joblib")
            s["latency_ms"] = latency_ms(pipe, list(val["url"].sample(200, random_state=SEED)))
        if extra:
            s.update(extra)
        results["models"][name] = s
        print(f"{name:24s} AUC {s['roc_auc']:.4f}  recall@1%FPR {s['recall_at_fpr_0.01']:.3f}  "
              f"FPR real roots {s['fpr_real_benign_root']:.3f}  "
              + (f"size {s.get('size_mb', 0):.1f} MB  latency {s.get('latency_ms', 0):.1f} ms" if model_obj is not None else ""),
              flush=True)

    # --- Baselines --------------------------------------------------------------------------
    dummy = DummyClassifier(strategy="prior").fit(X_train, y_train)
    evaluate("baseline_dummy", dummy.predict_proba(X_val)[:, 1])
    rule = RuleBaseline(tlds).fit(X_train)
    rule_scores = rule.predict_proba(X_val)[:, 1]
    evaluate("baseline_rules", rule_scores, extra={"rules_at_flag": at_threshold(y_val, rule_scores, 0.5)})

    # --- Hyper-parameter search on a group subsample of train_core (grouped CV) ---------------
    groups = train["group"].unique()
    chosen_groups = set(rng.choice(groups, size=int(len(groups) * SEARCH_GROUP_SHARE), replace=False))
    sub = train[train["group"].isin(chosen_groups)].reset_index(drop=True)
    sub_idx = np.flatnonzero(train["group"].isin(chosen_groups).to_numpy())
    X_sub, y_sub = X_train[sub_idx], y_train[sub_idx]
    cv = grouped_cv_indices(sub)
    print(f"search subsample: {len(sub)} rows ({(~sub['is_augmented']).sum()} original), 3 grouped folds")

    search_log = {}
    for name, (est, space, n_iter) in candidates().items():
        t0 = time.time()
        search = RandomizedSearchCV(est, space, n_iter=n_iter, scoring="roc_auc", cv=cv,
                                    random_state=SEED, n_jobs=1 if name == "random_forest" else 2,
                                    refit=False)
        search.fit(X_sub, y_sub)
        best = search.best_params_
        search_log[name] = {"best_params": {k: (v if not isinstance(v, np.generic) else v.item()) for k, v in best.items()},
                            "best_cv_roc_auc": float(search.best_score_),
                            "seconds": round(time.time() - t0)}
        print(f"  search {name}: CV AUC {search.best_score_:.4f} {best} ({time.time() - t0:.0f}s)", flush=True)

        model = sklearn.base.clone(est).set_params(**best).fit(X_train, y_train)
        pipe = Pipeline([("features", URLFeatures(tlds)), ("model", model)])
        evaluate(name, model.predict_proba(X_val)[:, 1], model, pipe)
        joblib.dump(pipe, MODELS_DIR / f"_candidate_{name}.joblib", compress=3)

    (REPORTS / "search_results.json").write_text(json.dumps(search_log, indent=2))

    # --- Selection (rule fixed in the module docstring) -------------------------------------
    ml = {k: v for k, v in results["models"].items() if not k.startswith("baseline")}
    eligible = {k: v for k, v in ml.items() if v["size_mb"] <= MAX_SIZE_MB and v["latency_ms"] <= MAX_LATENCY_MS}
    best_recall = max(v["recall_at_fpr_0.01"] for v in eligible.values())
    close = {k: v for k, v in eligible.items() if v["recall_at_fpr_0.01"] >= best_recall - 0.01}
    chosen = min(close, key=lambda k: close[k]["fpr_real_benign_root"])
    results["selection"] = {"eligible": sorted(eligible), "within_0.01_of_best": sorted(close), "chosen": chosen}
    print(f"chosen model: {chosen}")

    pipe = joblib.load(MODELS_DIR / f"_candidate_{chosen}.joblib")
    scores = pipe.named_steps["model"].predict_proba(X_val)[:, 1]
    # Thresholds are rounded UP to whole percentages (keeps FPR <= target) so that the app's
    # displayed score 0-100 always agrees with the band.
    t_high = whole_percent(threshold_at_fpr(y_val, scores, FPR_HIGH)[0])
    t_low = whole_percent(threshold_at_fpr(y_val, scores, FPR_LOW)[0])
    at_h, at_l = at_threshold(y_val, scores, t_high), at_threshold(y_val, scores, t_low)
    fpr_h, rec_h, fpr_l, rec_l = at_h["fpr"], at_h["recall"], at_l["fpr"], at_l["recall"]
    joblib.dump(pipe, MODELS_DIR / "model.joblib", compress=3)
    np.save(MODELS_DIR.parent / "data" / "features" / "val_scores_chosen.npy", scores)

    metadata = {
        "model_version": "v2",
        "model": chosen,
        "params": search_log[chosen]["best_params"],
        "thresholds": {"high": t_high, "low": t_low},
        "threshold_definition": {"high": "FPR 1 % on validation benign URLs",
                                 "low": "FPR 5 % on validation benign URLs"},
        "val_at_thresholds": {"high": {"fpr": fpr_h, "recall": rec_h}, "low": {"fpr": fpr_l, "recall": rec_l}},
        "feature_names": names,
        "feature_code_hash": feature_code_hash(),
        "trained_on": "train_core (PhreshPhish train split, dated before 2025-07-01) + augmented benign prefixes",
        "training_rows": int(len(train)),
        "dataset_revision": json.loads((ROOT / "data" / "MANIFEST.json").read_text())["revision"],
        "versions": {"python": platform.python_version(), "scikit-learn": sklearn.__version__,
                     "numpy": np.__version__, "pandas": pd.__version__},
    }
    metadata["model_sha256"] = hashlib.sha256((MODELS_DIR / "model.joblib").read_bytes()).hexdigest()
    (MODELS_DIR / "metadata.json").write_text(json.dumps(metadata, indent=2))
    results["thresholds"] = metadata["thresholds"]
    results["runtime_seconds"] = round(time.time() - t_start)
    (REPORTS / "val_model_comparison.json").write_text(json.dumps(results, indent=2))
    print(json.dumps(metadata["thresholds"], indent=2))


if __name__ == "__main__":
    main()
