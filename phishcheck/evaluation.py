"""Metric helpers shared by training, evaluation and monitoring scripts."""
from __future__ import annotations

import math

import numpy as np
from sklearn.metrics import average_precision_score, confusion_matrix, roc_auc_score, roc_curve


def threshold_at_fpr(y, scores, max_fpr: float) -> tuple[float, float, float]:
    """Lowest threshold t such that FPR(score >= t) <= max_fpr. Returns (t, fpr, recall)."""
    fpr, tpr, thr = roc_curve(y, scores, drop_intermediate=False)
    i = np.searchsorted(fpr, max_fpr, side="right") - 1
    return float(thr[i]), float(fpr[i]), float(tpr[i])


def whole_percent(t: float) -> float:
    """Round a threshold UP to a whole percentage (keeps FPR <= target). Infinite thresholds
    (constant scores, e.g. the dummy baseline) are returned unchanged."""
    return t if not np.isfinite(t) else math.ceil(round(t * 100, 9)) / 100


def at_threshold(y, scores, t: float) -> dict:
    y = np.asarray(y)
    pred = (np.asarray(scores) >= t).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    precision = tp / (tp + fp) if tp + fp else float("nan")
    recall = tp / (tp + fn) if tp + fn else float("nan")
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else float("nan")
    return {
        "threshold": float(t), "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
        "precision": float(precision), "recall": float(recall), "f1": float(f1),
        "fpr": float(fp / (fp + tn)) if fp + tn else float("nan"),
    }


def summary(y, scores, max_fpr: float = 0.01) -> dict:
    t, fpr, rec = threshold_at_fpr(y, scores, max_fpr)
    return {
        "n": int(len(y)), "phish_share": float(np.mean(y)),
        "roc_auc": float(roc_auc_score(y, scores)),
        "average_precision": float(average_precision_score(y, scores)),
        f"recall_at_fpr_{max_fpr}": rec, f"threshold_at_fpr_{max_fpr}": t,
    }


def precision_at_base_rate(recall: float, fpr: float, base_rate: float) -> float:
    """Expected precision (PPV) if the share of phishing URLs is `base_rate` (Bayes' rule)."""
    num = recall * base_rate
    return num / (num + fpr * (1 - base_rate))
