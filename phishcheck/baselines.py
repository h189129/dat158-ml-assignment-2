"""A simple hand-written rule used as a non-ML baseline.

Flags a URL if it shows any classic phishing trick that a security-aware human would check:
IP address as host, 'user@host' obfuscation, punycode (look-alike characters), a phishing
keyword/brand in the sub-domain, or unencrypted http. The rules were written from general
domain knowledge before looking at validation or test results.
"""
from __future__ import annotations

import numpy as np
from sklearn.base import BaseEstimator, ClassifierMixin

from .features import URLFeatures


class RuleBaseline(BaseEstimator, ClassifierMixin):
    def __init__(self, tlds: tuple[str, ...] = ()):
        self.tlds = tlds

    def fit(self, X, y=None):
        self.classes_ = np.array([0, 1])
        names = list(URLFeatures(self.tlds).get_feature_names_out())
        self.idx_ = {n: names.index(n) for n in
                     ["is_ip_host", "has_userinfo", "is_punycode", "keyword_in_subdomain", "is_https"]}
        return self

    def _flag(self, F):
        i = self.idx_
        return (
            (F[:, i["is_ip_host"]] > 0) | (F[:, i["has_userinfo"]] > 0) | (F[:, i["is_punycode"]] > 0)
            | (F[:, i["keyword_in_subdomain"]] > 0) | (F[:, i["is_https"]] == 0)
        ).astype(int)

    def predict(self, F):
        """F is the feature matrix from URLFeatures (not raw URLs)."""
        return self._flag(np.asarray(F))

    def predict_proba(self, F):
        p = self._flag(np.asarray(F)).astype(float)
        return np.column_stack([1 - p, p])
