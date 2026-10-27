#!/usr/bin/env bash
# Reproduce the whole pipeline: data -> features/audit -> training -> analysis -> test -> app checks.
# Runtime on a 2-core laptop: about 1 hour. Peak RAM: about 4 GB.
set -euo pipefail
python scripts/download.py        # pinned PhreshPhish revision, URL columns only (~70 MB)
python scripts/prepare.py         # canonicalize, de-duplicate, train_core / val / test
python scripts/audit_months.py    # month audit (decides which features are dropped)
python scripts/train.py           # baselines, random search, model selection, thresholds
python scripts/analyze_val.py     # error analysis, permutation importance, learning curve
python scripts/evaluate_test.py --force  # test evaluation; --force only to REPRODUCE the documented run 2
python scripts/monitor.py         # simulated monitoring over the test months
python scripts/sanity_check.py    # qualitative check on Norwegian URLs
pytest -q
