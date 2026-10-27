"""Deploy the web app to a Hugging Face Space (Gradio SDK).

Uploads ONLY the files the app needs (allow-list), plus a Space-specific README.md whose YAML
header pins the Gradio SDK version and the Python version. Training data, notebooks and caches
are not uploaded.

Prerequisites (done once by a group member, see README "Deploy"):
  1. A Hugging Face account and an access token with WRITE permission
     (https://huggingface.co/settings/tokens).
  2. pip install huggingface_hub   (already in requirements.txt)

Usage:
  export HF_TOKEN=hf_...            # PowerShell:  $env:HF_TOKEN="hf_..."
  python scripts/deploy_space.py --space <hf-username>/dat158-phishing-lenkesjekk

The Space is created automatically (public, Gradio SDK) if it does not exist.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
from pathlib import Path

from huggingface_hub import HfApi

ROOT = Path(__file__).resolve().parents[1]
SDK_VERSION = "6.30.0"
PYTHON_VERSION = "3.12"

ALLOW = [
    "app.py",
    "phishcheck/*.py",
    "models/model.joblib",
    "models/metadata.json",
    "reports/test_metrics.json",
    "reports/val_analysis.json",
    "LICENSE",
]

SPACE_README = f"""---
title: Phishing-lenkesjekk
emoji: 🎣
colorFrom: red
colorTo: gray
sdk: gradio
sdk_version: {SDK_VERSION}
python_version: "{PYTHON_VERSION}"
app_file: app.py
pinned: false
license: mit
short_description: URL-basert phishing-risiko (DAT158, HVL)
---

# Phishing-lenkesjekk

Studentprosjekt i DAT158 Maskinlæring (HVL). Appen vurderer phishing-risiko ut fra selve
URL-teksten med en scikit-learn-modell trent på PhreshPhish-datasettet (CC BY 4.0).
Appen åpner aldri lenken. Kildekode, data-pipeline og dokumentasjon ligger i GitHub-repoet.
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--space", required=True, help="<hf-username>/<space-name>")
    args = ap.parse_args()
    token = os.environ.get("HF_TOKEN")
    if not token:
        print("Set the HF_TOKEN environment variable to a Hugging Face WRITE token.", file=sys.stderr)
        return 1
    for f in ["models/model.joblib", "models/metadata.json"]:
        if not (ROOT / f).exists():
            print(f"Missing {f}: run the training pipeline first (see README).", file=sys.stderr)
            return 1

    api = HfApi(token=token)
    api.create_repo(args.space, repo_type="space", space_sdk="gradio", exist_ok=True, private=False)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        for pattern in ALLOW:
            for src in ROOT.glob(pattern):
                dst = tmp / src.relative_to(ROOT)
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
        shutil.copy2(ROOT / "requirements-app.txt", tmp / "requirements.txt")
        (tmp / "README.md").write_text(SPACE_README, encoding="utf-8")
        api.upload_folder(folder_path=str(tmp), repo_id=args.space, repo_type="space",
                          commit_message="Deploy phishing-lenkesjekk")
    print(f"Deployed: https://huggingface.co/spaces/{args.space}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
