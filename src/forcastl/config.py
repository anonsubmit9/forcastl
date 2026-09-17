"""Centralized configuration for FORCAST-L."""

import os
from pathlib import Path

# This module lives at src/forcastl/config.py, so the repo root is two levels up.
# The project is a clone + ``pip install -e .`` checkout: the dataset sits at
# ``<repo>/data`` and generated artefacts at ``<repo>/outputs`` (both overridable
# by env var for non-default deployments).
PACKAGE_DIR = Path(__file__).resolve().parent          # src/forcastl
REPO_ROOT = PACKAGE_DIR.parents[1]                     # repo root
PROJECT_ROOT = REPO_ROOT                                # back-compat alias

DATA_DIR = Path(os.getenv("FORCASTL_DATA_DIR", REPO_ROOT / "data"))
METADATA_FILE = DATA_DIR / "metadata.json"
GROUND_TRUTH_FILE = DATA_DIR / "ground_truth_evidence.json"
OUTPUTS_DIR = Path(os.getenv("FORCASTL_OUTPUTS_DIR", REPO_ROOT / "outputs"))
DEFAULT_LLM_SERVER = os.getenv("LLM_SERVER_URL", "http://localhost:1234")


def require_data_dir() -> Path:
    """Return DATA_DIR, or exit with a clear message when the corpus is absent.

    A plain wheel install has no ``<repo>/data`` next to site-packages, and a
    bare ``FileNotFoundError`` deep in a run is a confusing way to find that
    out. Entry points that need the corpus call this first.
    """
    if METADATA_FILE.is_file() and GROUND_TRUTH_FILE.is_file():
        return DATA_DIR
    raise SystemExit(
        f"[ERROR] FORCAST-L corpus not found at {DATA_DIR}\n"
        f"  (missing {METADATA_FILE.name} / {GROUND_TRUTH_FILE.name})\n"
        "FORCAST-L is a clone-and-editable-install project: the dataset lives at\n"
        "<repo>/data. Either run from a git checkout (pip install -e .) or point\n"
        "FORCASTL_DATA_DIR at a directory containing the corpus."
    )


# ── Verdict thresholds ────────────────────────────────────────────────────────
# Drives the PASS / CAUTION / FAIL run-level verdict. Each driver has a PASS
# bound (best the threshold can be) and a FAIL bound (worst before forcing a
# FAIL tier). The space between is CAUTION. Higher-is-better for recall;
# lower-is-better for fp_rate and hallucination.
VERDICT_THRESHOLDS = {
    "recall":        {"pass": 90.0, "fail": 60.0},   # detection rate (%)
    "fp_rate":       {"pass": 10.0, "fail": 50.0},   # false-positive rate (%)
    "hallucination": {"pass": 10.0, "fail": 40.0},   # hallucination rate (%)
}


# ── Fuzzy evidence matching ───────────────────────────────────────────────────
# Per-field SequenceMatcher ratios a claimed value must reach to count as a
# match. Shared by ground-truth alignment (ground_truth_compare) and
# hallucination detection (hallucination) so the two scorers can never drift.
# event_ids is exact-matched and registry is substring-matched — no ratio.
# Note: hallucination keeps `network` exact (the ratio applies only on the
# ground-truth alignment side).
FUZZY_MATCH_THRESHOLDS = {
    "processes": 0.8,
    "accounts":  0.8,
    "commands":  0.6,
    "network":   0.9,
}
