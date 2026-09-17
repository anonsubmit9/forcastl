#!/usr/bin/env python3
"""Re-score saved model responses against the CURRENT ground truth under the
frozen SCORING_VERSION — without re-calling any LLM.

Why this exists
---------------
The detection CSVs preserve the raw ``LLM Response`` per file. The scoring
pipeline (``process_file`` -> ``compute_detection`` -> ``compute_run_summary``)
is deterministic given (response, parsed artefact, ground truth). The ONLY
non-deterministic / paid step is the network call in ``send_to_llm``.

So to re-score a past run against today's curated ground truth, we replay each
saved response through the *real* pipeline with only ``send_to_llm`` swapped for
a lookup. This guarantees parity by construction: identical code path, identical
parsing, only the model answer is injected instead of fetched.

What it emits
-------------
- A fresh v1 manifest + CSV per model (``*_rescore_<suffix>``), stamped with the
  current ``SCORING_VERSION``, scored against the live ground_truth_evidence.json.
- A head-to-head table on the file set the models share (apples-to-apples).

Validation
----------
``--verify-against <manifest.json>`` re-scores a model's saved CSV and asserts
the verdict drivers match that manifest's stored summary, so you can confirm the
replay reproduces a known result *before* trusting the v1 numbers. Point it at
the run's own manifest using a GT snapshot from that run's date (e.g. via
``git stash``/checkout of data/) to prove the only difference is GT, not code.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from forcastl.cli.detect import MaliciousActivityDetector
from forcastl.reporting.csv_output import read_detection_csv
from forcastl.benchmark_contract import SCORING_VERSION


# Default best Full / Standard runs per model (verified 2026-06-17).
DEFAULT_CSVS = [
    "outputs/detection_results_claude-opus-4-8_20260612_170300.csv",
    "outputs/detection_results_gpt-5.5-2026-04-23_20260613_123806.csv",
    "outputs/detection_results_qwen3.6-27b_20260615_194908.csv",
]


class ReplayDetector(MaliciousActivityDetector):
    """A detector that returns SAVED responses instead of calling an LLM.

    Only ``send_to_llm`` is overridden — every other step (CSV parse, sampled
    evidence, artefact text, scoring, verdict) runs the production code path.
    """

    def attach_saved(self, model_id: str, saved: dict) -> "ReplayDetector":
        # saved: {stem: {"response": str, "time": float, "status": str}}
        self._saved = saved
        self._cur_stem = None
        # Stand in for setup_llm() so _get_model_id() and the manifest are right,
        # without any provider connection or API key (send_to_llm never calls out).
        self.selected_model = {"id": model_id, "name": model_id}
        self.server_url = "replay://saved-csv"
        return self

    def process_file(self, file_path: str, file_info: dict):
        self._cur_stem = Path(file_path).stem
        result = super().process_file(file_path, file_info)
        if not result:
            return result
        saved = self._saved.get(self._cur_stem)
        # 'sampled_evidence' is only present on process_file's success path. Its
        # absence means the artefact failed to parse NOW (corpus changed) — let
        # that error surface rather than masking it with the saved status.
        if "sampled_evidence" not in result:
            return result
        # Preserve the original run's terminal status (error/context_exceeded):
        # those are properties of the original call, not of ground truth, and the
        # saved response text doesn't always re-derive the same bucket. Only
        # 'processed' rows get re-scored against current GT.
        if saved and saved["status"] != "processed":
            result["status"] = saved["status"]
        return result

    def send_to_llm(self, prompt: str):  # noqa: ARG002 - prompt unused by design
        saved = self._saved.get(self._cur_stem)
        if not saved:
            return ("Error: no saved response for this file", 0)
        return (saved["response"], saved["time"])


def _load_saved(csv_path: Path) -> tuple[str, dict]:
    rows = read_detection_csv(csv_path)
    if not rows:
        raise SystemExit(f"No data rows in {csv_path}")
    model_id = rows[0]["Model"]
    saved = {}
    for r in rows:
        stem = Path(r["Filename"]).stem
        try:
            t = float(r.get("Response Time (s)") or 0)
        except ValueError:
            t = 0.0
        saved[stem] = {
            "response": r.get("LLM Response", ""),
            "time": t,
            "status": r.get("Status", "processed"),
        }
    return model_id, saved


def rescore_one(csv_path: Path, run_suffix: str, write_reports: bool = True):
    """Replay one saved CSV; return (detector, results_by_stem, summary, missing)."""
    model_id, saved = _load_saved(csv_path)
    print(f"\n{'='*70}\n{model_id}  ({len(saved)} saved files)  <- {csv_path.name}\n{'='*70}")

    det = ReplayDetector(verbose=False, include_benign=True).attach_saved(model_id, saved)
    files = det.select_files(mode="all")
    by_stem = {Path(fi["full_path"]).stem: fi for fi in files}

    results_by_stem: dict = {}
    missing = []
    for stem in saved:
        fi = by_stem.get(stem)
        if not fi:
            missing.append(stem)
            continue
        result = det.process_file(fi["full_path"], fi)
        det.compute_detection(result, fi)
        results_by_stem[stem] = result

    results = list(results_by_stem.values())
    summary = det._compute_run_summary(results)

    if write_reports:
        sel = [by_stem[s] for s in saved if s in by_stem]
        det.generate_reports(
            results, run_id=f"rescore_{run_suffix}", mode="all",
            sample_size=None, selected_files=sel,
        )

    if missing:
        print(f"  [!] {len(missing)} saved file(s) no longer in current corpus "
              f"(excluded): {', '.join(missing[:3])}{'...' if len(missing) > 3 else ''}")
    return det, results_by_stem, summary, missing


def _drivers(summary: dict) -> dict:
    v = summary.get("verdict", {}) or {}
    d = v.get("drivers", {}) or {}
    return {
        "tier": v.get("tier"),
        "recall": summary.get("recall_pct"),
        "fp": summary.get("fp_rate_pct"),
        "hall": summary.get("avg_hallucination_rate", 0) * 100,
        "n_mal": d.get("n_malicious"),
        "n_ben": d.get("n_benign"),
    }


def _fmt(x, suffix=""):
    return f"{x:.1f}{suffix}" if isinstance(x, (int, float)) else str(x)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csvs", nargs="*", default=DEFAULT_CSVS,
                    help="detection_results_*.csv paths (default: the three best runs)")
    ap.add_argument("--suffix", default="v1",
                    help="run_id suffix for emitted manifests/CSVs (default: v1)")
    ap.add_argument("--no-write", action="store_true",
                    help="compute + print only; do not write manifests/CSVs")
    ap.add_argument("--verify-against", metavar="MANIFEST",
                    help="re-score the FIRST csv and assert its drivers match this "
                         "manifest's stored summary (parity check; use a matching "
                         "GT snapshot)")
    args = ap.parse_args()

    print(f"Re-scoring against SCORING_VERSION = {SCORING_VERSION}")
    print("(ground truth read live from data/ground_truth_evidence.json)")

    if args.verify_against:
        import json
        det, by_stem, summary, _ = rescore_one(
            Path(args.csvs[0]), args.suffix, write_reports=False)
        ref = json.load(open(args.verify_against, encoding="utf-8"))["summary"]
        got, exp = _drivers(summary), _drivers({"verdict": ref.get("verdict", {}),
                                                "recall_pct": ref.get("recall_pct"),
                                                "fp_rate_pct": ref.get("fp_rate_pct"),
                                                "avg_hallucination_rate": ref.get("avg_hallucination_rate", 0)})
        ok = True
        print(f"\n{'metric':<10}{'replay':>12}{'manifest':>12}  match")
        for k in ("recall", "fp", "hall", "n_mal", "n_ben"):
            a, b = got[k], exp[k]
            m = (a is not None and b is not None
                 and abs((a or 0) - (b or 0)) < 0.05)
            ok = ok and m
            print(f"{k:<10}{_fmt(a):>12}{_fmt(b):>12}  {'OK' if m else 'DRIFT'}")
        print(f"\n{'PARITY OK' if ok else 'PARITY FAILED'} — "
              f"{'replay reproduces the manifest' if ok else 'investigate before trusting v1 numbers'}")
        sys.exit(0 if ok else 1)

    runs = []
    for c in args.csvs:
        det, by_stem, summary, missing = rescore_one(
            Path(c), args.suffix, write_reports=not args.no_write)
        runs.append((det, by_stem, summary))

    # Per-model v1 summary (each on all its own files).
    print(f"\n\n{'='*70}\nPER-MODEL v1 SUMMARY (each on its own file set)\n{'='*70}")
    print(f"{'model':<22}{'n_mal':>7}{'n_ben':>7}{'recall':>9}{'fp':>8}{'hall':>8}  verdict")
    for det, _, summary in runs:
        d = _drivers(summary)
        print(f"{det._get_model_id():<22}{_fmt(d['n_mal']):>7}{_fmt(d['n_ben']):>7}"
              f"{_fmt(d['recall'],'%'):>9}{_fmt(d['fp'],'%'):>8}{_fmt(d['hall'],'%'):>8}  {d['tier']}")

    # Apples-to-apples: restrict every model to the files they ALL share.
    common = set.intersection(*[set(by_stem) for _, by_stem, _ in runs])
    print(f"\n{'='*70}\nHEAD-TO-HEAD on {len(common)} shared files (identical GT + {SCORING_VERSION})\n{'='*70}")
    print(f"{'model':<22}{'n_mal':>7}{'n_ben':>7}{'recall':>9}{'fp':>8}{'hall':>8}  verdict")
    for det, by_stem, _ in runs:
        sub = [by_stem[s] for s in common]
        s = det._compute_run_summary(sub)
        d = _drivers(s)
        print(f"{det._get_model_id():<22}{_fmt(d['n_mal']):>7}{_fmt(d['n_ben']):>7}"
              f"{_fmt(d['recall'],'%'):>9}{_fmt(d['fp'],'%'):>8}{_fmt(d['hall'],'%'):>8}  {d['tier']}")
    print("\nNote: recall/fp denominators exclude errored-benign per the verdict "
          "error rule; errored-attack counts as a miss.")


if __name__ == "__main__":
    main()
