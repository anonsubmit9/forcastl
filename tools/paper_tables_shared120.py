#!/usr/bin/env python3
"""Compute Tables IV-VI for the paper on the UNIFORM shared-120 v1 set, plus the
true per-criterion reasoning-loss breakdown.

All three models, the same 120 artifacts, identical ground truth, frozen
SCORING_VERSION. Numbers come from the parity-verified replay pipeline
(tools/rescore_saved.py). Analysis only — prints; writes nothing.
"""
from __future__ import annotations

from pathlib import Path
from collections import defaultdict

from forcastl.benchmark_contract import SCORING_VERSION
from tools.rescore_saved import ReplayDetector, _load_saved, DEFAULT_CSVS

REASON_CRITERIA = ["substantive", "evidence-grounded", "consistent", "domain-aware"]
LABEL = {"claude-opus-4-8": "Claude Opus 4.8", "gpt-5.5-2026-04-23": "GPT-5.5",
         "qwen3.6-27b": "Qwen 3.6-27B"}


def run_all():
    runs = []
    for csv in DEFAULT_CSVS:
        model_id, saved = _load_saved(Path(csv))
        det = ReplayDetector(verbose=False, include_benign=True).attach_saved(model_id, saved)
        by_stem = {Path(fi["full_path"]).stem: fi for fi in det.select_files(mode="all")}
        per = {}
        for stem in saved:
            fi = by_stem.get(stem)
            if not fi:
                continue
            r = det.process_file(fi["full_path"], fi)
            det.compute_detection(r, fi)
            per[stem] = (r, fi)
        runs.append({"id": model_id, "det": det, "per": per})
    common = sorted(set.intersection(*[set(r["per"]) for r in runs]))
    return runs, common


def analyze(run, common):
    det, per = run["det"], run["per"]
    results = [per[s][0] for s in common]
    s = det._compute_run_summary(results)

    proc = [per[stem][0] for stem in common if per[stem][0].get("status") == "processed"]
    n_proc, n_err = len(proc), len(common) - len(proc)

    def bd(r):
        return r["detection"]["score_breakdown"]

    dims = {k: sum(bd(r)[k] for r in proc) / len(proc) for k in
            ("extraction", "interpretation", "hallucination", "reasoning")}
    mean20 = sum(bd(r)["total"] for r in proc) / len(proc)

    # det. acc = (TP+TN) / scored cases
    tp, tn, fp, fn = s["true_positives"], s["true_negatives"], s["false_positives"], s["false_negatives"]
    scored = tp + tn + fp + fn
    det_acc = 100 * (tp + tn) / scored if scored else 0

    # per-difficulty mean alignment/20
    by_diff = defaultdict(list)
    for stem in common:
        r, fi = per[stem]
        if r.get("status") != "processed":
            continue
        by_diff[(fi.get("difficulty") or "?").lower()].append(bd(r)["total"])
    diff = {d: (sum(v) / len(v), len(v)) for d, v in by_diff.items()}

    # reasoning: earn-rate per criterion (over processed files)
    earn = {c: 0 for c in REASON_CRITERIA}
    for r in proc:
        for c in r["detection"]["reasoning"].get("details", []):
            if c in earn:
                earn[c] += 1
    reason_rate = {c: 100 * earn[c] / len(proc) for c in REASON_CRITERIA}

    return {
        "id": run["id"], "n_proc": n_proc, "n_err": n_err,
        "mean20": mean20, "det_acc": det_acc,
        "recall": s["recall_pct"], "fp": s["fp_rate_pct"],
        "precision": s["precision_pct"], "hall": s["avg_hallucination_rate"] * 100,
        "dims": dims, "diff": diff, "reason_rate": reason_rate,
        "err_mal": s["errors_on_malicious"], "err_ben": s["errors_on_benign"],
    }


def main():
    runs, common = run_all()
    rows = [analyze(r, common) for r in runs]
    print(f"\nSCORING_VERSION = {SCORING_VERSION}  |  shared set = {len(common)} files "
          f"(uniform scope, all three models)\n")

    print("== Table IV: Aggregate (shared-120, v1) ==")
    print(f"{'Model':<16}{'Scored(err)':>12}{'Mean/20':>9}{'DetAcc':>8}"
          f"{'Recall':>8}{'FP':>7}{'Prec':>7}{'Hall':>7}")
    for r in rows:
        scored = f"{r['n_proc']} ({r['n_err']})"
        print(f"{LABEL[r['id']]:<16}{scored:>12}"
              f"{r['mean20']:>9.2f}{r['det_acc']:>7.1f}%{r['recall']:>7.1f}%"
              f"{r['fp']:>6.1f}%{r['precision']:>6.1f}%{r['hall']:>6.2f}%")

    print("\n== Table V: Per-dimension means (shared-120, v1) ==")
    print(f"{'Model':<16}{'Extract/6':>10}{'Interp/6':>10}{'HallRes/4':>11}{'Reason/4':>10}")
    for r in rows:
        d = r["dims"]
        print(f"{LABEL[r['id']]:<16}{d['extraction']:>10.2f}{d['interpretation']:>10.2f}"
              f"{d['hallucination']:>11.2f}{d['reasoning']:>10.2f}")

    print("\n== Table VI: Mean alignment/20 by difficulty (shared-120, v1) ==")
    print(f"{'Model':<16}{'Easy':>16}{'Medium':>16}{'Hard':>16}")
    for r in rows:
        def c(d):
            v = r["diff"].get(d)
            return f"{v[0]:.2f} (n={v[1]})" if v else "-"
        print(f"{LABEL[r['id']]:<16}{c('easy'):>16}{c('medium'):>16}{c('hard'):>16}")

    print("\n== Reasoning loss breakdown: % of processed files EARNING each /1 point ==")
    print(f"{'Model':<16}" + "".join(f"{c:>17}" for c in REASON_CRITERIA))
    for r in rows:
        print(f"{LABEL[r['id']]:<16}" +
              "".join(f"{r['reason_rate'][c]:>16.0f}%" for c in REASON_CRITERIA))
    print("\n(low earn-rate = where reasoning points are actually lost; max is 1.0/criterion)")


if __name__ == "__main__":
    main()
