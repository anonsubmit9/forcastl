"""Run-level summary aggregation for corpus detection manifests."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

# Fields averaged across repeat runs (None-aware mean).
_RATE_FIELDS = (
    "recall_pct", "precision_pct", "fp_rate_pct", "confabulation_rate_pct",
    "avg_alignment", "avg_confidence", "avg_score_20", "avg_hallucination_rate",
)
# Integer fields averaged then rounded (every run scores the same file list,
# so per-run counts are directly comparable).
_COUNT_FIELDS = (
    "total_files", "processed", "failed", "context_exceeded", "error",
    "malicious", "benign", "true_positives", "true_negatives",
    "false_positives", "false_negatives", "errors_on_malicious",
    "errors_on_benign", "total_hallucinated_fields", "total_claimed_fields",
    "fp_with_hallucination",
)


def wilson_ci_pct(k: int, n: int, z: float = 1.96) -> Optional[Dict[str, float]]:
    """95% Wilson score interval for a binomial proportion, in percent.

    Reported alongside recall/FP point estimates so small-sample runs are
    honest about their precision (e.g. 30/35 caught reads ~86% with a CI of
    roughly 71-94%).
    """
    if n <= 0:
        return None
    p = k / n
    z2 = z * z
    denom = 1 + z2 / n
    centre = (p + z2 / (2 * n)) / denom
    half = (z * ((p * (1 - p) / n + z2 / (4 * n * n)) ** 0.5)) / denom
    return {
        "lo": round(max(0.0, centre - half) * 100.0, 1),
        "hi": round(min(1.0, centre + half) * 100.0, 1),
    }


def compute_run_summary(
    results: List[Dict],
    ground_truth: Optional[Dict] = None,
) -> Dict:
    """Aggregate per-file results into a manifest summary block.

    `ground_truth` is the same dict shape the detector loads from
    `ground_truth_evidence.json`'s `files` key — keyed by filename, with
    values containing at minimum `{"malicious": "YES" | "NO"}`.
    """
    from forcastl.core.verdict import compute_verdict

    ground_truth = ground_truth or {}

    def _status(r: Dict) -> str:
        return (r.get('status') or 'processed').strip().lower()

    processed = [r for r in results if _status(r) == 'processed']
    failed = [r for r in results if _status(r) != 'processed']
    ctx = sum(1 for r in failed if _status(r) == 'context_exceeded')
    err = sum(1 for r in failed if _status(r) == 'error')

    malicious_count = sum(
        1 for r in processed if r.get('detection', {}).get('is_malicious', False)
    )
    benign_count = len(processed) - malicious_count

    alignments = [
        r.get('detection', {}).get('alignment', {}).get('score')
        for r in processed if r.get('detection', {}).get('alignment')
    ]
    alignments = [a for a in alignments if a is not None]
    avg_alignment = sum(alignments) / len(alignments) if alignments else 0.0

    confidences = [
        r.get('detection', {}).get('confidence', 0)
        for r in processed if r.get('detection')
    ]
    avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0

    scores = [
        r.get('detection', {}).get('score_breakdown', {}).get('total', 0)
        for r in processed if r.get('detection', {}).get('score_breakdown')
    ]
    avg_score = sum(scores) / len(scores) if scores else 0.0

    total_hallucinated_fields = sum(
        (r.get('detection', {}).get('hallucination') or {}).get('total_hallucinated', 0)
        for r in processed
    )
    total_claimed_fields = sum(
        (r.get('detection', {}).get('hallucination') or {}).get('total_claimed', 0)
        for r in processed
    )
    avg_hallucination_rate = (
        total_hallucinated_fields / total_claimed_fields if total_claimed_fields else 0.0
    )

    grades = [
        r.get('detection', {}).get('score_breakdown', {}).get('grade', '')
        for r in processed if r.get('detection', {}).get('score_breakdown')
    ]
    grade_dist = {}
    for g in grades:
        if g:
            grade_dist[g] = grade_dist.get(g, 0) + 1

    tp = fp = tn = fn = 0
    err_on_mal = 0
    err_on_benign = 0
    total_malicious_in_scope = 0
    total_benign_in_scope = 0
    has_benign = False
    fp_with_hallucination = 0
    for r in results:
        fname = Path(r.get('file_path', '') or '').name
        gt_entry = ground_truth.get(fname)
        if gt_entry is None and fname.lower().endswith('.csv'):
            gt_entry = ground_truth.get(fname[:-4] + '.evtx')
        truth = (gt_entry or {}).get('malicious')
        is_processed = _status(r) == 'processed'
        if truth == 'YES':
            total_malicious_in_scope += 1
            if not is_processed:
                err_on_mal += 1
            elif r.get('detection', {}).get('is_malicious'):
                tp += 1
            else:
                fn += 1
        elif truth == 'NO':
            has_benign = True
            total_benign_in_scope += 1
            if not is_processed:
                err_on_benign += 1
            if is_processed:
                if r.get('detection', {}).get('is_malicious'):
                    fp += 1
                hall_ratio = (r.get('detection', {}).get('hallucination') or {}).get('ratio', 0)
                if r.get('detection', {}).get('is_malicious') and hall_ratio and hall_ratio > 0:
                    fp_with_hallucination += 1
                if not r.get('detection', {}).get('is_malicious'):
                    tn += 1

    # Error rule (applies to both rates, documented for the paper): an errored
    # or context-exceeded ATTACK file stays in the recall denominator — a file
    # the model could not process is a missed detection. An errored BENIGN
    # file is excluded from the FP-rate denominator — it produced no verdict
    # to be false about (it is surfaced via errors_on_benign instead).
    recall_pct = (100.0 * tp / total_malicious_in_scope if total_malicious_in_scope else None)
    fp_rate_pct = (100.0 * fp / (fp + tn)) if (fp + tn) else None
    precision_pct = (100.0 * tp / (tp + fp)) if (tp + fp) else None
    confabulation_rate_pct = (100.0 * fp_with_hallucination / fp) if fp else None
    recall_ci_pct = wilson_ci_pct(tp, total_malicious_in_scope)
    fp_rate_ci_pct = wilson_ci_pct(fp, fp + tn)

    verdict = compute_verdict(
        recall_pct=recall_pct,
        fp_rate_pct=fp_rate_pct,
        hallucination_pct=avg_hallucination_rate * 100.0,
        has_benign_samples=has_benign,
        n_malicious=total_malicious_in_scope,
        # Count benign IN-SCOPE (selected), symmetric with malicious — an errored
        # benign is a reliability issue (surfaced via errors_on_benign), not an
        # "insufficient sample". Previously this was fp+tn, so one errored benign
        # dropped a 30-benign run under the floor and falsely read "insufficient".
        n_benign=total_benign_in_scope,
        tp=tp,
        fp=fp,
    )

    return {
        "total_files": len(results),
        "processed": len(processed),
        "failed": len(failed),
        "context_exceeded": ctx,
        "error": err,
        "malicious": malicious_count,
        "benign": benign_count,
        "avg_alignment": avg_alignment,
        "avg_confidence": avg_confidence,
        "avg_score_20": avg_score,
        "avg_hallucination_rate": avg_hallucination_rate,
        "total_hallucinated_fields": total_hallucinated_fields,
        "total_claimed_fields": total_claimed_fields,
        "grade_dist": grade_dist,
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "errors_on_malicious": err_on_mal,
        "errors_on_benign": err_on_benign,
        "total_malicious_in_scope": total_malicious_in_scope,
        "total_benign_in_scope": total_benign_in_scope,
        "has_benign_samples": has_benign,
        "recall_pct": recall_pct,
        "recall_ci_pct": recall_ci_pct,
        "precision_pct": precision_pct,
        "fp_rate_pct": fp_rate_pct,
        "fp_rate_ci_pct": fp_rate_ci_pct,
        "fp_with_hallucination": fp_with_hallucination,
        "confabulation_rate_pct": confabulation_rate_pct,
        "verdict": verdict,
    }


def aggregate_run_summaries(per_run: List[Dict]) -> Dict:
    """Combine N repeat-run summaries (same file list each run) into one.

    Headline rates are the across-run MEAN and the verdict is recomputed from
    those means — previously the manifest silently reported the last run only.
    Per-run rates and min/max spread stay in the summary so run-to-run
    variance is visible alongside the point estimate.
    """
    from forcastl.core.verdict import compute_verdict

    if not per_run:
        return {}
    if len(per_run) == 1:
        return per_run[0]

    def _mean(values):
        vals = [v for v in values if v is not None]
        return (sum(vals) / len(vals)) if vals else None

    agg = dict(per_run[-1])  # same scope fields (in-scope counts, has_benign) every run

    for f in _RATE_FIELDS:
        agg[f] = _mean([s.get(f) for s in per_run])
    for f in _COUNT_FIELDS:
        m = _mean([s.get(f) for s in per_run])
        agg[f] = int(round(m)) if m is not None else 0

    grade_dist: Dict[str, float] = {}
    for s in per_run:
        for g, n in (s.get("grade_dist") or {}).items():
            grade_dist[g] = grade_dist.get(g, 0) + n
    agg["grade_dist"] = {g: int(round(n / len(per_run))) for g, n in grade_dist.items()}

    agg["recall_ci_pct"] = wilson_ci_pct(
        agg["true_positives"], agg.get("total_malicious_in_scope", 0))
    agg["fp_rate_ci_pct"] = wilson_ci_pct(
        agg["false_positives"], agg["false_positives"] + agg["true_negatives"])

    hall_pct = (agg["avg_hallucination_rate"] or 0.0) * 100.0
    agg["verdict"] = compute_verdict(
        recall_pct=agg["recall_pct"],
        fp_rate_pct=agg["fp_rate_pct"],
        hallucination_pct=hall_pct,
        has_benign_samples=agg.get("has_benign_samples", False),
        n_malicious=agg.get("total_malicious_in_scope", 0),
        n_benign=agg.get("total_benign_in_scope", 0),
        tp=agg["true_positives"],
        fp=agg["false_positives"],
    )

    def _spread(field, scale=1.0):
        vals = [s.get(field) for s in per_run if s.get(field) is not None]
        return {"min": min(vals) * scale, "max": max(vals) * scale} if vals else None

    agg["runs"] = len(per_run)
    agg["rate_spread"] = {
        "recall_pct": _spread("recall_pct"),
        "fp_rate_pct": _spread("fp_rate_pct"),
        "hallucination_pct": _spread("avg_hallucination_rate", scale=100.0),
    }
    agg["per_run_rates"] = [
        {
            "run": i + 1,
            "recall_pct": s.get("recall_pct"),
            "fp_rate_pct": s.get("fp_rate_pct"),
            "hallucination_pct": (s.get("avg_hallucination_rate") or 0.0) * 100.0,
            "verdict_tier": (s.get("verdict") or {}).get("tier"),
        }
        for i, s in enumerate(per_run)
    ]
    return agg
