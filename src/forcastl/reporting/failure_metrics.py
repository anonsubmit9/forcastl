"""Failure-aware benchmark aggregates.

The existing summary math averages only over *processed* files. That makes a
model that silently errors on hard artefacts look better than one that
actually answers them. This module produces a parallel view that treats
unprocessed malicious files as benchmark misses (zero score, zero alignment,
not detected) so readers see both:

  - processed-only quality metrics (existing, preserved)
  - failure-adjusted outcome metrics (new, this module)

The two views are kept distinct and labeled explicitly in all consumers.

The helper is corpus-agnostic in shape but this phase only targets malicious
cases, since the current corpus is malicious-only. Records for benign ground
truth are accepted and pass through the totals but do not affect
`malicious_outcome_recall`, `score20_adjusted_for_failures`, or
`alignment_adjusted_for_failures`, which are deliberately scoped to malicious
files.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


STATUS_PROCESSED = "processed"


def _is_processed(status: Optional[str]) -> bool:
    return (status or STATUS_PROCESSED).strip().lower() == STATUS_PROCESSED


def _pct(num: float, den: float) -> float:
    return (num / den * 100.0) if den else 0.0


def _ratio(num: float, den: float) -> float:
    return (num / den) if den else 0.0


def compute_failure_adjusted_metrics(
    records: Iterable[Dict[str, Any]],
) -> Dict[str, Any]:
    """Failure-aware aggregates over an iterable of per-file records.

    Each record must carry:
      - status: 'processed' | 'error' | 'context_exceeded' | 'missing' | ...
      - is_malicious_gt: bool (True iff ground truth says malicious)
      - detected_malicious: bool | None (model verdict, None if not processed)
      - score_20: float | None (composite score, None if not processed)
      - alignment_pct: float | None (0..100, None if not processed)

    Returns a dict with:
      - total_in_scope
      - total_malicious_in_scope
      - processed_count, failed_count
      - processed_coverage_pct, failure_rate_pct
      - malicious_outcome_recall (0..1): TP / total_malicious_in_scope,
        where failed/missing/context-exceeded malicious files count as misses.
      - score20_adjusted_for_failures: mean score over malicious-in-scope,
        substituting 0 for unprocessed/missing.
      - alignment_adjusted_for_failures: mean alignment over malicious-in-scope,
        substituting 0 for unprocessed/missing.
    """
    records = list(records)
    total = len(records)
    processed = sum(1 for r in records if _is_processed(r.get("status")))
    failed = total - processed

    malicious = [r for r in records if bool(r.get("is_malicious_gt"))]
    total_malicious = len(malicious)

    tp = sum(
        1 for r in malicious
        if _is_processed(r.get("status")) and bool(r.get("detected_malicious"))
    )

    def _zero_if_unprocessed(r: Dict[str, Any], key: str) -> float:
        if not _is_processed(r.get("status")):
            return 0.0
        v = r.get(key)
        return 0.0 if v is None else float(v)

    score_sum = sum(_zero_if_unprocessed(r, "score_20") for r in malicious)
    align_sum = sum(_zero_if_unprocessed(r, "alignment_pct") for r in malicious)

    return {
        "total_in_scope": total,
        "total_malicious_in_scope": total_malicious,
        "processed_count": processed,
        "failed_count": failed,
        "processed_coverage_pct": _pct(processed, total),
        "failure_rate_pct": _pct(failed, total),
        "malicious_outcome_recall": _ratio(tp, total_malicious),
        "score20_adjusted_for_failures": (
            (score_sum / total_malicious) if total_malicious else 0.0
        ),
        "alignment_adjusted_for_failures": (
            (align_sum / total_malicious) if total_malicious else 0.0
        ),
    }


# ── Adapters ─────────────────────────────────────────────────────────────────

def records_from_detection_results(
    results: Iterable[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Shape the detector's in-memory result list into failure-metrics records.

    Uses each result's attached `detection.expected_evidence.malicious` as the
    ground-truth label. Unprocessed results (status != 'processed') contribute
    a record with `status` preserved and score/alignment set to None.
    """
    out: List[Dict[str, Any]] = []
    for r in results or []:
        filename = Path(r.get("file_path", "")).name
        status = (r.get("status") or STATUS_PROCESSED)
        det = r.get("detection") or {}
        expected = (det.get("expected_evidence") or {}) or {}
        gt_is_malicious = expected.get("malicious") == "YES"
        if _is_processed(status):
            sb = det.get("score_breakdown") or {}
            align = det.get("alignment") or {}
            out.append({
                "filename": filename,
                "status": status,
                "is_malicious_gt": gt_is_malicious,
                "detected_malicious": bool(det.get("is_malicious")),
                "score_20": sb.get("total"),
                "alignment_pct": align.get("score"),
            })
        else:
            out.append({
                "filename": filename,
                "status": status,
                "is_malicious_gt": gt_is_malicious,
                "detected_malicious": None,
                "score_20": None,
                "alignment_pct": None,
            })
    return out


def records_from_model_csv(
    model_rows_by_filename: Dict[str, Dict[str, Any]],
    gt_files: Dict[str, Dict[str, Any]],
    all_files: List[str],
    status_fn,
    float_parser,
) -> List[Dict[str, Any]]:
    """Shape one model's CSV-parsed rows into failure-metrics records.

    `model_rows_by_filename` maps filename → CSV row dict.
    `gt_files` maps filename → {'malicious': 'YES'|'NO', ...}.
    `all_files` is the authoritative list of filenames in scope.
    `status_fn(row)` returns the normalized status string.
    `float_parser(value)` parses a numeric field tolerantly (used for
    Alignment % / Total (20)).

    Files absent from `model_rows_by_filename` are treated as `status='missing'`.
    """
    out: List[Dict[str, Any]] = []
    for filename in all_files:
        gt_entry = gt_files.get(filename, {}) or {}
        gt_is_malicious = gt_entry.get("malicious") == "YES"
        row = model_rows_by_filename.get(filename)
        if row is None:
            out.append({
                "filename": filename,
                "status": "missing",
                "is_malicious_gt": gt_is_malicious,
                "detected_malicious": None,
                "score_20": None,
                "alignment_pct": None,
            })
            continue
        status = status_fn(row) or STATUS_PROCESSED
        if _is_processed(status):
            out.append({
                "filename": filename,
                "status": status,
                "is_malicious_gt": gt_is_malicious,
                "detected_malicious": (row.get("Malicious") == "YES"),
                "score_20": float_parser(row.get("Total (20)")) if row.get("Total (20)") else None,
                "alignment_pct": float_parser(row.get("Alignment %")) if row.get("Alignment %") else None,
            })
        else:
            out.append({
                "filename": filename,
                "status": status,
                "is_malicious_gt": gt_is_malicious,
                "detected_malicious": None,
                "score_20": None,
                "alignment_pct": None,
            })
    return out
