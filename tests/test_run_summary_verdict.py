"""Integration tests for `compute_run_summary` verdict + confusion-matrix
plumbing.

Feeds a fabricated results list to the live `compute_run_summary` function
and asserts the manifest carries TP/FP/TN/FN, recall, fp_rate, precision,
and the verdict block with correct values across the realistic scenarios:

  - mixed run with benigns: TP/FP/TN/FN all non-zero, recall + fp_rate measured
  - malicious-only run: fp_rate is None, has_benign_samples=False
  - error on malicious file: counted as miss in failure-adjusted recall
  - no malicious in scope: verdict tier='insufficient'

`compute_run_summary` is a module-level helper now; tests target it directly
without instantiating the heavy MaliciousActivityDetector.
"""
import pytest

from forcastl.cli.detect import compute_run_summary


def _make_result(filename, *, detected, status='processed'):
    """Shape a per-file record the way `compute_run_summary` consumes."""
    return {
        'file_path': f'/fake/path/{filename}',
        'status': status,
        'detection': {
            'is_malicious': detected,
            'alignment': {'score': 100.0 if detected else 0.0},
            'confidence': 80.0,
            'score_breakdown': {'total': 18.0, 'grade': 'A'},
            'hallucination': {'ratio': 0.05},
        },
    }


def _gt(*entries):
    """Build a ground_truth dict mapping filename -> {"malicious": YES|NO}."""
    return {fname: {'malicious': label} for fname, label in entries}


def test_perfect_run_with_benigns():
    """Clean run: all malicious correctly flagged, all benign correctly
    skipped → recall=100, fp=0, verdict=PASS. Uses ≥30 of each so the
    sample-size guard doesn't fire."""
    mal = [(f'm{i}.evtx', True) for i in range(30)]
    ben = [(f'b{i}.evtx', False) for i in range(30)]
    results = [_make_result(fn, detected=det) for fn, det in mal + ben]
    gt = _gt(*[(fn, 'YES') for fn, _ in mal], *[(fn, 'NO') for fn, _ in ben])
    s = compute_run_summary(results, gt)
    assert s['true_positives'] == 30
    assert s['false_negatives'] == 0
    assert s['false_positives'] == 0
    assert s['true_negatives'] == 30
    assert s['recall_pct'] == 100.0
    assert s['fp_rate_pct'] == 0.0
    assert s['precision_pct'] == 100.0
    assert s['has_benign_samples'] is True
    assert s['verdict']['tier'] == 'pass'


def test_misclassified_benign_drives_fp_rate():
    """Half of benigns misclassified → FP rate 50% → CAUTION tier.
    Uses ≥30 of each so the sample-size guard doesn't fire."""
    mal = [(f'm{i}.evtx', True) for i in range(30)]      # all TP
    ben = [(f'b{i}.evtx', i < 15) for i in range(30)]    # 15 FP, 15 TN
    results = [_make_result(fn, detected=det) for fn, det in mal + ben]
    gt = _gt(*[(fn, 'YES') for fn, _ in mal], *[(fn, 'NO') for fn, _ in ben])
    s = compute_run_summary(results, gt)
    assert s['false_positives'] == 15
    assert s['true_negatives'] == 15
    assert s['fp_rate_pct'] == 50.0
    assert s['verdict']['tier'] == 'caution'


def test_failure_adjusted_recall_counts_errors_as_misses():
    """Errors on malicious files count against recall (failure-adjusted).
    30 malicious in scope: 10 TP, 10 errors, 10 FN → recall = 33.3%."""
    mal_results = (
        [_make_result(f'tp{i}.evtx', detected=True) for i in range(10)] +
        [_make_result(f'er{i}.evtx', detected=False, status='error') for i in range(10)] +
        [_make_result(f'fn{i}.evtx', detected=False) for i in range(10)]
    )
    ben_results = [_make_result(f'b{i}.evtx', detected=False) for i in range(30)]
    results = mal_results + ben_results
    gt = _gt(
        *[(f'tp{i}.evtx', 'YES') for i in range(10)],
        *[(f'er{i}.evtx', 'YES') for i in range(10)],
        *[(f'fn{i}.evtx', 'YES') for i in range(10)],
        *[(f'b{i}.evtx',  'NO')  for i in range(30)],
    )
    s = compute_run_summary(results, gt)
    assert s['true_positives'] == 10
    assert s['false_negatives'] == 10
    assert s['errors_on_malicious'] == 10
    assert s['total_malicious_in_scope'] == 30
    # 10/30 = 33.33%, well below the 60% FAIL threshold
    assert round(s['recall_pct'], 1) == 33.3
    assert s['verdict']['tier'] == 'fail'


def test_errored_benign_excluded_from_fp_rate():
    """An errored benign isn't a false positive — there's no verdict to be
    wrong about. Denominator should not include the errored benign."""
    results = [
        _make_result('a.evtx', detected=True),
        _make_result('b.evtx', detected=False),                      # TN
        _make_result('c.evtx', detected=False, status='error'),      # excluded
    ]
    gt = _gt(('a.evtx', 'YES'), ('b.evtx', 'NO'), ('c.evtx', 'NO'))
    s = compute_run_summary(results, gt)
    assert s['false_positives'] == 0
    assert s['true_negatives'] == 1
    # benign-in-scope = 1 (only TN counted), fp_rate = 0/1 = 0%
    assert s['fp_rate_pct'] == 0.0


def test_malicious_only_run_no_benign_samples():
    """No benign samples → fp_rate is None, has_benign_samples=False, verdict
    still computes from recall + hallucination. Uses ≥30 mal so the
    sample-size guard doesn't fire."""
    mal = ([(f'tp{i}.evtx', True) for i in range(20)] +
           [(f'fn{i}.evtx', False) for i in range(10)])
    results = [_make_result(fn, detected=det) for fn, det in mal]
    gt = _gt(*[(fn, 'YES') for fn, _ in mal])
    s = compute_run_summary(results, gt)
    assert s['fp_rate_pct'] is None
    assert s['has_benign_samples'] is False
    assert s['recall_pct'] == pytest.approx(66.666, rel=1e-3)
    # Recall 66.67% is in caution band (60-90); verdict should be CAUTION
    assert s['verdict']['tier'] == 'caution'
    # And the no-benign caveat must appear in reasons
    assert any('FP rate not measured' in r for r in s['verdict']['reasons'])


def test_no_malicious_in_scope_marks_insufficient():
    """With zero malicious files in scope we cannot compute recall, so the
    verdict must abstain (tier='insufficient') rather than guess."""
    results = [
        _make_result('a.evtx', detected=False),
        _make_result('b.evtx', detected=False),
    ]
    gt = _gt(('a.evtx', 'NO'), ('b.evtx', 'NO'))
    s = compute_run_summary(results, gt)
    assert s['total_malicious_in_scope'] == 0
    assert s['recall_pct'] is None
    assert s['verdict']['tier'] == 'insufficient'


def test_summary_carries_all_verdict_schema_keys():
    """Manifest schema contract: all the new keys the plan promised must be
    present so downstream consumers (UI, PDF, comparison report) can rely on
    them without defensive `.get(...)` everywhere."""
    results = [_make_result('a.evtx', detected=True)]
    gt = _gt(('a.evtx', 'YES'))
    s = compute_run_summary(results, gt)
    expected_keys = {
        'true_positives', 'false_positives', 'true_negatives', 'false_negatives',
        'errors_on_malicious', 'total_malicious_in_scope', 'has_benign_samples',
        'recall_pct', 'fp_rate_pct', 'precision_pct', 'verdict',
    }
    assert expected_keys <= set(s.keys())
    # Verdict block contract
    v = s['verdict']
    assert {'tier', 'reasons', 'drivers', 'has_benign'} <= set(v.keys())
    assert {'recall_pct', 'fp_rate_pct', 'hallucination_pct'} <= set(v['drivers'].keys())


def test_no_ground_truth_skips_confusion_matrix():
    """Backward compat: callers that pass `{}` for ground_truth get TP/FP/TN/FN
    all zero — confusion matrix not derivable, but the rest of the summary
    (avg_alignment, avg_score, etc.) still computes."""
    results = [_make_result('a.evtx', detected=True)]
    s = compute_run_summary(results, {})
    assert s['true_positives'] == 0
    assert s['total_malicious_in_scope'] == 0
    assert s['recall_pct'] is None
    assert s['verdict']['tier'] == 'insufficient'
    # Other aggregates still work
    assert s['processed'] == 1
    assert s['avg_alignment'] == 100.0


def test_errored_benign_does_not_trigger_insufficient():
    """Regression: an errored benign is a reliability issue, not "insufficient
    data". The benign floor counts files IN SCOPE (selected), symmetric with
    malicious — so 30 benign selected clears the floor even if one errors.
    Previously n_benign was fp+tn, so a single errored benign dropped a 30-benign
    run to 29 and falsely read "insufficient"."""
    mal = [(f'm{i}.evtx', True) for i in range(35)]      # 35 attacks (all TP)
    ben = [(f'b{i}.evtx', False) for i in range(30)]     # 30 benign
    results = [_make_result(fn, detected=det) for fn, det in mal + ben]
    results[-1] = _make_result('b29.evtx', detected=False, status='error')  # 1 errors
    gt = _gt(*[(fn, 'YES') for fn, _ in mal], *[(fn, 'NO') for fn, _ in ben])
    s = compute_run_summary(results, gt)
    assert s['total_benign_in_scope'] == 30
    assert s['errors_on_benign'] == 1
    assert s['true_negatives'] + s['false_positives'] == 29   # only 29 scored
    assert s['verdict']['insufficient'] is False              # floor still met
    assert s['verdict']['drivers']['n_benign'] == 30
