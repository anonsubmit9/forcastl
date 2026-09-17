"""Tests for aggregate_run_summaries — multi-run manifest aggregation."""
import unittest

from forcastl.reporting.run_summary import aggregate_run_summaries, compute_run_summary


def _result(fname, malicious, status="processed"):
    return {
        "file_path": f"x/{fname}",
        "status": status,
        "detection": {
            "is_malicious": malicious,
            "alignment": {"score": 80.0},
            "confidence": 90,
            "score_breakdown": {"total": 15.0, "grade": "B"},
            "hallucination": {"total_hallucinated": 0, "total_claimed": 4, "ratio": 0},
        },
    }


GT = {f"m{i}.evtx": {"malicious": "YES"} for i in range(35)}
GT.update({f"b{i}.evtx": {"malicious": "NO"} for i in range(30)})


def _run(tp_count):
    """A run catching `tp_count` of 35 attacks, no FPs."""
    results = []
    for i in range(35):
        results.append(_result(f"m{i}.evtx", malicious=(i < tp_count)))
    for i in range(30):
        results.append(_result(f"b{i}.evtx", malicious=False))
    return compute_run_summary(results, GT)


class AggregateRunSummariesTests(unittest.TestCase):
    def test_single_run_passthrough(self):
        s = _run(30)
        self.assertEqual(aggregate_run_summaries([s]), s)

    def test_mean_rates_and_verdict_from_means(self):
        runs = [_run(28), _run(32)]  # 80% and ~91.4% recall
        agg = aggregate_run_summaries(runs)
        self.assertAlmostEqual(agg["recall_pct"], (28 + 32) / 2 / 35 * 100, places=3)
        self.assertEqual(agg["runs"], 2)
        self.assertEqual(agg["true_positives"], 30)
        # Spread captures both runs.
        spread = agg["rate_spread"]["recall_pct"]
        self.assertAlmostEqual(spread["min"], 80.0, places=3)
        self.assertAlmostEqual(spread["max"], 32 / 35 * 100, places=3)
        # Verdict recomputed from the mean (85.7% recall -> caution band).
        self.assertEqual(agg["verdict"]["tier"], "caution")
        self.assertEqual(len(agg["per_run_rates"]), 2)
        self.assertEqual(agg["per_run_rates"][0]["recall_pct"], 80.0)

    def test_none_rates_survive(self):
        # No benign in scope -> fp_rate_pct None in every run.
        gt = {f"m{i}.evtx": {"malicious": "YES"} for i in range(35)}
        results = [_result(f"m{i}.evtx", malicious=True) for i in range(35)]
        s = compute_run_summary(results, gt)
        agg = aggregate_run_summaries([s, s])
        self.assertIsNone(agg["fp_rate_pct"])


if __name__ == "__main__":
    unittest.main()


class WilsonCiTests(unittest.TestCase):
    def test_ci_brackets_point_estimate(self):
        from forcastl.reporting.run_summary import wilson_ci_pct
        ci = wilson_ci_pct(30, 35)  # ~85.7%
        self.assertLess(ci["lo"], 30 / 35 * 100)
        self.assertGreater(ci["hi"], 30 / 35 * 100)
        self.assertGreaterEqual(ci["lo"], 0.0)
        self.assertLessEqual(ci["hi"], 100.0)

    def test_ci_none_on_zero_n(self):
        from forcastl.reporting.run_summary import wilson_ci_pct
        self.assertIsNone(wilson_ci_pct(0, 0))

    def test_summary_carries_cis(self):
        s = _run(30)
        self.assertIsNotNone(s["recall_ci_pct"])
        self.assertIsNotNone(s["fp_rate_ci_pct"])
        agg = aggregate_run_summaries([s, s])
        self.assertIsNotNone(agg["recall_ci_pct"])
