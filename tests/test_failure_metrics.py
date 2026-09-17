"""Tests for failure-aware benchmark aggregates.

These cover the three pieces that together keep failed files from being
silently hidden from benchmark outcomes:

  - `compute_failure_adjusted_metrics`: core aggregator.
  - `records_from_detection_results`: adapter for detector's in-memory results.
  - `records_from_model_csv`: adapter for CSV-parsed per-model rows.
"""

import unittest

from forcastl.reporting.failure_metrics import (
    compute_failure_adjusted_metrics,
    records_from_detection_results,
    records_from_model_csv,
)


class ComputeFailureAdjustedMetricsTests(unittest.TestCase):

    def test_all_processed_malicious_tp(self):
        records = [
            {"status": "processed", "is_malicious_gt": True,
             "detected_malicious": True, "score_20": 18.0, "alignment_pct": 90.0},
            {"status": "processed", "is_malicious_gt": True,
             "detected_malicious": True, "score_20": 16.0, "alignment_pct": 80.0},
        ]
        m = compute_failure_adjusted_metrics(records)
        self.assertEqual(m["total_in_scope"], 2)
        self.assertEqual(m["total_malicious_in_scope"], 2)
        self.assertEqual(m["processed_count"], 2)
        self.assertEqual(m["failed_count"], 0)
        self.assertAlmostEqual(m["processed_coverage_pct"], 100.0)
        self.assertAlmostEqual(m["failure_rate_pct"], 0.0)
        self.assertAlmostEqual(m["malicious_outcome_recall"], 1.0)
        self.assertAlmostEqual(m["score20_adjusted_for_failures"], 17.0)
        self.assertAlmostEqual(m["alignment_adjusted_for_failures"], 85.0)

    def test_failures_pull_down_adjusted_metrics(self):
        """One of two malicious files fails -> adjusted metrics halve vs processed-only."""
        records = [
            {"status": "processed", "is_malicious_gt": True,
             "detected_malicious": True, "score_20": 20.0, "alignment_pct": 100.0},
            {"status": "error", "is_malicious_gt": True,
             "detected_malicious": None, "score_20": None, "alignment_pct": None},
        ]
        m = compute_failure_adjusted_metrics(records)
        # Recall: 1 TP / 2 malicious in scope
        self.assertAlmostEqual(m["malicious_outcome_recall"], 0.5)
        # Adj score: (20 + 0) / 2
        self.assertAlmostEqual(m["score20_adjusted_for_failures"], 10.0)
        # Adj alignment: (100 + 0) / 2
        self.assertAlmostEqual(m["alignment_adjusted_for_failures"], 50.0)
        self.assertAlmostEqual(m["processed_coverage_pct"], 50.0)
        self.assertAlmostEqual(m["failure_rate_pct"], 50.0)

    def test_context_exceeded_and_missing_count_as_misses(self):
        records = [
            {"status": "processed", "is_malicious_gt": True,
             "detected_malicious": True, "score_20": 18.0, "alignment_pct": 90.0},
            {"status": "context_exceeded", "is_malicious_gt": True,
             "detected_malicious": None, "score_20": None, "alignment_pct": None},
            {"status": "missing", "is_malicious_gt": True,
             "detected_malicious": None, "score_20": None, "alignment_pct": None},
        ]
        m = compute_failure_adjusted_metrics(records)
        # 1 TP / 3 malicious
        self.assertAlmostEqual(m["malicious_outcome_recall"], 1.0 / 3.0)
        self.assertAlmostEqual(m["score20_adjusted_for_failures"], 18.0 / 3.0)
        self.assertAlmostEqual(m["alignment_adjusted_for_failures"], 90.0 / 3.0)
        self.assertEqual(m["failed_count"], 2)

    def test_processed_but_detected_no_counts_as_miss(self):
        records = [
            {"status": "processed", "is_malicious_gt": True,
             "detected_malicious": False, "score_20": 10.0, "alignment_pct": 40.0},
        ]
        m = compute_failure_adjusted_metrics(records)
        # Processed but wrong verdict -> not a TP
        self.assertAlmostEqual(m["malicious_outcome_recall"], 0.0)
        # But score/alignment are included at their actual values (not zeroed),
        # because the model *did* process the file.
        self.assertAlmostEqual(m["score20_adjusted_for_failures"], 10.0)
        self.assertAlmostEqual(m["alignment_adjusted_for_failures"], 40.0)

    def test_benign_records_pass_through_totals_only(self):
        """Benign files affect coverage/failure counts but not malicious
        recall or malicious-scoped averages."""
        records = [
            {"status": "processed", "is_malicious_gt": True,
             "detected_malicious": True, "score_20": 20.0, "alignment_pct": 100.0},
            {"status": "processed", "is_malicious_gt": False,
             "detected_malicious": False, "score_20": 5.0, "alignment_pct": 10.0},
        ]
        m = compute_failure_adjusted_metrics(records)
        self.assertEqual(m["total_in_scope"], 2)
        self.assertEqual(m["total_malicious_in_scope"], 1)
        self.assertAlmostEqual(m["malicious_outcome_recall"], 1.0)
        self.assertAlmostEqual(m["score20_adjusted_for_failures"], 20.0)
        self.assertAlmostEqual(m["alignment_adjusted_for_failures"], 100.0)

    def test_empty_records(self):
        m = compute_failure_adjusted_metrics([])
        self.assertEqual(m["total_in_scope"], 0)
        self.assertEqual(m["total_malicious_in_scope"], 0)
        self.assertEqual(m["processed_count"], 0)
        self.assertEqual(m["failed_count"], 0)
        self.assertEqual(m["processed_coverage_pct"], 0.0)
        self.assertEqual(m["malicious_outcome_recall"], 0.0)
        self.assertEqual(m["score20_adjusted_for_failures"], 0.0)
        self.assertEqual(m["alignment_adjusted_for_failures"], 0.0)

    def test_none_score_on_processed_row_counts_as_zero(self):
        """Defensive: a processed row with a missing score_20 must not crash
        and must be treated as 0 for the adjusted average."""
        records = [
            {"status": "processed", "is_malicious_gt": True,
             "detected_malicious": True, "score_20": None, "alignment_pct": None},
            {"status": "processed", "is_malicious_gt": True,
             "detected_malicious": True, "score_20": 20.0, "alignment_pct": 100.0},
        ]
        m = compute_failure_adjusted_metrics(records)
        # Recall: both processed + detected malicious = 2/2
        self.assertAlmostEqual(m["malicious_outcome_recall"], 1.0)
        # Adj score: (0 + 20) / 2
        self.assertAlmostEqual(m["score20_adjusted_for_failures"], 10.0)


class RecordsFromDetectionResultsTests(unittest.TestCase):

    def test_processed_result_shape(self):
        results = [{
            "file_path": "data/sample.evtx",
            "status": "processed",
            "detection": {
                "is_malicious": True,
                "expected_evidence": {"malicious": "YES"},
                "score_breakdown": {"total": 18.0},
                "alignment": {"score": 85.0},
            },
        }]
        records = records_from_detection_results(results)
        self.assertEqual(len(records), 1)
        r = records[0]
        self.assertEqual(r["filename"], "sample.evtx")
        self.assertEqual(r["status"], "processed")
        self.assertTrue(r["is_malicious_gt"])
        self.assertTrue(r["detected_malicious"])
        self.assertEqual(r["score_20"], 18.0)
        self.assertEqual(r["alignment_pct"], 85.0)

    def test_errored_result_sets_none_and_preserves_status(self):
        results = [{
            "file_path": "data/bad.evtx",
            "status": "error",
            "detection": {"expected_evidence": {"malicious": "YES"}},
        }]
        records = records_from_detection_results(results)
        self.assertEqual(records[0]["status"], "error")
        self.assertTrue(records[0]["is_malicious_gt"])
        self.assertIsNone(records[0]["detected_malicious"])
        self.assertIsNone(records[0]["score_20"])
        self.assertIsNone(records[0]["alignment_pct"])


class RecordsFromModelCsvTests(unittest.TestCase):

    def _status(self, row):
        return (row.get("Status") or "processed").strip().lower()

    def _parse_float(self, v, default=0.0):
        try:
            return float(v)
        except (TypeError, ValueError):
            return default

    def test_missing_filename_becomes_missing_status(self):
        rows_by_filename = {
            "a.evtx": {"Filename": "a.evtx", "Malicious": "YES",
                       "Status": "processed", "Total (20)": "18", "Alignment %": "90"},
        }
        gt_files = {
            "a.evtx": {"malicious": "YES"},
            "b.evtx": {"malicious": "YES"},  # not in rows_by_filename
        }
        all_files = ["a.evtx", "b.evtx"]
        records = records_from_model_csv(
            rows_by_filename, gt_files, all_files, self._status, self._parse_float,
        )
        by_name = {r["filename"]: r for r in records}
        self.assertEqual(by_name["b.evtx"]["status"], "missing")
        self.assertIsNone(by_name["b.evtx"]["detected_malicious"])
        self.assertIsNone(by_name["b.evtx"]["score_20"])
        self.assertIsNone(by_name["b.evtx"]["alignment_pct"])
        # Present row gets populated.
        self.assertEqual(by_name["a.evtx"]["status"], "processed")
        self.assertTrue(by_name["a.evtx"]["detected_malicious"])
        self.assertEqual(by_name["a.evtx"]["score_20"], 18.0)
        self.assertEqual(by_name["a.evtx"]["alignment_pct"], 90.0)

    def test_non_processed_status_drops_numeric_fields(self):
        rows_by_filename = {
            "c.evtx": {"Filename": "c.evtx", "Status": "context_exceeded",
                       "Malicious": "", "Total (20)": "0", "Alignment %": "0"},
        }
        gt_files = {"c.evtx": {"malicious": "YES"}}
        all_files = ["c.evtx"]
        records = records_from_model_csv(
            rows_by_filename, gt_files, all_files, self._status, self._parse_float,
        )
        r = records[0]
        self.assertEqual(r["status"], "context_exceeded")
        self.assertIsNone(r["detected_malicious"])
        self.assertIsNone(r["score_20"])
        self.assertIsNone(r["alignment_pct"])


class ManifestIncludesFailureAdjustedTests(unittest.TestCase):
    """write_run_manifest must stamp both processed-only summary and the
    failure_adjusted block so downstream readers (web UI, CI scripts) can
    compare the two views."""

    def test_manifest_carries_failure_adjusted_block(self):
        import json
        import tempfile
        from pathlib import Path
        from unittest import mock

        from forcastl import config
        from forcastl.reporting.csv_output import write_run_manifest

        def _fake_summary(results):
            processed = [r for r in results if (r.get("status") or "processed") == "processed"]
            return {
                "total_files": len(results),
                "processed": len(processed),
                "failed": len(results) - len(processed),
                "context_exceeded": sum(1 for r in results if r.get("status") == "context_exceeded"),
                "error": sum(1 for r in results if r.get("status") == "error"),
                "malicious": 0, "benign": 0,
                "avg_alignment": 0.0, "avg_confidence": 0.0,
                "avg_score_20": 0.0, "avg_hallucination_rate": 0.0,
                "grade_dist": {},
                "correct_verdict_with_fabrication": 0,
                "correct_verdict_weak_evidence": 0,
            }

        results = [
            {
                "file_path": "data/ok.evtx",
                "status": "processed",
                "response_time": 1.0,
                "detection": {
                    "is_malicious": True,
                    "expected_evidence": {"malicious": "YES"},
                    "score_breakdown": {"total": 20.0, "grade": "A"},
                    "alignment": {"score": 100.0},
                    "hallucination": {"ratio": 0.0},
                    "confidence": 100.0,
                    "quality_flags": {},
                },
            },
            {
                "file_path": "data/err.evtx",
                "status": "context_exceeded",
                "response_time": 0.0,
                "detection": {
                    "expected_evidence": {"malicious": "YES"},
                },
            },
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            with mock.patch.object(config, "OUTPUTS_DIR", Path(tmpdir)):
                path = write_run_manifest(
                    run_id="fa-manifest-test",
                    started_at="2026-01-01T00:00:00",
                    finished_at="2026-01-01T00:00:10",
                    mode="sample",
                    sample_size=2,
                    results=results,
                    outputs={},
                    model_id="test-model",
                    input_format="evtx",
                    csv_dir=None,
                    max_tokens=1000,
                    timeout=120,
                    delay=0.5,
                    difficulty=None,
                    test_set=None,
                    server_url="http://x",
                    compute_run_summary=_fake_summary,
                )
            with open(path, encoding="utf-8") as f:
                manifest = json.load(f)

        self.assertIn("failure_adjusted", manifest)
        fa = manifest["failure_adjusted"]
        self.assertEqual(fa["total_in_scope"], 2)
        self.assertEqual(fa["total_malicious_in_scope"], 2)
        # 1 of 2 malicious processed & detected -> recall 0.5, adj score 10, adj align 50.
        self.assertAlmostEqual(fa["malicious_outcome_recall"], 0.5)
        self.assertAlmostEqual(fa["score20_adjusted_for_failures"], 10.0)
        self.assertAlmostEqual(fa["alignment_adjusted_for_failures"], 50.0)
        # Processed-only summary must still be present (backward compat).
        self.assertIn("summary", manifest)


if __name__ == "__main__":
    unittest.main()
