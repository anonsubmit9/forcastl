import unittest

from forcastl.reporting.comparison_report import compute_file_matrix, compute_stats


class ComparisonReportParsingTests(unittest.TestCase):
    def test_compute_stats_tolerates_non_numeric_fields(self):
        model_data = {
            "model-a": {
                "file1.evtx": {
                    "Filename": "file1.evtx",
                    "Malicious": "YES",
                    "Alignment %": "N/A",
                    "Confidence %": "",
                    "Structure Valid": "YES",
                    "Response Time (s)": "bad",
                }
            }
        }
        gt_files = {"file1.evtx": {"malicious": "YES"}}
        all_files = ["file1.evtx"]
        model_order = ["model-a"]

        stats = compute_stats(model_data, gt_files, all_files, model_order)
        self.assertEqual(stats["model-a"]["avg_alignment"], 0)
        self.assertEqual(stats["model-a"]["avg_confidence"], 0)
        self.assertEqual(stats["model-a"]["avg_response_time"], 0)

    def test_compute_file_matrix_tolerates_non_numeric(self):
        model_data = {
            "model-a": {
                "file1.evtx": {
                    "Filename": "file1.evtx",
                    "Malicious": "YES",
                    "Alignment %": "n/a",
                    "Confidence %": None,
                    "Total (20)": "bad",
                    "Grade": "D",
                }
            }
        }
        gt_files = {"file1.evtx": {"malicious": "YES"}}
        rows = compute_file_matrix(model_data, gt_files, ["file1.evtx"], ["model-a"])
        m = rows[0]["models"]["model-a"]
        self.assertEqual(m["alignment"], 0)
        self.assertEqual(m["confidence"], 0)
        self.assertEqual(m["score_20"], 0)

    def test_missing_rows_are_counted_as_fn_for_malicious_files(self):
        model_data = {
            "model-a": {
                "file1.evtx": {
                    "Filename": "file1.evtx",
                    "Malicious": "YES",
                    "Alignment %": "90",
                    "Confidence %": "90",
                    "Structure Valid": "YES",
                    "Response Time (s)": "1.0",
                }
            }
        }
        gt_files = {
            "file1.evtx": {"malicious": "YES"},
            "file2.evtx": {"malicious": "YES"},
        }
        all_files = ["file1.evtx", "file2.evtx"]
        stats = compute_stats(model_data, gt_files, all_files, ["model-a"])
        self.assertEqual(stats["model-a"]["tp"], 1)
        self.assertEqual(stats["model-a"]["fn"], 1)
        self.assertEqual(stats["model-a"]["missing"], 1)
        self.assertAlmostEqual(stats["model-a"]["recall"], 0.5)

    def test_compute_file_matrix_marks_missing_rows(self):
        model_data = {"model-a": {}}
        gt_files = {"file1.evtx": {"malicious": "YES"}}
        rows = compute_file_matrix(model_data, gt_files, ["file1.evtx"], ["model-a"])
        m = rows[0]["models"]["model-a"]
        self.assertEqual(m["detected"], "MISSING")
        self.assertEqual(m["alignment"], 0.0)
        self.assertEqual(m["confidence"], 0.0)


if __name__ == "__main__":
    unittest.main()
