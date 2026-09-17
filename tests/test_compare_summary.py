"""compare._summary_row: GT-based comparison-table rows (recall/FP, not 'called malicious')."""
import unittest

from forcastl.cli.compare import _summary_row


def _summary(**over):
    base = {
        "total_files": 65, "processed": 63, "failed": 2,
        "true_positives": 30, "false_positives": 1, "total_malicious_in_scope": 35,
        "recall_pct": 85.7, "fp_rate_pct": 3.3, "recall_ci_pct": {"lo": 70.6, "hi": 93.7},
        "avg_alignment": 88.0, "avg_confidence": 91.0,
    }
    base.update(over)
    return base


class SummaryRowTests(unittest.TestCase):
    def test_recall_and_fp_from_ground_truth(self):
        row = _summary_row("m", _summary(), elapsed_s=600, csv_file="a.csv", html_file="a.html")
        # The row reports GT-derived recall/FP, not malicious/processed.
        self.assertEqual(row["recall"], "85.7%")
        self.assertEqual(row["fp_rate"], "3.3%")
        self.assertEqual(row["true_positives"], 30)
        self.assertEqual(row["total_malicious_in_scope"], 35)
        self.assertEqual(row["recall_ci_95"], "71-94%")
        self.assertEqual(row["runtime_min"], "10.0")
        self.assertEqual(row["csv_file"], "a.csv")

    def test_none_recall_renders_na(self):
        # No malicious in scope → recall_pct/ci None → "N/A", not a crash.
        row = _summary_row("m", _summary(recall_pct=None, recall_ci_pct=None),
                           elapsed_s=0, csv_file="", html_file="")
        self.assertEqual(row["recall"], "N/A")
        self.assertEqual(row["recall_ci_95"], "N/A")

    def test_none_fp_rate_renders_na(self):
        # No benign in scope → fp_rate_pct None → "N/A".
        row = _summary_row("m", _summary(fp_rate_pct=None), elapsed_s=0,
                           csv_file="", html_file="")
        self.assertEqual(row["fp_rate"], "N/A")


if __name__ == "__main__":
    unittest.main()
