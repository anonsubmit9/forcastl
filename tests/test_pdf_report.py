"""Tests for reporting/pdf_report.py — ensures PDF generation handles the
shapes of real manifest/CSV data without raising.

Skipped when no Chrome/Chromium binary is available (see ``pdf_export_available``).
"""
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from forcastl.reporting.pdf_report import (
    generate_pdf_report,
    pdf_export_available,
    _build_per_file,
    _build_run_config,
)

_requires_chromium = unittest.skipUnless(
    pdf_export_available(),
    "Chrome/Chromium not installed — PDF export tests skipped",
)


def _minimal_manifest():
    return {
        "run_id": "20260101_120000",
        "kind": "detection",
        "model": "test-model",
        "server": "http://example",
        "started_at": "2026-01-01T12:00:00",
        "finished_at": "2026-01-01T12:00:45",
        "mode": "sample",
        "sample_size": 3,
        "input_format": "csv",
        "context_window": 8192,
        "max_output_tokens": 1000,
        "timeout_s": 180,
        "delay_s": 0.2,
        "summary": {
            "total_files": 3, "processed": 3, "error": 0,
            "malicious": 2, "benign": 1,
            "avg_alignment": 85.0, "avg_hallucination_rate": 0.1,
            "avg_score_20": 17.3, "grade_dist": {"A": 2, "B": 1},
            "verdict": {
                "tier": "pass",
                "reasons": [
                    "Detection rate 100.0% meets PASS threshold (90%)",
                    "False-positive rate 0.0% within PASS threshold (10%)",
                    "Hallucination 10.0% within PASS threshold (10%)",
                ],
                "drivers": {
                    "recall_pct": 100.0,
                    "fp_rate_pct": 0.0,
                    "hallucination_pct": 10.0,
                },
                "has_benign": True,
                "insufficient": False,
            },
        },
        "outputs": {},
        "recommendations": [
            {"id": "r1", "severity": "warning", "title": "High hallucination",
             "description": "fabricated items", "affected_files": ["x.evtx"]},
            {"id": "r2", "severity": "info", "title": "All malicious",
             "description": "consider benign samples"},
        ],
        "files": [
            {"filename": "attack1.evtx", "status": "processed", "malicious": True,
             "alignment_pct": 100.0, "hallucination_rate": 0.0, "score_20": 19.0,
             "grade": "A", "verdict_matches_truth": True},
            {"filename": "attack2.evtx", "status": "processed", "malicious": True,
             "alignment_pct": 80.0, "hallucination_rate": 0.2, "score_20": 15.0,
             "grade": "B", "verdict_matches_truth": True},
            {"filename": "benign1.evtx", "status": "processed", "malicious": False,
             "alignment_pct": 100.0, "hallucination_rate": 0.0, "score_20": 18.0,
             "grade": "A", "verdict_matches_truth": True},
        ],
        "benchmark_contract": {"effective_config": {"temperature": 0.1}},
    }


@_requires_chromium
class PdfReportTests(unittest.TestCase):
    def test_generates_nonempty_pdf_for_minimal_manifest(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.pdf"
            generate_pdf_report(_minimal_manifest(), [], out)
            self.assertTrue(out.exists())
            data = out.read_bytes()
            self.assertTrue(data.startswith(b"%PDF-"))
            self.assertGreater(len(data), 1000)

    def test_handles_empty_manifest(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.pdf"
            generate_pdf_report({}, [], out)
            self.assertTrue(out.exists())
            self.assertTrue(out.read_bytes().startswith(b"%PDF-"))

    def test_handles_error_rows(self):
        m = _minimal_manifest()
        m["files"].append({
            "filename": "timed-out.evtx", "status": "error",
            "malicious": None, "alignment_pct": None, "hallucination_rate": None,
            "score_20": None, "grade": None, "verdict_matches_truth": None,
        })
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.pdf"
            generate_pdf_report(m, [], out)
            self.assertTrue(out.read_bytes().startswith(b"%PDF-"))

    def test_incorporates_csv_rows(self):
        csv_rows = [
            {"Filename": "attack1.evtx", "Malicious": "YES", "Grade": "A",
             "Alignment %": "100.0", "LLM Response": "MALICIOUS: YES\nEVIDENCE: ..."},
        ]
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.pdf"
            generate_pdf_report(_minimal_manifest(), csv_rows, out)
            self.assertTrue(out.exists())

    def test_confusion_matrix_when_ground_truth_has_benign(self):
        """When ground truth includes benign samples, the report renders the
        confusion-matrix page without raising — and the PDF is bigger because
        of the extra metrics block."""
        m = _minimal_manifest()
        # Add one benign file to the manifest
        m["files"].append({
            "filename": "benign-x.evtx", "status": "processed", "malicious": False,
            "alignment_pct": 100.0, "hallucination_rate": 0.0, "score_20": 18.0,
            "grade": "A",
        })
        gt = {
            "attack1.evtx": {"malicious": "YES"},
            "attack2.evtx": {"malicious": "YES"},
            "benign1.evtx": {"malicious": "NO"},
            "benign-x.evtx": {"malicious": "NO"},
        }
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.pdf"
            generate_pdf_report(m, [], out, ground_truth=gt)
            self.assertTrue(out.read_bytes().startswith(b"%PDF-"))

    def test_no_ground_truth_skips_confusion_matrix(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.pdf"
            generate_pdf_report(_minimal_manifest(), [], out, ground_truth=None)
            self.assertTrue(out.read_bytes().startswith(b"%PDF-"))

    def test_verdict_block_renders_for_each_tier(self):
        """The new _verdict_block should render without crashing for all
        tier values plus the insufficient-data fallback."""
        for tier in ("pass", "caution", "fail"):
            m = _minimal_manifest()
            m["summary"]["verdict"]["tier"] = tier
            with TemporaryDirectory() as tmp:
                out = Path(tmp) / f"report_{tier}.pdf"
                generate_pdf_report(m, [], out)
                self.assertTrue(out.read_bytes().startswith(b"%PDF-"))

    def test_verdict_insufficient_renders(self):
        m = _minimal_manifest()
        m["summary"]["verdict"]["insufficient"] = True
        m["summary"]["verdict"]["reasons"] = [
            "Detection rate not measured",
            "False-positive rate not measured",
        ]
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "report_insuff.pdf"
            generate_pdf_report(m, [], out)
            self.assertTrue(out.read_bytes().startswith(b"%PDF-"))

    def test_old_manifest_without_verdict_renders(self):
        """Backward compat: a manifest predating this feature should still
        produce a PDF — the verdict block is hidden."""
        m = _minimal_manifest()
        m["summary"].pop("verdict", None)
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "report_legacy.pdf"
            generate_pdf_report(m, [], out)
            self.assertTrue(out.read_bytes().startswith(b"%PDF-"))


class PerFileAppendixTests(unittest.TestCase):
    """Chromium-free: the per-file appendix must read the REAL detection-CSV
    headers (Filename / Malicious / Alignment % / Total (20) / Grade). A prior
    bug read lowercase keys, so every row rendered blank."""

    def _real_csv_row(self, **over):
        row = {
            "Model": "m", "Filename": "TA0006/attack1.evtx", "Difficulty": "easy",
            "Test Set": "A", "Status": "processed", "Malicious": "YES",
            "Confidence %": "90.0", "Alignment %": "100.0", "Structure Valid": "YES",
            "Hallucination %": "0.0", "Total (20)": "19.0", "Grade": "A",
            "LLM Response": "MALICIOUS: YES",
        }
        row.update(over)
        return row

    def test_reads_capitalized_csv_headers(self):
        rows = [self._real_csv_row()]
        gt = {"attack1.evtx": {"malicious": "YES"}}
        out = _build_per_file(rows, gt)
        self.assertEqual(len(out), 1)
        r = out[0]
        self.assertEqual(r["filename"], "attack1.evtx")  # basename, not blank
        self.assertEqual(r["verdict"], "YES")
        self.assertEqual(r["grade"], "A")
        self.assertEqual(r["align_pct"], 100)
        self.assertEqual(r["score_20"], 19)
        self.assertIs(r["is_match"], True)

    def test_verdict_mismatch_flagged(self):
        rows = [self._real_csv_row(Malicious="NO")]
        gt = {"attack1.evtx": {"malicious": "YES"}}
        self.assertIs(_build_per_file(rows, gt)[0]["is_match"], False)

    def test_error_row_has_no_match(self):
        rows = [self._real_csv_row(Status="error", Malicious="NO",
                                   **{"Alignment %": "", "Total (20)": "", "Grade": ""})]
        gt = {"attack1.evtx": {"malicious": "YES"}}
        r = _build_per_file(rows, gt)[0]
        self.assertIsNone(r["is_match"])
        self.assertIsNone(r["score_20"])

    def test_csv_filename_matches_evtx_keyed_ground_truth(self):
        """Webapp runs are always CSV, but ground truth is keyed by .evtx.
        The per-file Expected/match column must apply the same .csv->.evtx
        fallback as run_summary, or it renders blank while the KPIs don't."""
        rows = [self._real_csv_row(Filename="TA0006/attack1.csv", Malicious="YES")]
        gt = {"attack1.evtx": {"malicious": "YES"}}  # keyed by .evtx only
        r = _build_per_file(rows, gt)[0]
        self.assertEqual(r["filename"], "attack1.csv")
        self.assertEqual(r["expected"], "YES")     # resolved via fallback
        self.assertIs(r["is_match"], True)

    def test_legacy_lowercase_keys_still_supported(self):
        rows = [{"filename": "x.evtx", "malicious": "YES", "grade": "B",
                 "alignment": "80", "score_20": "15"}]
        r = _build_per_file(rows, {})[0]
        self.assertEqual(r["filename"], "x.evtx")
        self.assertEqual(r["grade"], "B")
        self.assertEqual(r["score_20"], 15)


class RunConfigAppendixTests(unittest.TestCase):
    """Chromium-free: run-config reads TOP-LEVEL manifest keys. A prior bug read
    a non-existent `config` sub-dict, so the appendix was always empty."""

    def test_reads_top_level_manifest_keys(self):
        manifest = _minimal_manifest()
        cfg = dict(_build_run_config(manifest))
        self.assertEqual(cfg.get("Mode"), "sample")
        self.assertEqual(cfg.get("Sample size"), "3")
        self.assertEqual(cfg.get("Input format"), "csv")
        self.assertEqual(cfg.get("Max output tokens"), "1000")
        self.assertEqual(cfg.get("Timeout (s)"), "180")
        self.assertTrue(cfg, "run-config must not be empty for a real manifest")

    def test_omits_missing_values(self):
        cfg = dict(_build_run_config({"mode": "all"}))
        self.assertEqual(cfg.get("Mode"), "all")
        self.assertNotIn("Sample size", cfg)

    def test_legacy_config_subdict_fallback(self):
        manifest = {"config": {"mode": "sample", "max_tokens": 500, "timeout": 120}}
        cfg = dict(_build_run_config(manifest))
        self.assertEqual(cfg.get("Mode"), "sample")
        self.assertEqual(cfg.get("Max output tokens"), "500")
        self.assertEqual(cfg.get("Timeout (s)"), "120")


if __name__ == "__main__":
    unittest.main()
