"""Tests for reporting/html_report.py"""
import os
import tempfile
import unittest

from forcastl.reporting.html_report import (
    _is_error_result,
    _GRADE_COLORS,
    generate_file_result_html,
    generate_detection_html_report,
)


# ── Fixtures ─────────────────────────────────────────────────────────────────

def _normal_result(malicious=True, score=18.0, grade="A", alignment=90.0,
                   confidence=100.0, response_time=5.0, filename="test.evtx",
                   llm_response="MALICIOUS: YES\nEVIDENCE:\n- Event IDs: 4688\nEXPLANATION: Attack."):
    """Build a minimal valid detection result for testing."""
    return {
        "file_path": f"data/{filename}",
        "llm_response": llm_response,
        "prompt": "Analyze this file...",
        "response_time": response_time,
        "status": "processed",
        "detection": {
            "is_malicious": malicious,
            "confidence": confidence,
            "parsed": {"malicious": "YES" if malicious else "NO"},
            "validation": {"is_valid": True, "evidence_fields_populated": 4, "issues": []},
            "alignment": {
                "score": alignment,
                "malicious_match": True,
                "field_matches": {
                    "event_ids": {"expected": ["4688"], "detected": ["4688"], "score": 100},
                    "processes": {"expected": ["cmd.exe"], "detected": ["cmd.exe"], "score": 100},
                },
            },
            "score_breakdown": {
                "extraction": 5.4,
                "interpretation": 6.0,
                "hallucination": 3.6,
                "reasoning": 3.0,
                "total": score,
                "grade": grade,
            },
            "hallucination": {
                "total_hallucinated": 0,
                "total_claimed": 4,
                "score": 4,
                "ratio": 0.0,
                "hallucinated": {},
            },
            "reasoning": {
                "score": 3,
                "details": ["substantive", "references evidence", "consistent"],
            },
        },
    }


def _error_result(status="error", llm_response="Something went wrong", filename="error.evtx"):
    return {
        "file_path": f"data/{filename}",
        "llm_response": llm_response,
        "prompt": "",
        "response_time": 0,
        "status": status,
        "detection": {},
    }


# ── _is_error_result ─────────────────────────────────────────────────────────

class TestIsErrorResult(unittest.TestCase):
    def test_normal_result_returns_empty(self):
        self.assertEqual(_is_error_result(_normal_result()), "")

    def test_context_exceeded(self):
        r = _error_result(status="context_exceeded")
        self.assertEqual(_is_error_result(r), "Context Exceeded")

    def test_generic_error(self):
        r = _error_result(status="error", llm_response="Unknown failure")
        self.assertEqual(_is_error_result(r), "Error")

    def test_timeout_error(self):
        r = _error_result(status="error", llm_response="Request timed out after 120s")
        self.assertEqual(_is_error_result(r), "Timeout")

    def test_parse_error(self):
        r = _error_result(status="error", llm_response="Failed to parse EVTX file")
        self.assertEqual(_is_error_result(r), "Parse Error")

    def test_parse_error_variant(self):
        r = _error_result(status="error", llm_response="parse error in event data")
        self.assertEqual(_is_error_result(r), "Parse Error")

    def test_missing_status_returns_empty(self):
        self.assertEqual(_is_error_result({}), "")

    def test_processed_status_returns_empty(self):
        self.assertEqual(_is_error_result({"status": "processed"}), "")


# ── generate_file_result_html: error results ─────────────────────────────────

class TestFileResultHtmlErrors(unittest.TestCase):
    def test_error_result_has_error_badge(self):
        html = generate_file_result_html(_error_result(), 0)
        self.assertIn("badge-error", html)
        self.assertIn("ERROR", html)

    def test_error_result_has_orange_border(self):
        html = generate_file_result_html(_error_result(), 0)
        self.assertIn("border-left: 4px solid #e67e22", html)

    def test_error_result_has_data_category_error(self):
        html = generate_file_result_html(_error_result(), 0)
        self.assertIn('data-category="error"', html)

    def test_context_exceeded_shows_label(self):
        r = _error_result(status="context_exceeded", llm_response="Context exceeded: 26000 > 6992")
        html = generate_file_result_html(r, 0)
        self.assertIn("Context Exceeded", html)

    def test_error_html_escapes_response(self):
        r = _error_result(llm_response='<script>alert("xss")</script>')
        html = generate_file_result_html(r, 0)
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)


# ── generate_file_result_html: normal results ────────────────────────────────

class TestFileResultHtmlNormal(unittest.TestCase):
    def test_malicious_badge(self):
        html = generate_file_result_html(_normal_result(malicious=True), 0)
        self.assertIn("badge-malicious", html)
        self.assertIn("MALICIOUS", html)

    def test_benign_badge(self):
        html = generate_file_result_html(_normal_result(malicious=False), 0)
        self.assertIn("badge-benign", html)
        self.assertIn("BENIGN", html)

    def test_grade_colored_left_border(self):
        for grade, color in _GRADE_COLORS.items():
            html = generate_file_result_html(_normal_result(grade=grade), 0)
            self.assertIn(f"border-left: 4px solid {color}", html,
                          f"Grade {grade} should have border color {color}")

    def test_data_attributes_for_filtering(self):
        html = generate_file_result_html(_normal_result(malicious=True, score=18.0, alignment=90.0), 0)
        self.assertIn('data-category="malicious"', html)
        self.assertIn('data-score="18.0"', html)
        self.assertIn('data-alignment="90.0"', html)
        self.assertIn('data-index="0"', html)

    def test_data_category_benign(self):
        html = generate_file_result_html(_normal_result(malicious=False), 0)
        self.assertIn('data-category="benign"', html)

    def test_score_bar_hides_zero_segments(self):
        r = _normal_result()
        r["detection"]["score_breakdown"]["reasoning"] = 0
        html = generate_file_result_html(r, 0)
        self.assertNotIn("seg-reasoning", html)
        self.assertIn("seg-extraction", html)

    def test_score_bar_shows_all_nonzero_segments(self):
        html = generate_file_result_html(_normal_result(), 0)
        self.assertIn("seg-extraction", html)
        self.assertIn("seg-interpretation", html)
        self.assertIn("seg-hallucination", html)
        self.assertIn("seg-reasoning", html)

    def test_header_contains_metrics(self):
        html = generate_file_result_html(_normal_result(confidence=95.0, alignment=80.0), 0)
        self.assertIn("Confidence: 95%", html)
        self.assertIn("Alignment: 80%", html)

    def test_response_time_in_header(self):
        html = generate_file_result_html(_normal_result(response_time=12.345), 0)
        self.assertIn("12.3s", html)

    def test_llm_response_in_details_element(self):
        html = generate_file_result_html(_normal_result(), 0)
        self.assertIn("<details>", html)
        self.assertIn("Click to view raw LLM response", html)

    def test_filename_displayed(self):
        html = generate_file_result_html(_normal_result(filename="MyFile.evtx"), 0)
        self.assertIn("MyFile.evtx", html)

    def test_two_column_grid_layout(self):
        html = generate_file_result_html(_normal_result(), 0)
        self.assertIn("file-content-grid", html)
        self.assertIn("file-content-left", html)
        self.assertIn("file-content-right", html)

    def test_gt_table_rendered(self):
        html = generate_file_result_html(_normal_result(), 0)
        self.assertIn("gt-table", html)
        self.assertIn("Ground Truth Alignment", html)

    def test_gt_low_score_row_highlighted(self):
        r = _normal_result()
        r["detection"]["alignment"]["field_matches"]["processes"]["score"] = 30
        html = generate_file_result_html(r, 0)
        self.assertIn("gt-row-low", html)

    def test_hallucination_pills_when_present(self):
        r = _normal_result()
        r["detection"]["hallucination"]["total_hallucinated"] = 1
        r["detection"]["hallucination"]["hallucinated"] = {
            "network": ["88.88.88.88"]
        }
        html = generate_file_result_html(r, 0)
        self.assertIn("hall-pill", html)
        self.assertIn("88.88.88.88", html)

    def test_no_hallucination_pills_when_clean(self):
        html = generate_file_result_html(_normal_result(), 0)
        self.assertNotIn("hall-pill", html)

    def test_format_warning_on_xml_echo(self):
        r = _normal_result(llm_response="<Event xmlns='http://schemas.microsoft.com/win'>...</Event>")
        html = generate_file_result_html(r, 0)
        self.assertIn("Format Warning", html)
        self.assertIn("XML Echo Detected", html)

    def test_format_warning_on_raw_echo(self):
        r = _normal_result(llm_response="WINDOWS EVENT LOG DATA:\nsome data here")
        html = generate_file_result_html(r, 0)
        self.assertIn("Format Warning", html)

    def test_no_format_warning_on_normal_response(self):
        html = generate_file_result_html(_normal_result(), 0)
        self.assertNotIn("Format Warning", html)

    def test_no_score_data_message(self):
        r = _normal_result()
        r["detection"]["score_breakdown"] = {}
        html = generate_file_result_html(r, 0)
        self.assertIn("No score data available", html)

    def test_no_ground_truth_message(self):
        r = _normal_result()
        r["detection"]["alignment"] = {}
        html = generate_file_result_html(r, 0)
        self.assertIn("No ground truth available", html)

    def test_html_escapes_filename_in_attribute(self):
        r = _normal_result(filename='file"with"quotes.evtx')
        html = generate_file_result_html(r, 0)
        self.assertIn("data-filename=", html)
        self.assertNotIn('data-filename="file"with"', html)


# ── generate_detection_html_report ────────────────────────────────────────────

class TestDetectionHtmlReport(unittest.TestCase):
    def test_generates_html_file(self):
        results = [_normal_result()]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_detection_html_report(
                results, "test-model", 8192,
                output_dir=tmpdir, run_id="test001"
            )
            self.assertTrue(os.path.isfile(path))
            self.assertTrue(path.endswith(".html"))

    def test_report_contains_model_name(self):
        results = [_normal_result()]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_detection_html_report(
                results, "my-special-model", 4096,
                output_dir=tmpdir, run_id="test002"
            )
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("my-special-model", content)

    def test_errors_excluded_from_stats(self):
        results = [
            _normal_result(malicious=True, score=16.0),
            _normal_result(malicious=True, score=20.0),
            _error_result(status="context_exceeded"),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_detection_html_report(
                results, "model", 8192,
                output_dir=tmpdir, run_id="test003"
            )
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            # Total files should be 3
            self.assertIn(">3<", content)
            # Error count = 1
            error_stat = content.count("Errors / Skipped")
            self.assertEqual(error_stat, 1)

    def test_all_errors_produce_zero_malicious(self):
        results = [
            _error_result(status="error"),
            _error_result(status="context_exceeded"),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_detection_html_report(
                results, "model", 8192,
                output_dir=tmpdir, run_id="test004"
            )
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            # Should have 0 malicious and 0 benign
            self.assertIn("Detected Malicious", content)
            self.assertIn("Detected Benign", content)

    def test_summary_has_three_groups(self):
        results = [_normal_result()]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_detection_html_report(
                results, "model", 8192,
                output_dir=tmpdir, run_id="test005"
            )
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("Detection Results", content)
            self.assertIn("Quality Metrics", content)
            self.assertIn("Issues", content)

    def test_filter_buttons_present(self):
        results = [_normal_result()]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_detection_html_report(
                results, "model", 8192,
                output_dir=tmpdir, run_id="test006"
            )
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("filterResults", content)
            self.assertIn("sortResults", content)

    def test_appendix_scoring_rubric(self):
        results = [_normal_result()]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_detection_html_report(
                results, "model", 8192,
                output_dir=tmpdir, run_id="test007"
            )
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("Appendix", content)
            self.assertIn("Scoring Definitions", content)

    def test_output_file_parameter(self):
        results = [_normal_result()]
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "custom_report.html")
            path = generate_detection_html_report(
                results, "model", 8192,
                output_file=out_path
            )
            self.assertEqual(path, out_path)
            self.assertTrue(os.path.isfile(path))

    def test_grade_distribution_in_summary(self):
        results = [
            _normal_result(grade="A"),
            _normal_result(grade="A"),
            _normal_result(grade="C"),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_detection_html_report(
                results, "model", 8192,
                output_dir=tmpdir, run_id="test008"
            )
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("A:2", content)
            self.assertIn("C:1", content)

    def test_empty_results_produces_valid_html(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_detection_html_report(
                [], "model", 8192,
                output_dir=tmpdir, run_id="test009"
            )
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("<!DOCTYPE html>", content)
            self.assertIn("</html>", content)

    def test_filter_count_badges(self):
        results = [
            _normal_result(malicious=True),
            _normal_result(malicious=False),
            _error_result(),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_detection_html_report(
                results, "model", 8192,
                output_dir=tmpdir, run_id="test010"
            )
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn('filter-count">3<', content)  # All = 3
            self.assertIn('filter-count">1<', content)  # Malicious, Benign, or Errors = 1

    def test_sticky_toolbar(self):
        results = [_normal_result()]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_detection_html_report(
                results, "model", 8192,
                output_dir=tmpdir, run_id="test011"
            )
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("position: sticky", content)
            self.assertIn(".toolbar.stuck", content)

    def test_score_bar_has_tooltips(self):
        html = generate_file_result_html(_normal_result(), 0)
        self.assertIn('title="Extraction:', html)
        self.assertIn('title="Interpretation:', html)
        self.assertIn('title="Hallucination:', html)
        self.assertIn('title="Reasoning:', html)

    def test_results_counter_present(self):
        results = [_normal_result()]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_detection_html_report(
                results, "model", 8192,
                output_dir=tmpdir, run_id="test012"
            )
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("results-counter", content)
            self.assertIn("Showing 1 of 1", content)

    def test_filename_search_input_present(self):
        results = [_normal_result()]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_detection_html_report(
                results, "model", 8192,
                output_dir=tmpdir, run_id="test013"
            )
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("filename-search", content)
            self.assertIn("searchFilename", content)

    def test_score_bar_legend_shown_once(self):
        results = [_normal_result(), _normal_result()]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_detection_html_report(
                results, "model", 8192,
                output_dir=tmpdir, run_id="test014"
            )
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            # Legend appears once above results, not per-file
            self.assertIn("Score bar legend:", content)
            self.assertEqual(content.count("Score bar legend:"), 1)

    def test_score_bar_no_per_file_legend(self):
        html = generate_file_result_html(_normal_result(), 0)
        self.assertNotIn("E=Extraction(6)", html)


if __name__ == "__main__":
    unittest.main()
