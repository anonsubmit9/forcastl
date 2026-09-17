"""Tests for reporting/recommendations.py"""
import unittest

from forcastl.reporting.recommendations import (
    generate_recommendations,
    _parse_estimated_tokens,
    _parse_budget_tokens,
    _configuration_recommendations,
    _quality_recommendations,
    _per_file_recommendations,
)


# ── Fixtures ─────────────────────────────────────────────────────────────────

def _make_result(
    filename="test.evtx",
    status="processed",
    malicious=True,
    confidence=90.0,
    alignment=85.0,
    score=16.0,
    grade="B",
    hall_ratio=0.05,
    hallucinated=None,
    response_time=3.0,
    llm_response="MALICIOUS: YES",
    malicious_match=True,
    reasoning_score=3,
    reasoning_details=None,
    field_matches=None,
):
    """Build a minimal detection result for testing."""
    if reasoning_details is None:
        # Real detail strings emitted by core.detection_scoring.score_reasoning.
        reasoning_details = ["substantive", "evidence-grounded", "consistent"]
    result = {
        "file_path": f"data/{filename}",
        "status": status,
        "llm_response": llm_response,
        "response_time": response_time,
        "detection": {
            "is_malicious": malicious,
            "confidence": confidence,
            "alignment": {
                "score": alignment,
                "malicious_match": malicious_match,
                "field_matches": field_matches or {},
            },
            "score_breakdown": {
                "total": score,
                "grade": grade,
            },
            "hallucination": {
                "ratio": hall_ratio,
                "hallucinated": hallucinated or {},
            },
            "reasoning": {
                "score": reasoning_score,
                "details": reasoning_details,
            },
        },
    }
    return result


def _context_exceeded_result(filename="big.evtx", estimated=7114, budget=6992):
    return {
        "file_path": f"data/{filename}",
        "status": "context_exceeded",
        "llm_response": f"Context exceeded: {estimated} tokens > {budget}",
        "response_time": 0,
        "detection": {},
    }


DEFAULT_CONFIG = {
    "context_window": 8192,
    "max_tokens": 1000,
    "model_name": "test-model",
}


# ── Token parsing ────────────────────────────────────────────────────────────

class TestParseEstimatedTokens(unittest.TestCase):

    def test_standard_format(self):
        resp = "Context exceeded: 7114 tokens > 6992"
        self.assertEqual(_parse_estimated_tokens(resp), 7114)

    def test_budget_parse(self):
        resp = "Context exceeded: 7114 tokens > 6992"
        self.assertEqual(_parse_budget_tokens(resp), 6992)

    def test_no_match(self):
        self.assertIsNone(_parse_estimated_tokens("Some random text"))

    def test_empty(self):
        self.assertIsNone(_parse_estimated_tokens(""))
        self.assertIsNone(_parse_estimated_tokens(None))

    def test_commas_in_numbers(self):
        resp = "Context exceeded: 12,345 tokens > 10,000"
        self.assertEqual(_parse_estimated_tokens(resp), 12345)
        self.assertEqual(_parse_budget_tokens(resp), 10000)


# ── Context exceeded ─────────────────────────────────────────────────────────

class TestContextExceeded(unittest.TestCase):

    def test_context_exceeded_with_gap(self):
        results = [_context_exceeded_result("big.evtx", 7114, 6992)]
        recs = _configuration_recommendations(results, DEFAULT_CONFIG)
        self.assertEqual(len(recs), 1)
        rec = recs[0]
        self.assertEqual(rec["id"], "cfg-context-exceeded")
        self.assertEqual(rec["severity"], "warning")
        self.assertIn("big.evtx", rec["affected_files"])
        # Gap is 122, so suggested = 1000 - 122 - 1 = 877
        self.assertEqual(rec["data"]["suggested_max_tokens"], 877)

    def test_context_exceeded_no_parseable(self):
        results = [{
            "file_path": "data/x.evtx",
            "status": "context_exceeded",
            "llm_response": "Some error happened",
            "response_time": 0,
            "detection": {},
        }]
        recs = _configuration_recommendations(results, DEFAULT_CONFIG)
        self.assertEqual(len(recs), 1)
        self.assertIn("Could not parse", recs[0]["description"])


# ── Near-miss ────────────────────────────────────────────────────────────────

# ── Response time outliers ───────────────────────────────────────────────────

class TestResponseTimeOutliers(unittest.TestCase):

    def test_outlier_flagged(self):
        results = [
            _make_result(filename="a.evtx", response_time=2.0),
            _make_result(filename="b.evtx", response_time=2.5),
            _make_result(filename="c.evtx", response_time=3.0),
            _make_result(filename="slow.evtx", response_time=30.0),
        ]
        recs = _configuration_recommendations(results, DEFAULT_CONFIG)
        outlier_recs = [r for r in recs if r["id"] == "cfg-slow-files"]
        self.assertEqual(len(outlier_recs), 1)
        self.assertIn("slow.evtx", outlier_recs[0]["affected_files"])

    def test_no_outlier_with_few_files(self):
        results = [
            _make_result(filename="a.evtx", response_time=2.0),
            _make_result(filename="b.evtx", response_time=20.0),
        ]
        recs = _configuration_recommendations(results, DEFAULT_CONFIG)
        outlier_recs = [r for r in recs if r["id"] == "cfg-slow-files"]
        self.assertEqual(len(outlier_recs), 0)


# ── High hallucination ──────────────────────────────────────────────────────

class TestHighHallucination(unittest.TestCase):

    def test_high_hallucination_flagged(self):
        results = [
            _make_result(filename="h1.evtx", hall_ratio=0.25,
                         hallucinated={"event_ids": ["9999"], "processes": ["fake.exe"]}),
            _make_result(filename="h2.evtx", hall_ratio=0.20,
                         hallucinated={"event_ids": ["8888"]}),
        ]
        recs = _quality_recommendations(results, DEFAULT_CONFIG)
        hall_recs = [r for r in recs if r["id"] == "qual-high-hallucination"]
        self.assertEqual(len(hall_recs), 1)
        self.assertIn("22%", hall_recs[0]["title"])

    def test_low_hallucination_not_flagged(self):
        results = [
            _make_result(filename="ok.evtx", hall_ratio=0.05),
            _make_result(filename="ok2.evtx", hall_ratio=0.10),
        ]
        recs = _quality_recommendations(results, DEFAULT_CONFIG)
        hall_recs = [r for r in recs if r["id"] == "qual-high-hallucination"]
        self.assertEqual(len(hall_recs), 0)


# ── Low alignment ───────────────────────────────────────────────────────────

class TestLowAlignment(unittest.TestCase):

    def test_low_alignment_flagged(self):
        results = [
            _make_result(filename="la.evtx", alignment=60.0,
                         field_matches={"event_ids": {"score": 40}, "processes": {"score": 80}}),
            _make_result(filename="la2.evtx", alignment=70.0,
                         field_matches={"event_ids": {"score": 50}, "processes": {"score": 90}}),
        ]
        recs = _quality_recommendations(results, DEFAULT_CONFIG)
        align_recs = [r for r in recs if r["id"] == "qual-low-alignment"]
        self.assertEqual(len(align_recs), 1)
        self.assertIn("65%", align_recs[0]["title"])

    def test_high_alignment_not_flagged(self):
        results = [
            _make_result(filename="ok.evtx", alignment=95.0),
        ]
        recs = _quality_recommendations(results, DEFAULT_CONFIG)
        align_recs = [r for r in recs if r["id"] == "qual-low-alignment"]
        self.assertEqual(len(align_recs), 0)


# ── Grade D ──────────────────────────────────────────────────────────────────

class TestGradeD(unittest.TestCase):

    def test_grade_d_listed(self):
        results = [
            _make_result(filename="bad.evtx", grade="D", score=8.0),
            _make_result(filename="ok.evtx", grade="B", score=15.0),
        ]
        recs = _quality_recommendations(results, DEFAULT_CONFIG)
        d_recs = [r for r in recs if r["id"] == "qual-grade-d"]
        self.assertEqual(len(d_recs), 1)
        self.assertIn("bad.evtx", d_recs[0]["affected_files"])
        self.assertNotIn("ok.evtx", d_recs[0]["affected_files"])


# ── All-malicious / all-benign ───────────────────────────────────────────────

class TestSamplingBias(unittest.TestCase):

    def test_all_malicious(self):
        results = [
            _make_result(filename="m1.evtx", malicious=True),
            _make_result(filename="m2.evtx", malicious=True),
            _make_result(filename="m3.evtx", malicious=True),
        ]
        recs = _quality_recommendations(results, DEFAULT_CONFIG)
        bias = [r for r in recs if r["id"] == "qual-all-malicious"]
        self.assertEqual(len(bias), 1)

    def test_all_benign(self):
        results = [
            _make_result(filename="b1.evtx", malicious=False),
            _make_result(filename="b2.evtx", malicious=False),
            _make_result(filename="b3.evtx", malicious=False),
        ]
        recs = _quality_recommendations(results, DEFAULT_CONFIG)
        bias = [r for r in recs if r["id"] == "qual-all-benign"]
        self.assertEqual(len(bias), 1)

    def test_mixed_no_bias(self):
        results = [
            _make_result(filename="m.evtx", malicious=True),
            _make_result(filename="b.evtx", malicious=False),
            _make_result(filename="m2.evtx", malicious=True),
        ]
        recs = _quality_recommendations(results, DEFAULT_CONFIG)
        bias = [r for r in recs if "all-" in r.get("id", "")]
        self.assertEqual(len(bias), 0)

    def test_fewer_than_3_no_bias_check(self):
        results = [
            _make_result(filename="m.evtx", malicious=True),
            _make_result(filename="m2.evtx", malicious=True),
        ]
        recs = _quality_recommendations(results, DEFAULT_CONFIG)
        bias = [r for r in recs if "all-malicious" in r.get("id", "")]
        self.assertEqual(len(bias), 0)


# ── Low reasoning ────────────────────────────────────────────────────────────

class TestLowReasoning(unittest.TestCase):

    def test_low_reasoning_flagged(self):
        results = [
            _make_result(filename="lr.evtx", reasoning_score=1,
                         reasoning_details=["substantive"]),
            _make_result(filename="lr2.evtx", reasoning_score=2,
                         reasoning_details=["substantive", "consistent"]),
        ]
        recs = _quality_recommendations(results, DEFAULT_CONFIG)
        reason_recs = [r for r in recs if r["id"] == "qual-low-reasoning"]
        self.assertEqual(len(reason_recs), 1)
        self.assertIn("1.5/4", reason_recs[0]["title"])

    def test_missing_traits_match_real_detail_names(self):
        # Regression for the label-mismatch bug: a file that genuinely has
        # 'evidence-grounded' + 'domain-aware' must NOT be reported as missing
        # the friendly labels 'references evidence' / 'security language'.
        results = [
            _make_result(filename="a.evtx", reasoning_score=1,
                         reasoning_details=["substantive", "evidence-grounded", "domain-aware"]),
            _make_result(filename="b.evtx", reasoning_score=1,
                         reasoning_details=["substantive"]),
        ]
        recs = _quality_recommendations(results, DEFAULT_CONFIG)
        desc = next(r for r in recs if r["id"] == "qual-low-reasoning")["description"]
        # consistent missing in both files; the others only in b.
        self.assertIn("consistent (missing in 2)", desc)
        self.assertIn("references evidence (missing in 1)", desc)
        self.assertIn("security language (missing in 1)", desc)
        # The bug would have reported these as missing-in-all (2).
        self.assertNotIn("references evidence (missing in 2)", desc)
        self.assertNotIn("security language (missing in 2)", desc)


# ── Per-file: consolidated alerts ────────────────────────────────────────────

class TestPerFileAlerts(unittest.TestCase):

    def test_high_hallucination_only(self):
        results = [_make_result(filename="hall.evtx", hall_ratio=0.65)]
        recs = _per_file_recommendations(results, DEFAULT_CONFIG)
        alerts = [r for r in recs if r["id"] == "file-alert"]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "warning")
        self.assertIn("hall.evtx", alerts[0]["affected_files"])
        self.assertIn("hallucination 65%", alerts[0]["title"])

    def test_normal_hallucination_not_flagged(self):
        results = [_make_result(filename="ok.evtx", hall_ratio=0.10)]
        recs = _per_file_recommendations(results, DEFAULT_CONFIG)
        self.assertEqual(len(recs), 0)

    def test_low_alignment_only(self):
        results = [_make_result(filename="low.evtx", alignment=30.0)]
        recs = _per_file_recommendations(results, DEFAULT_CONFIG)
        alerts = [r for r in recs if r["id"] == "file-alert"]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "warning")
        self.assertIn("alignment 30%", alerts[0]["title"])

    def test_acceptable_alignment_not_flagged(self):
        results = [_make_result(filename="ok.evtx", alignment=75.0)]
        recs = _per_file_recommendations(results, DEFAULT_CONFIG)
        self.assertEqual(len(recs), 0)

    def test_misclassification_only(self):
        results = [_make_result(filename="wrong.evtx", malicious=True, malicious_match=False)]
        recs = _per_file_recommendations(results, DEFAULT_CONFIG)
        alerts = [r for r in recs if r["id"] == "file-alert"]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "warning")
        self.assertIn("wrong.evtx", alerts[0]["affected_files"])
        self.assertIn("misclassified", alerts[0]["title"])

    def test_correct_classification_not_flagged(self):
        results = [_make_result(filename="ok.evtx", malicious_match=True)]
        recs = _per_file_recommendations(results, DEFAULT_CONFIG)
        self.assertEqual(len(recs), 0)

    def test_multiple_issues_consolidated_into_one_card(self):
        """A file with hallucination + low alignment + misclassification => 1 card."""
        results = [_make_result(
            filename="bad.evtx", hall_ratio=0.70, alignment=25.0,
            malicious=True, malicious_match=False,
        )]
        recs = _per_file_recommendations(results, DEFAULT_CONFIG)
        self.assertEqual(len(recs), 1)
        rec = recs[0]
        self.assertEqual(rec["id"], "file-alert")
        self.assertIn("bad.evtx", rec["affected_files"])
        self.assertIn("hallucination 70%", rec["title"])
        self.assertIn("alignment 25%", rec["title"])
        self.assertIn("misclassified", rec["title"])
        self.assertIn("70%", rec["description"])
        self.assertIn("25%", rec["description"])
        self.assertIn("benign", rec["description"])  # expected benign

    def test_two_bad_files_get_separate_cards(self):
        results = [
            _make_result(filename="a.evtx", hall_ratio=0.60),
            _make_result(filename="b.evtx", alignment=20.0),
        ]
        recs = _per_file_recommendations(results, DEFAULT_CONFIG)
        self.assertEqual(len(recs), 2)
        files = {r["affected_files"][0] for r in recs}
        self.assertEqual(files, {"a.evtx", "b.evtx"})


# ── Integration ──────────────────────────────────────────────────────────────

class TestGenerateRecommendations(unittest.TestCase):

    def test_empty_results(self):
        recs = generate_recommendations([], DEFAULT_CONFIG)
        self.assertEqual(recs, [])

    def test_sort_order_critical_before_warning_before_info(self):
        results = [
            _make_result(filename="hall.evtx", hall_ratio=0.65),  # per_file warning
            _make_result(filename="ok.evtx", alignment=95.0, response_time=2.0),
            _make_result(filename="ok2.evtx", alignment=95.0, response_time=2.5),
            _make_result(filename="slow.evtx", alignment=95.0, response_time=25.0),  # cfg info
        ]
        recs = generate_recommendations(results, DEFAULT_CONFIG)
        severities = [r["severity"] for r in recs]
        # critical should come before warning, warning before info
        for i in range(len(severities) - 1):
            order = {"critical": 0, "warning": 1, "info": 2}
            self.assertLessEqual(order[severities[i]], order[severities[i + 1]],
                                 f"Out of order at index {i}: {severities}")

    def test_all_recommendation_types_present(self):
        """Comprehensive test with results that trigger multiple recommendation types."""
        results = [
            _make_result(filename="a.evtx", hall_ratio=0.60, alignment=40.0,
                         grade="D", score=6.0, malicious_match=False, malicious=True,
                         reasoning_score=1, reasoning_details=["substantive"]),
            _make_result(filename="b.evtx", hall_ratio=0.30, alignment=55.0,
                         grade="D", score=7.0, malicious=True,
                         reasoning_score=2, reasoning_details=["substantive", "consistent"]),
            _make_result(filename="c.evtx", hall_ratio=0.20, alignment=60.0,
                         grade="C", score=11.0, malicious=True,
                         reasoning_score=2, reasoning_details=["substantive"]),
        ]
        recs = generate_recommendations(results, DEFAULT_CONFIG)
        ids = {r["id"] for r in recs}
        self.assertIn("qual-high-hallucination", ids)
        self.assertIn("qual-low-alignment", ids)
        self.assertIn("qual-grade-d", ids)
        self.assertIn("qual-all-malicious", ids)
        self.assertIn("qual-low-reasoning", ids)
        self.assertIn("file-alert", ids)
        # a.evtx has hall>50%, align<50%, misclassified => 1 card
        # b.evtx has hall 30% (no), align 55% (no per-file alert) => 0 cards
        file_alerts = [r for r in recs if r["id"] == "file-alert"]
        self.assertEqual(len(file_alerts), 1)
        self.assertIn("a.evtx", file_alerts[0]["affected_files"])


class VerdictRecommendationsTests(unittest.TestCase):
    """Verdict-driven recommendations surface the run-level PASS/CAUTION/FAIL
    in the existing attention-list. They are emitted only when a `summary`
    is passed to `generate_recommendations`."""

    def _summary(self, tier, reasons=None, drivers=None):
        # Mirrors compute_verdict's output shape — tier=="insufficient"
        # gets the matching boolean flag the recommendations engine reads.
        return {
            "verdict": {
                "tier": tier,
                "insufficient": tier == "insufficient",
                "reasons": reasons or [],
                "drivers": drivers or {},
                "has_benign": tier != "insufficient",
            }
        }

    def test_pass_tier_emits_no_rec(self):
        """A clean PASS doesn't need to clutter the attention-list — the
        verdict banner already says PASS."""
        recs = generate_recommendations([], DEFAULT_CONFIG, summary=self._summary("pass"))
        verdict_recs = [r for r in recs if r["category"] == "verdict"]
        self.assertEqual(verdict_recs, [])

    def test_fail_tier_critical_severity(self):
        recs = generate_recommendations(
            [], DEFAULT_CONFIG,
            summary=self._summary(
                "fail",
                reasons=["Detection rate 50.0% below FAIL threshold (60%)"],
                drivers={"recall_pct": 50.0},
            ),
        )
        verdict_recs = [r for r in recs if r["category"] == "verdict"]
        self.assertEqual(len(verdict_recs), 1)
        rec = verdict_recs[0]
        self.assertEqual(rec["severity"], "critical")
        self.assertIn("FAIL", rec["title"])
        # Reasons live in rec["data"]["reasons"], not the human-readable
        # description (which stays a fixed actionable sentence).
        self.assertIn("Detection rate 50.0% below FAIL threshold (60%)",
                      rec["data"]["reasons"])

    def test_caution_tier_warning_severity(self):
        recs = generate_recommendations(
            [], DEFAULT_CONFIG,
            summary=self._summary("caution", reasons=["FP rate 25.0% exceeds PASS threshold (10%)"]),
        )
        verdict_recs = [r for r in recs if r["category"] == "verdict"]
        self.assertEqual(verdict_recs[0]["severity"], "warning")

    def test_insufficient_tier_info_severity(self):
        recs = generate_recommendations(
            [], DEFAULT_CONFIG,
            summary=self._summary("insufficient", reasons=["No malicious samples in scope"]),
        )
        verdict_recs = [r for r in recs if r["category"] == "verdict"]
        self.assertEqual(verdict_recs[0]["severity"], "info")

    def test_no_summary_skips_verdict_block(self):
        """Backward compat: callers that don't pass `summary` get the same
        recommendations as before — no verdict block, no errors."""
        recs = generate_recommendations([], DEFAULT_CONFIG)
        verdict_recs = [r for r in recs if r["category"] == "verdict"]
        self.assertEqual(verdict_recs, [])

    def test_verdict_rec_sorts_to_top_when_critical(self):
        """A critical verdict rec must sort above per-file warnings/infos."""
        results = [_make_result(filename="x.evtx", response_time=25.0)]  # cfg-info latency
        summary = self._summary("fail", reasons=["Detection rate 30.0% below FAIL threshold"])
        recs = generate_recommendations(results, DEFAULT_CONFIG, summary=summary)
        # First non-empty rec should be the verdict critical
        self.assertEqual(recs[0]["category"], "verdict")
        self.assertEqual(recs[0]["severity"], "critical")


class TestErroredFiles(unittest.TestCase):
    """Files that error out (timeouts / oversized) must surface in recommendations
    — otherwise a run that failed on its biggest files looks clean."""

    def _cfg(self):
        c = dict(DEFAULT_CONFIG); c["timeout"] = 300; return c

    def test_errored_files_surfaced_and_categorized(self):
        results = [
            _make_result(filename="timeout.evtx", status="error", response_time=300.0),
            _make_result(filename="toobig.evtx", status="error", response_time=0.0),
            _make_result(filename="ok.evtx"),
        ]
        recs = _configuration_recommendations(results, self._cfg())
        errd = [r for r in recs if r["id"] == "cfg-files-errored"]
        self.assertEqual(len(errd), 1)
        r = errd[0]
        self.assertEqual(r["severity"], "warning")
        self.assertIn("2 file(s) failed", r["title"])
        self.assertIn("timeout.evtx", r["data"]["timeouts"])
        self.assertIn("toobig.evtx", r["data"]["oversized"])

    def test_no_errors_no_rec(self):
        results = [_make_result(filename="ok.evtx")]
        recs = _configuration_recommendations(results, self._cfg())
        self.assertEqual([r for r in recs if r["id"] == "cfg-files-errored"], [])


if __name__ == "__main__":
    unittest.main()
