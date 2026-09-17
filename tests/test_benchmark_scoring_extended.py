"""Extended tests for core/benchmark_scoring.py — indicator matching, semantic matching,
hallucination traps, reasoning, parsing, and grading."""
import unittest

from forcastl.core.benchmark_scoring import (
    _grade,
    _scale_hits,
    _score_hallucinations,
    _score_reasoning,
    _indicator_hit,
    _semantic_match,
    _token_overlap,
    _tokens,
    _is_event_indicator,
    _looks_like_process_indicator,
    _process_like_match,
    _count_indicator_hits,
    _has_reasoning_signal,
    score_benchmark_response,
)
from forcastl.core.response_parser import parse_structured_response as _parse_structured_response, split_list as _split_list


# ── _grade ───────────────────────────────────────────────────────────────────

class TestGrade(unittest.TestCase):
    def test_a(self):
        self.assertEqual(_grade(17.0), "A")
        self.assertEqual(_grade(20.0), "A")

    def test_b(self):
        self.assertEqual(_grade(14.0), "B")
        self.assertEqual(_grade(16.9), "B")

    def test_c(self):
        self.assertEqual(_grade(10.0), "C")
        self.assertEqual(_grade(13.9), "C")

    def test_d(self):
        self.assertEqual(_grade(9.9), "D")
        self.assertEqual(_grade(0.0), "D")


# ── _scale_hits ──────────────────────────────────────────────────────────────

class TestScaleHits(unittest.TestCase):
    def test_all_hits(self):
        self.assertEqual(_scale_hits(3, 3, 6), 6.0)

    def test_no_hits(self):
        self.assertEqual(_scale_hits(0, 3, 6), 0.0)

    def test_partial_hits(self):
        self.assertEqual(_scale_hits(1, 2, 6), 3.0)

    def test_zero_total(self):
        self.assertEqual(_scale_hits(0, 0, 6), 0.0)

    def test_rounding(self):
        result = _scale_hits(1, 3, 6)
        self.assertEqual(result, 2.0)


# ── _score_hallucinations ───────────────────────────────────────────────────

class TestScoreHallucinations(unittest.TestCase):
    def test_no_traps(self):
        score, flag, matches = _score_hallucinations("some response", [])
        self.assertEqual(score, 4.0)
        self.assertFalse(flag)
        self.assertEqual(matches, [])

    def test_trap_found(self):
        score, flag, matches = _score_hallucinations(
            "The attacker used mimikatz to dump credentials",
            ["mimikatz"]
        )
        self.assertEqual(score, 0.0)
        self.assertTrue(flag)
        self.assertIn("mimikatz", matches)

    def test_trap_not_found(self):
        score, flag, matches = _score_hallucinations(
            "Normal event log activity detected.",
            ["mimikatz", "cobalt strike"]
        )
        self.assertEqual(score, 4.0)
        self.assertFalse(flag)

    def test_trap_case_insensitive(self):
        score, flag, _ = _score_hallucinations("MIMIKATZ was used", ["mimikatz"])
        self.assertTrue(flag)

    def test_trap_with_regex_pattern(self):
        score, flag, _ = _score_hallucinations(
            "The attacker used bloodhound tool",
            [r"\bbloodhound\b"]
        )
        self.assertTrue(flag)

    def test_invalid_regex_falls_back_to_substring(self):
        score, flag, _ = _score_hallucinations(
            "found (bad regex pattern",
            ["(bad regex"]
        )
        self.assertTrue(flag)

    def test_empty_trap_string_ignored(self):
        score, flag, matches = _score_hallucinations("response", ["", "  "])
        self.assertEqual(score, 4.0)
        self.assertFalse(flag)


# ── _score_reasoning ─────────────────────────────────────────────────────────

class TestScoreReasoning(unittest.TestCase):
    def test_reasoning_terms_give_2_points(self):
        score = _score_reasoning("", "this suggests a pattern because of the evidence")
        self.assertGreaterEqual(score, 2.0)

    def test_cautious_terms_give_1_point(self):
        score = _score_reasoning("", "cannot conclude from insufficient evidence")
        self.assertGreaterEqual(score, 1.0)

    def test_length_gives_1_point(self):
        long_text = " ".join(["word"] * 30)
        score = _score_reasoning("", long_text)
        self.assertGreaterEqual(score, 1.0)

    def test_multiline_gives_1_point(self):
        score = _score_reasoning("", "line one\nline two")
        self.assertGreaterEqual(score, 1.0)

    def test_capped_at_4(self):
        text = "because this suggests a pattern due to the evidence cannot conclude " + " ".join(["word"] * 30)
        score = _score_reasoning("", text)
        self.assertLessEqual(score, 4.0)

    def test_empty_text_zero(self):
        score = _score_reasoning("", "")
        self.assertEqual(score, 0.0)

    def test_falls_back_to_response(self):
        """When explanation is empty, should use response_l."""
        score = _score_reasoning("this suggests suspicious activity because of lateral movement", "")
        self.assertGreaterEqual(score, 2.0)


# ── _tokens ──────────────────────────────────────────────────────────────────

class TestTokens(unittest.TestCase):
    def test_extracts_words(self):
        result = _tokens("powershell.exe executed command")
        self.assertIn("powershell.exe", result)
        self.assertIn("executed", result)
        self.assertIn("command", result)

    def test_removes_stopwords(self):
        result = _tokens("the event is malicious")
        self.assertNotIn("the", result)
        self.assertNotIn("event", result)
        self.assertNotIn("is", result)
        self.assertNotIn("malicious", result)

    def test_minimum_length_3(self):
        result = _tokens("ab cd efg")
        self.assertNotIn("ab", result)
        self.assertNotIn("cd", result)
        self.assertIn("efg", result)

    def test_lowercase(self):
        result = _tokens("PowerShell.EXE")
        self.assertIn("powershell.exe", result)

    def test_empty_string(self):
        result = _tokens("")
        self.assertEqual(result, set())


# ── _semantic_match ──────────────────────────────────────────────────────────

class TestSemanticMatch(unittest.TestCase):
    def test_matching_terms(self):
        self.assertTrue(_semantic_match(
            "suspicious process execution",
            "the process execution was flagged as suspicious"
        ))

    def test_no_matching_terms(self):
        self.assertFalse(_semantic_match(
            "credential dumping attack",
            "normal login activity"
        ))

    def test_empty_expected(self):
        self.assertFalse(_semantic_match("", "some text"))

    def test_empty_actual(self):
        self.assertFalse(_semantic_match("some text", ""))

    def test_single_word_match_enough_for_short(self):
        """For <= 2 expected terms, threshold is 1."""
        self.assertTrue(_semantic_match("powershell", "powershell was executed"))


# ── _token_overlap ───────────────────────────────────────────────────────────

class TestTokenOverlap(unittest.TestCase):
    def test_overlap_above_threshold(self):
        self.assertTrue(_token_overlap(
            "credential dumping attack",
            "attacker performed credential dumping"
        ))

    def test_no_overlap(self):
        self.assertFalse(_token_overlap("powershell execution", "normal login"))

    def test_empty_strings(self):
        self.assertFalse(_token_overlap("", "test"))
        self.assertFalse(_token_overlap("test", ""))


# ── _is_event_indicator ─────────────────────────────────────────────────────

class TestIsEventIndicator(unittest.TestCase):
    def test_event_id_phrase(self):
        self.assertTrue(_is_event_indicator("event id 4688", {"4688"}))

    def test_pure_digit(self):
        self.assertTrue(_is_event_indicator("4688", {"4688"}))

    def test_no_event_ids(self):
        self.assertFalse(_is_event_indicator("powershell.exe", set()))

    def test_text_with_embedded_number(self):
        self.assertFalse(_is_event_indicator("powershell process 1234", {"1234"}))


# ── _looks_like_process_indicator ────────────────────────────────────────────

class TestLooksLikeProcessIndicator(unittest.TestCase):
    def test_exe_extension(self):
        self.assertTrue(_looks_like_process_indicator("powershell.exe"))

    def test_dll_extension(self):
        self.assertTrue(_looks_like_process_indicator("malware.dll"))

    def test_sys_extension(self):
        self.assertTrue(_looks_like_process_indicator("driver.sys"))

    def test_path_with_backslash(self):
        self.assertTrue(_looks_like_process_indicator("C:\\Windows\\cmd"))

    def test_path_with_slash(self):
        self.assertTrue(_looks_like_process_indicator("/usr/bin/python"))

    def test_plain_text(self):
        self.assertFalse(_looks_like_process_indicator("suspicious process"))


# ── _process_like_match ──────────────────────────────────────────────────────

class TestProcessLikeMatch(unittest.TestCase):
    def test_exact_filename(self):
        self.assertTrue(_process_like_match("cmd.exe", "cmd.exe"))

    def test_path_vs_filename(self):
        self.assertTrue(_process_like_match("cmd.exe", "C:\\Windows\\System32\\cmd.exe"))

    def test_partial_match(self):
        self.assertTrue(_process_like_match("powershell.exe", "powershell.exe -enc abc"))

    def test_no_match(self):
        self.assertFalse(_process_like_match("cmd.exe", "notepad.exe"))


# ── _split_list ──────────────────────────────────────────────────────────────

class TestSplitList(unittest.TestCase):
    def test_comma_split(self):
        self.assertEqual(_split_list("a, b, c"), ["a", "b", "c"])

    def test_semicolon_preferred(self):
        self.assertEqual(_split_list("a; b; c", prefer_semicolon=True), ["a", "b", "c"])

    def test_no_semicolon_keeps_whole(self):
        self.assertEqual(_split_list("a, b, c", prefer_semicolon=True), ["a, b, c"])

    def test_none_value(self):
        self.assertEqual(_split_list("None"), [])
        self.assertEqual(_split_list("n/a"), [])

    def test_empty_string(self):
        self.assertEqual(_split_list(""), [])

    def test_strips_whitespace(self):
        self.assertEqual(_split_list("  a  ,  b  "), ["a", "b"])

    def test_filters_none_items(self):
        self.assertEqual(_split_list("a, None, b"), ["a", "b"])


# ── _parse_structured_response ───────────────────────────────────────────────

class TestParseStructuredResponse(unittest.TestCase):
    def test_extracts_event_ids(self):
        response = "EVIDENCE:\n- Event IDs: 4688, 4689\nEXPLANATION: test"
        parsed = _parse_structured_response(response)
        self.assertIn("4688", parsed["evidence"]["event_ids"])
        self.assertIn("4689", parsed["evidence"]["event_ids"])

    def test_extracts_processes(self):
        response = "EVIDENCE:\n- Processes: cmd.exe, powershell.exe\nEXPLANATION: test"
        parsed = _parse_structured_response(response)
        self.assertIn("cmd.exe", parsed["evidence"]["processes"])
        self.assertIn("powershell.exe", parsed["evidence"]["processes"])

    def test_extracts_explanation(self):
        response = "MALICIOUS: YES\nEVIDENCE:\n- Event IDs: 1\nEXPLANATION:\nThis is the explanation text."
        parsed = _parse_structured_response(response)
        self.assertIn("explanation text", parsed["explanation"])

    def test_evidence_blob_populated(self):
        response = "EVIDENCE:\n- Event IDs: 4688\n- Processes: cmd.exe\nEXPLANATION: test"
        parsed = _parse_structured_response(response)
        self.assertIn("4688", parsed["evidence_blob"])
        self.assertIn("cmd.exe", parsed["evidence_blob"])

    def test_none_values_excluded(self):
        response = "EVIDENCE:\n- Network: None\nEXPLANATION: test"
        parsed = _parse_structured_response(response)
        self.assertEqual(parsed["evidence"]["network"], [])


# ── _indicator_hit ───────────────────────────────────────────────────────────

class TestIndicatorHit(unittest.TestCase):
    def test_direct_substring(self):
        parsed = _parse_structured_response("Event IDs: 4688\nEXPLANATION: test")
        self.assertTrue(_indicator_hit("4688", "event ids: 4688", parsed))

    def test_event_id_match_via_parsed(self):
        parsed = _parse_structured_response("Event IDs: 4688\nEXPLANATION: test")
        self.assertTrue(_indicator_hit("event id 4688", "evidence:\n- event ids: 4688", parsed))

    def test_process_match(self):
        parsed = _parse_structured_response("Processes: powershell.exe\nEXPLANATION: test")
        self.assertTrue(_indicator_hit("powershell.exe", "processes: powershell.exe", parsed))

    def test_no_match(self):
        parsed = _parse_structured_response("Event IDs: 4688\nEXPLANATION: test")
        self.assertFalse(_indicator_hit("mimikatz", "event ids: 4688", parsed))

    def test_empty_indicator(self):
        parsed = _parse_structured_response("Event IDs: 4688\nEXPLANATION: test")
        self.assertFalse(_indicator_hit("", "event ids: 4688", parsed))


# ── _has_reasoning_signal ────────────────────────────────────────────────────

class TestHasReasoningSignal(unittest.TestCase):
    def test_reasoning_term(self):
        self.assertTrue(_has_reasoning_signal("this suggests suspicious activity"))

    def test_long_text(self):
        text = " ".join(["word"] * 15)
        self.assertTrue(_has_reasoning_signal(text))

    def test_empty(self):
        self.assertFalse(_has_reasoning_signal(""))

    def test_short_no_signal(self):
        self.assertFalse(_has_reasoning_signal("bad"))


# ── _count_indicator_hits ────────────────────────────────────────────────────

class TestCountIndicatorHits(unittest.TestCase):
    def test_all_found(self):
        response = "MALICIOUS: YES\nEVIDENCE:\n- Event IDs: 4688\n- Processes: cmd.exe\nEXPLANATION: test"
        parsed = _parse_structured_response(response)
        findings = [
            {"indicator": "4688"},
            {"indicator": "cmd.exe"},
        ]
        self.assertEqual(_count_indicator_hits(response.lower(), findings, parsed), 2)

    def test_none_found(self):
        response = "MALICIOUS: YES\nEVIDENCE:\n- Event IDs: 4688\nEXPLANATION: test"
        parsed = _parse_structured_response(response)
        findings = [{"indicator": "mimikatz"}, {"indicator": "bloodhound"}]
        self.assertEqual(_count_indicator_hits(response.lower(), findings, parsed), 0)


# ── Full score_benchmark_response ────────────────────────────────────────────

class TestScoreBenchmarkResponse(unittest.TestCase):
    def _case(self):
        return {
            "id": "TEST-001",
            "artefact_type": "EVTX",
            "difficulty": "Easy",
            "scenario_prompt": "Analyze logs.",
            "expected_findings": [
                {"indicator": "event id 4688", "explanation": "process execution"},
                {"indicator": "cmd.exe", "explanation": "command shell"},
            ],
            "hallucination_traps": ["bloodhound"],
        }

    def test_perfect_response(self):
        response = (
            "MALICIOUS: YES\n\n"
            "EVIDENCE:\n"
            "- Event IDs: 4688\n"
            "- Processes: cmd.exe\n"
            "- Accounts: admin\n"
            "- Commands: whoami\n"
            "- Network: None\n"
            "- Registry: None\n\n"
            "EXPLANATION:\n"
            "Event ID 4688 indicates process execution. The command shell cmd.exe "
            "was spawned, suggesting suspicious process execution activity."
        )
        result = score_benchmark_response(response, self._case())
        self.assertGreaterEqual(result["Extraction"], 3.0)
        self.assertFalse(result["HallucinationFlag"])
        self.assertEqual(result["NoHallucination"], 4.0)

    def test_hallucination_trap_triggered(self):
        response = "The attacker used bloodhound for reconnaissance."
        result = score_benchmark_response(response, self._case())
        self.assertTrue(result["HallucinationFlag"])
        self.assertEqual(result["NoHallucination"], 0.0)

    def test_empty_response(self):
        result = score_benchmark_response("", self._case())
        self.assertEqual(result["Extraction"], 0.0)
        self.assertEqual(result["ExtractionHits"], 0)

    def test_no_traps_in_case(self):
        case = self._case()
        case["hallucination_traps"] = []
        response = "Some response mentioning bloodhound."
        result = score_benchmark_response(response, case)
        # No traps → full hallucination score
        self.assertEqual(result["NoHallucination"], 4.0)
        self.assertFalse(result["HallucinationFlag"])


if __name__ == "__main__":
    unittest.main()
