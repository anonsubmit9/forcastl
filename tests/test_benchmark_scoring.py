import unittest

from forcastl.core.benchmark_scoring import score_benchmark_response
from forcastl.core.prompt import PromptManager
from forcastl.validation.testcase_loader import TestCaseValidationError


def _case():
    return {
        "id": "EVTX-001",
        "artefact_type": "EVTX",
        "difficulty": "Medium",
        "scenario_prompt": "Analyze event logs.",
        "expected_findings": [
            {
                "indicator": "event id 4688",
                "explanation": "suspicious process execution",
            },
            {
                "indicator": "powershell.exe",
                "explanation": "script-based execution",
            },
        ],
        "hallucination_traps": [
            "non-existent malware names"
        ],
    }


class BenchmarkScoringTests(unittest.TestCase):
    def test_scores_high_without_hallucinations(self):
        response = (
            "MALICIOUS: YES\n\n"
            "EVIDENCE:\n"
            "- Event IDs: 4688\n"
            "- Processes: powershell.exe\n"
            "- Accounts: None\n"
            "- Commands: powershell -enc ...\n"
            "- Network: None\n"
            "- Registry: None\n\n"
            "EXPLANATION:\n"
            "This suggests suspicious process execution because Event ID 4688 and "
            "powershell.exe indicate script-based execution."
        )
        result = score_benchmark_response(response, _case())
        self.assertGreaterEqual(result["Extraction"], 3.0)
        self.assertGreaterEqual(result["Interpretation"], 3.0)
        self.assertEqual(result["NoHallucination"], 4.0)
        self.assertFalse(result["HallucinationFlag"])

    def test_trap_sets_hallucination_flag(self):
        response = "The attacker used non-existent malware names."
        result = score_benchmark_response(response, _case())
        self.assertEqual(result["NoHallucination"], 0.0)
        self.assertTrue(result["HallucinationFlag"])

    def test_prompt_manager_rejects_unsupported_type(self):
        manager = PromptManager()
        with self.assertRaises(ValueError):
            manager.generate_benchmark_prompt("MFT", "x", "y")

    def test_invalid_test_case_raises(self):
        case = _case()
        case["artefact_type"] = "MFT"
        with self.assertRaises(TestCaseValidationError):
            score_benchmark_response("ok", case)

    def test_event_id_normalization_counts_extraction_hit(self):
        case = {
            "id": "EVTX-002",
            "artefact_type": "EVTX",
            "difficulty": "Easy",
            "scenario_prompt": "Analyze event logs.",
            "expected_findings": [
                {"indicator": "Event ID 1", "explanation": "process execution indicator"},
                {"indicator": "wmiexec", "explanation": "remote WMI execution behavior"},
            ],
            "hallucination_traps": [],
        }
        response = (
            "MALICIOUS: YES\n\n"
            "EVIDENCE:\n"
            "- Event IDs: 1\n"
            "- Processes: cmd.exe\n"
            "- Accounts: NT AUTHORITY\\SYSTEM\n"
            "- Commands: C:\\Windows\\system32\\cmd.exe /Q /c C:\\Windows\\TEMP\\execute.bat\n"
            "- Network: None\n"
            "- Registry: None\n\n"
            "EXPLANATION:\n"
            "This indicates suspicious process execution from SYSTEM context."
        )
        result = score_benchmark_response(response, case)
        self.assertGreaterEqual(result["Extraction"], 3.0)
        self.assertGreaterEqual(result["Interpretation"], 3.0)


if __name__ == "__main__":
    unittest.main()


class ScoringV2Tests(unittest.TestCase):
    """Proportional trap penalty + tightened interpretation fallback."""

    def test_trap_penalty_scales_with_hits(self):
        from forcastl.core.benchmark_scoring import _score_hallucinations
        traps = ["CVE-1999-0001", "evil\\.exe", "10\\.9\\.8\\.7", "HKLM\\\\Fake"]
        score, flagged, matches = _score_hallucinations(
            "found CVE-1999-0001 in the log", traps)
        self.assertTrue(flagged)
        self.assertEqual(matches, ["CVE-1999-0001"])
        self.assertEqual(score, 3.0)  # 1 of 4 traps -> 4*(1-1/4)

    def test_all_traps_hit_scores_zero(self):
        from forcastl.core.benchmark_scoring import _score_hallucinations
        traps = ["alpha", "beta"]
        score, flagged, _ = _score_hallucinations("alpha and beta", traps)
        self.assertTrue(flagged)
        self.assertEqual(score, 0.0)

    def test_no_traps_hit_scores_full(self):
        from forcastl.core.benchmark_scoring import _score_hallucinations
        score, flagged, _ = _score_hallucinations("clean response", ["alpha"])
        self.assertFalse(flagged)
        self.assertEqual(score, 4.0)

    def test_interpretation_fallback_requires_indicator_in_explanation(self):
        from forcastl.core.benchmark_scoring import _count_interpretation_hits
        findings = [{"indicator": "event id 9999", "explanation": ""}]
        # v1 credited an indicator echoed anywhere + any 12-word explanation.
        parsed_echo = {"explanation": "this is a long explanation with more "
                                      "than twelve words but no indicator mention here",
                       "evidence_blob": "event id 9999"}
        hits = _count_interpretation_hits("raw dump: event id 9999", findings, parsed_echo)
        self.assertEqual(hits, 0)
        # The fallback credits only the indicator discussed in the explanation itself.
        parsed_disc = {"explanation": "event id 9999 indicates remote execution "
                                      "because the service installed unexpectedly",
                       "evidence_blob": ""}
        hits = _count_interpretation_hits("...", findings, parsed_disc)
        self.assertEqual(hits, 1)
