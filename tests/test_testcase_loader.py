import unittest

from forcastl.validation.testcase_loader import TestCaseValidationError, validate_test_case


def _base_case():
    return {
        "id": "EVTX-001",
        "artefact_type": "EVTX",
        "difficulty": "Medium",
        "scenario_prompt": "Analyze the provided artifact.",
        "expected_findings": [{"indicator": "svchost.exe in AppData"}],
        "hallucination_traps": ["fabricated MFT fields"],
    }


class TestCaseLoaderTests(unittest.TestCase):
    def test_valid_case_passes(self):
        validate_test_case(_base_case())

    def test_missing_required_field_fails(self):
        case = _base_case()
        del case["id"]
        with self.assertRaises(TestCaseValidationError):
            validate_test_case(case)

    def test_invalid_difficulty_fails(self):
        case = _base_case()
        case["difficulty"] = "medium"
        with self.assertRaises(TestCaseValidationError):
            validate_test_case(case)

    def test_unsupported_artefact_type_fails(self):
        case = _base_case()
        case["artefact_type"] = "MFT"
        with self.assertRaises(TestCaseValidationError):
            validate_test_case(case)

    def test_expected_findings_requires_indicator(self):
        case = _base_case()
        case["expected_findings"] = [{"explanation": "missing indicator"}]
        with self.assertRaises(TestCaseValidationError):
            validate_test_case(case)

    def test_unknown_top_level_key_fails(self):
        case = _base_case()
        case["extra"] = True
        with self.assertRaises(TestCaseValidationError):
            validate_test_case(case)


if __name__ == "__main__":
    unittest.main()
