"""Validation and ground truth components."""

from forcastl.validation.ground_truth import extract_evidence_from_event, merge_evidence
from forcastl.validation.testcase_loader import (
    TestCaseValidationError,
    load_test_case,
    load_test_cases,
    validate_test_case,
)
