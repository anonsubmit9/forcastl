#!/usr/bin/env python3
"""Strict loader/validator for benchmark test case JSON files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


ALLOWED_DIFFICULTY = {"Easy", "Medium", "Hard"}
ALLOWED_ARTEFACT_TYPES = {"EVTX", "CSV"}
ALLOWED_TEST_SET = {"A", "B", "C"}
REQUIRED_TOP_LEVEL = {
    "id",
    "artefact_type",
    "difficulty",
    "scenario_prompt",
    "expected_findings",
    "hallucination_traps",
}
OPTIONAL_TOP_LEVEL = {
    "test_set",
    "artefact_file",
    "expected_output",
    "notes",
}
REQUIRED_FINDING_KEYS = {"indicator"}
OPTIONAL_FINDING_KEYS = {"explanation", "evidence_type"}


class TestCaseValidationError(ValueError):
    """Raised when a testcase JSON fails contract validation."""


def load_test_case(path: str | Path) -> Dict[str, Any]:
    """Load and validate a single testcase JSON."""
    p = Path(path)
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise TestCaseValidationError(f"testcase not found: {p}") from e
    except json.JSONDecodeError as e:
        raise TestCaseValidationError(f"invalid JSON in {p}: {e}") from e

    validate_test_case(raw, source=str(p))
    return raw


def load_test_cases(paths: List[str | Path]) -> List[Dict[str, Any]]:
    """Load and validate multiple testcase files."""
    return [load_test_case(path) for path in paths]


def validate_test_case(test_case: Dict[str, Any], source: str = "<dict>") -> None:
    """Validate testcase dict against benchmark contract."""
    if not isinstance(test_case, dict):
        raise TestCaseValidationError(f"{source}: testcase must be an object")

    keys = set(test_case.keys())
    unknown = keys - (REQUIRED_TOP_LEVEL | OPTIONAL_TOP_LEVEL)
    missing = REQUIRED_TOP_LEVEL - keys
    if missing:
        raise TestCaseValidationError(f"{source}: missing required keys: {sorted(missing)}")
    if unknown:
        raise TestCaseValidationError(f"{source}: unknown keys: {sorted(unknown)}")

    _require_non_empty_str(test_case, "id", source)
    _require_non_empty_str(test_case, "artefact_type", source)
    _require_non_empty_str(test_case, "scenario_prompt", source)
    if test_case["artefact_type"] not in ALLOWED_ARTEFACT_TYPES:
        raise TestCaseValidationError(
            f"{source}: artefact_type must be one of {sorted(ALLOWED_ARTEFACT_TYPES)}, "
            f"got {test_case['artefact_type']!r}"
        )

    difficulty = test_case.get("difficulty")
    if difficulty not in ALLOWED_DIFFICULTY:
        raise TestCaseValidationError(
            f"{source}: difficulty must be one of {sorted(ALLOWED_DIFFICULTY)}, got {difficulty!r}"
        )

    if "test_set" in test_case and test_case["test_set"] not in ALLOWED_TEST_SET:
        raise TestCaseValidationError(
            f"{source}: test_set must be one of {sorted(ALLOWED_TEST_SET)}, got {test_case['test_set']!r}"
        )

    if "artefact_file" in test_case:
        _require_non_empty_str(test_case, "artefact_file", source)
    if "expected_output" in test_case and not isinstance(test_case["expected_output"], str):
        raise TestCaseValidationError(f"{source}: expected_output must be a string")
    if "notes" in test_case and not isinstance(test_case["notes"], str):
        raise TestCaseValidationError(f"{source}: notes must be a string")

    _validate_expected_findings(test_case["expected_findings"], source)
    _validate_hallucination_traps(test_case["hallucination_traps"], source)


def _require_non_empty_str(obj: Dict[str, Any], key: str, source: str) -> None:
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        raise TestCaseValidationError(f"{source}: {key} must be a non-empty string")


def _validate_expected_findings(value: Any, source: str) -> None:
    if not isinstance(value, list) or not value:
        raise TestCaseValidationError(f"{source}: expected_findings must be a non-empty array")

    for idx, item in enumerate(value):
        loc = f"{source}: expected_findings[{idx}]"
        if not isinstance(item, dict):
            raise TestCaseValidationError(f"{loc} must be an object")

        keys = set(item.keys())
        unknown = keys - (REQUIRED_FINDING_KEYS | OPTIONAL_FINDING_KEYS)
        missing = REQUIRED_FINDING_KEYS - keys
        if missing:
            raise TestCaseValidationError(f"{loc} missing required keys: {sorted(missing)}")
        if unknown:
            raise TestCaseValidationError(f"{loc} unknown keys: {sorted(unknown)}")

        if not isinstance(item["indicator"], str) or not item["indicator"].strip():
            raise TestCaseValidationError(f"{loc}.indicator must be a non-empty string")
        if "explanation" in item and not isinstance(item["explanation"], str):
            raise TestCaseValidationError(f"{loc}.explanation must be a string")
        if "evidence_type" in item and not isinstance(item["evidence_type"], str):
            raise TestCaseValidationError(f"{loc}.evidence_type must be a string")


def _validate_hallucination_traps(value: Any, source: str) -> None:
    import re
    import warnings

    if not isinstance(value, list):
        raise TestCaseValidationError(f"{source}: hallucination_traps must be an array")
    for idx, trap in enumerate(value):
        if not isinstance(trap, str) or not trap.strip():
            raise TestCaseValidationError(
                f"{source}: hallucination_traps[{idx}] must be a non-empty string"
            )
        # Traps are matched as regexes (benchmark_scoring._score_hallucinations)
        # with a silent substring fallback on re.error. Surface invalid
        # patterns loudly at load time so a typo can't quietly change the
        # matching semantics for that trap.
        try:
            re.compile(trap)
        except re.error as e:
            warnings.warn(
                f"{source}: hallucination_traps[{idx}] is not a valid regex "
                f"({e}); it will be matched as a literal substring instead",
                stacklevel=2,
            )
