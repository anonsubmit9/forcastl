#!/usr/bin/env python3
"""Benchmark scoring for testcase contract (EVTX/CSV scope)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Set

from forcastl.core.detection_scoring import grade_from_total
from forcastl.core.response_parser import parse_structured_response as _parse_fn
from forcastl.validation.testcase_loader import validate_test_case


REASONING_TERMS = (
    "because",
    "therefore",
    "this suggests",
    "due to",
    "based on",
    "indicates",
)

CAUTIOUS_TERMS = (
    "no evidence found in dataset",
    "insufficient evidence",
    "cannot conclude",
    "cannot confirm",
)

STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "for",
    "from",
    "in",
    "is",
    "it",
    "of",
    "on",
    "or",
    "that",
    "the",
    "this",
    "to",
    "with",
    "event",
    "events",
    "id",
    "indicator",
    "indicators",
    "evidence",
    "behavior",
    "malicious",
    "benign",
}


def score_benchmark_response(response_text: str, test_case: Dict[str, Any]) -> Dict[str, Any]:
    """Score one LLM response against benchmark testcase JSON contract."""
    validate_test_case(test_case)
    response_l = response_text.lower()
    parsed = _parse_fn(response_text, clean=True)

    extraction_hits = _count_indicator_hits(response_l, test_case["expected_findings"], parsed)
    extraction = _scale_hits(extraction_hits, len(test_case["expected_findings"]), max_points=6)

    interpretation_hits = _count_interpretation_hits(response_l, test_case["expected_findings"], parsed)
    interpretation = _scale_hits(interpretation_hits, len(test_case["expected_findings"]), max_points=6)

    hallucination_score, hallucination_flag, hallucination_matches = _score_hallucinations(
        response_text, test_case.get("hallucination_traps", [])
    )

    reasoning = _score_reasoning(response_l, parsed.get("explanation") or "")

    total = round(extraction + interpretation + hallucination_score + reasoning, 1)
    grade = _grade(total)

    return {
        "TestID": test_case["id"],
        "Extraction": extraction,
        "Interpretation": interpretation,
        "NoHallucination": hallucination_score,
        "Reasoning": reasoning,
        "TotalScore": total,
        "Grade": grade,
        "HallucinationFlag": hallucination_flag,
        "MatchedTraps": hallucination_matches,
        "ExpectedFindings": len(test_case["expected_findings"]),
        "ExtractionHits": extraction_hits,
        "InterpretationHits": interpretation_hits,
    }


def _count_indicator_hits(
    response_l: str,
    expected_findings: List[Dict[str, Any]],
    parsed: Dict[str, Any],
) -> int:
    hits = 0
    for finding in expected_findings:
        indicator = str(finding.get("indicator", "")).strip().lower()
        if _indicator_hit(indicator, response_l, parsed):
            hits += 1
    return hits


def _count_interpretation_hits(
    response_l: str,
    expected_findings: List[Dict[str, Any]],
    parsed: Dict[str, Any],
) -> int:
    hits = 0
    explanation_l = (parsed.get("explanation") or "").lower()
    for finding in expected_findings:
        explanation = str(finding.get("explanation", "")).strip().lower()
        indicator = str(finding.get("indicator", "")).strip().lower()
        if explanation:
            if explanation in response_l:
                hits += 1
                continue
            if _semantic_match(explanation, explanation_l):
                hits += 1
                continue
        # Fallback path (tightened): the indicator must be
        # discussed in the model's EXPLANATION section — not merely echoed
        # anywhere in the response — alongside a reasoning signal. The v1
        # check (indicator anywhere + any 12-word explanation) credited
        # responses that dumped the artefact back without interpreting it.
        if indicator and indicator in explanation_l and _has_reasoning_signal(explanation_l):
            hits += 1
    return hits


def _scale_hits(hits: int, total: int, max_points: int) -> float:
    if total <= 0:
        return 0.0
    return round(max_points * (hits / total), 1)


def _score_hallucinations(response_text: str, traps: List[str]) -> tuple[float, bool, List[str]]:
    """Score trap avoidance, scaled by how many traps were hit.

    The penalty is proportional (one trap of four hit -> 3.0/4)
    rather than all-or-nothing — a model that echoes one fake IOC is not the
    same as one that fabricates all of them.
    """
    valid_traps = [str(t).strip() for t in traps if str(t).strip()]
    if not valid_traps:
        return 4.0, False, []

    matches = []
    for trap in valid_traps:
        try:
            found = re.search(trap, response_text, flags=re.IGNORECASE) is not None
        except re.error:
            found = trap.lower() in response_text.lower()
        if found:
            matches.append(trap)

    flagged = len(matches) > 0
    score = round(4.0 * (1 - len(matches) / len(valid_traps)), 1)
    return score, flagged, matches


def _score_reasoning(response_l: str, explanation_l: str) -> float:
    score = 0.0
    target_text = explanation_l or response_l

    if any(term in target_text for term in REASONING_TERMS):
        score += 2.0

    if any(term in target_text for term in CAUTIOUS_TERMS):
        score += 1.0

    lines = [ln.strip() for ln in target_text.splitlines() if ln.strip()]
    if len(lines) >= 2 or len(target_text.split()) >= 25:
        score += 1.0

    return min(score, 4.0)


def _grade(total: float) -> str:
    return grade_from_total(total)


def _indicator_hit(indicator: str, response_l: str, parsed: Dict[str, Any]) -> bool:
    if not indicator:
        return False

    if indicator in response_l:
        return True

    evidence_blob = parsed.get("evidence_blob", "")
    explanation_l = (parsed.get("explanation") or "").lower()
    combined = f"{evidence_blob} {explanation_l}".strip()
    if indicator in combined:
        return True

    indicator_event_ids = set(re.findall(r"\b\d{1,6}\b", indicator))
    if _is_event_indicator(indicator, indicator_event_ids):
        parsed_ids = set(parsed.get("evidence", {}).get("event_ids", []))
        if indicator_event_ids.intersection(parsed_ids):
            return True

    if _looks_like_process_indicator(indicator):
        observed = parsed.get("evidence", {}).get("processes", []) + parsed.get("evidence", {}).get("commands", [])
        if any(_process_like_match(indicator, obs) for obs in observed):
            return True

    return _token_overlap(indicator, combined)


def _is_event_indicator(indicator: str, indicator_event_ids: Set[str]) -> bool:
    if not indicator_event_ids:
        return False
    return "event id" in indicator or indicator.strip().isdigit()


def _looks_like_process_indicator(indicator: str) -> bool:
    return bool(re.search(r"\.(?:exe|dll|sys)\b", indicator)) or ("\\" in indicator) or ("/" in indicator)


def _process_like_match(indicator: str, observed: str) -> bool:
    a = Path(indicator.replace("\\", "/")).name.lower()
    b = Path(str(observed).replace("\\", "/")).name.lower()
    return a == b or (a and a in b) or (b and b in a)


def _semantic_match(expected: str, actual: str) -> bool:
    expected_terms = _tokens(expected)
    actual_terms = _tokens(actual)
    if not expected_terms or not actual_terms:
        return False
    shared = expected_terms.intersection(actual_terms)
    threshold = 1 if len(expected_terms) <= 2 else 2
    return len(shared) >= threshold


def _token_overlap(expected: str, actual: str) -> bool:
    expected_terms = _tokens(expected)
    actual_terms = _tokens(actual)
    if not expected_terms or not actual_terms:
        return False
    threshold = 1 if len(expected_terms) <= 2 else 2
    return len(expected_terms.intersection(actual_terms)) >= threshold


def _tokens(text: str) -> Set[str]:
    toks = set(re.findall(r"[a-z0-9_.-]{3,}", text.lower()))
    return {t for t in toks if t not in STOPWORDS}


def _has_reasoning_signal(explanation_l: str) -> bool:
    if not explanation_l:
        return False
    return any(term in explanation_l for term in REASONING_TERMS) or len(explanation_l.split()) >= 12
