#!/usr/bin/env python3
"""
Structured Malicious Activity Detector

Parses structured LLM responses, validates evidence, and compares against ground truth.
"""

import json
import re
from typing import Any, Dict, Optional

from forcastl import config
from forcastl.core.detection_scoring import compute_score_breakdown, grade_from_total, score_reasoning
from forcastl.core.ground_truth_compare import compare_ground_truth_evidence, fuzzy_match
from forcastl.core.hallucination import (
    build_cross_field_corpus,
    claim_supported_anywhere,
    detect_hallucinations,
    item_in_actual,
)
from forcastl.core.response_parser import clean_response as _clean_response_fn
from forcastl.core.response_parser import parse_structured_response as _parse_fn


class MaliciousDetector:
    """Detector with structure validation and ground truth comparison."""

    def __init__(self, ground_truth_file=None):
        if ground_truth_file is None:
            ground_truth_file = str(config.GROUND_TRUTH_FILE)
        self.ground_truth_data = self._load_ground_truth(ground_truth_file)

        self.malicious_keywords = [
            r'\bmalicious\b', r'\battack\b', r'\bsuspicious\b',
            r'\bthreat\b', r'\bunauthorized\b', r'\bexploit\b',
            r'\bcompromise\b', r'\badversar', r'\bfabricat',
        ]
        self.benign_keywords = [
            r'\bbenign\b', r'\blegitimate\b', r'\broutine\b', r'\bnormal\b',
            r'\bno indication\b', r'\bno evidence\b', r'\bnot malicious\b',
            r'\bexpected\b', r'\bsanctioned\b',
        ]

    def _load_ground_truth(self, file_path: str) -> Dict:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return data.get('files', {})
        except FileNotFoundError:
            return {}
        except Exception as e:
            print(f"Warning: Could not load ground truth: {e}")
            return {}

    def detect(
        self,
        llm_response: str,
        file_path: str = "",
        ground_truth: Optional[Dict] = None,
        filename: str = "",
        sampled_evidence: Optional[Dict] = None,
        artefact_text: Optional[str] = None,
    ) -> Dict[str, Any]:
        cleaned_response = _clean_response_fn(llm_response)
        parsed = _parse_fn(cleaned_response, clean=False)
        validation = self._validate_structure(parsed, llm_response)
        is_malicious = self._determine_malicious(parsed, llm_response)
        confidence = self._calculate_confidence(parsed, validation, is_malicious)

        expected_evidence = None
        if filename:
            expected_evidence = self.ground_truth_data.get(filename)
            # Benign controls are keyed by their logical `.evtx` name in ground
            # truth but reach scoring as `.csv`. Without this fallback they get
            # no alignment / malicious_match, so a false positive (benign flagged
            # malicious) is never surfaced as a misclassification. Mirrors the
            # same fallback in reporting.run_summary.
            if expected_evidence is None and filename.lower().endswith(".csv"):
                expected_evidence = self.ground_truth_data.get(filename[:-4] + ".evtx")

        alignment = None
        if expected_evidence:
            alignment = compare_ground_truth_evidence(parsed, expected_evidence)

        decoded_iocs = (expected_evidence or {}).get('decoded_iocs')
        hallucination_result = detect_hallucinations(
            parsed, sampled_evidence, artefact_text, decoded_iocs=decoded_iocs)
        reasoning_result = score_reasoning(parsed, validation, is_malicious)

        expected_malicious = expected_evidence.get('malicious') if expected_evidence else None
        score_breakdown = compute_score_breakdown(
            alignment,
            hallucination_result,
            reasoning_result,
            validation,
            parsed,
            is_malicious,
            expected_malicious,
        )

        return {
            'file_path': file_path,
            'is_malicious': is_malicious,
            'confidence': confidence,
            'raw_response': llm_response,
            'parsed': parsed,
            'validation': validation,
            'alignment': alignment,
            'ground_truth': ground_truth,
            'expected_evidence': expected_evidence,
            'hallucination': hallucination_result,
            'reasoning': reasoning_result,
            'score_breakdown': score_breakdown,
        }

    def _validate_structure(self, parsed: Dict, response: str) -> Dict[str, Any]:
        validation = {
            'is_valid': True,
            'has_malicious_field': parsed['malicious'] is not None,
            'has_evidence_section': bool(re.search(r'EVIDENCE:', response, re.IGNORECASE)),
            'has_explanation': parsed['explanation'] is not None,
            'evidence_fields_populated': 0,
            'issues': [],
        }

        if not validation['has_malicious_field']:
            validation['is_valid'] = False
            validation['issues'].append("Missing MALICIOUS field")

        if not validation['has_evidence_section']:
            validation['is_valid'] = False
            validation['issues'].append("Missing EVIDENCE section")

        if not validation['has_explanation']:
            validation['is_valid'] = False
            validation['issues'].append("Missing EXPLANATION section")

        for field, values in parsed['evidence'].items():
            if values:
                validation['evidence_fields_populated'] += 1

        if validation['evidence_fields_populated'] == 0:
            validation['issues'].append("No evidence fields populated")

        return validation

    def _determine_malicious(self, parsed: Dict, response: str) -> bool:
        if parsed['malicious'] == 'YES':
            return True
        if parsed['malicious'] == 'NO':
            return False

        response_lower = response.lower()
        mal_hits = sum(1 for p in self.malicious_keywords if re.search(p, response_lower))
        ben_hits = sum(1 for p in self.benign_keywords if re.search(p, response_lower))
        return mal_hits > ben_hits

    def _calculate_confidence(self, parsed: Dict, validation: Dict, is_malicious: bool) -> float:
        confidence = 50.0

        if validation['is_valid']:
            confidence += 30.0

        evidence_count = validation['evidence_fields_populated']
        confidence += min(evidence_count * 5, 20.0)

        if parsed['explanation']:
            confidence += 10.0

        if parsed['malicious'] is not None:
            confidence += 10.0

        return min(confidence, 100.0)

    def _clean_response(self, response: str) -> str:
        return _clean_response_fn(response)

    def _parse_structured_response(self, response: str) -> Dict[str, Any]:
        return _parse_fn(response, clean=False)

    # Backward-compatible aliases for tests/code that called private methods.
    _fuzzy_match = staticmethod(fuzzy_match)
    _compare_ground_truth_evidence = staticmethod(compare_ground_truth_evidence)
    _detect_hallucinations = staticmethod(detect_hallucinations)
    _score_reasoning = staticmethod(score_reasoning)
    _compute_score_breakdown = staticmethod(compute_score_breakdown)
    _item_in_actual = staticmethod(item_in_actual)
    _build_cross_field_corpus = staticmethod(build_cross_field_corpus)
    _claim_supported_anywhere = staticmethod(claim_supported_anywhere)

    @staticmethod
    def _get_grade(total: float) -> str:
        return grade_from_total(total)



def main():
    """Test the detector."""
    detector = MaliciousDetector()

    test_response = """
MALICIOUS: YES

EVIDENCE:
- Event IDs: 4625, 4776
- Processes: lsass.exe
- Accounts: administrator, sa
- Commands: None
- Network: 10.0.0.50
- Registry: None

EXPLANATION:
Multiple failed login attempts from Event ID 4625 indicate a brute force attack.
The same source IP targeted multiple accounts including administrator.
"""

    result = detector.detect(test_response, "test.evtx", filename="test.evtx")

    print("Malicious Detector Test")
    print("=" * 60)
    print(f"Is Malicious: {result['is_malicious']}")
    print(f"Confidence: {result['confidence']}%")
    print(f"Structure Valid: {result['validation']['is_valid']}")
    print(f"Evidence Fields: {result['validation']['evidence_fields_populated']}")
    if result['alignment']:
        print(f"  Alignment Score: {result['alignment']['score']}%")


if __name__ == "__main__":
    main()
