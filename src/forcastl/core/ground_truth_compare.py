"""Ground-truth alignment for structured detection responses."""

from __future__ import annotations

from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Dict

from forcastl.config import FUZZY_MATCH_THRESHOLDS


def fuzzy_match(text1: str, text2: str, threshold: float = 0.7) -> float:
    """Calculate fuzzy similarity between two strings."""
    if not text1 or not text2:
        return 0.0
    text1_norm = text1.lower().strip()
    text2_norm = text2.lower().strip()
    if text1_norm == text2_norm:
        return 1.0
    return SequenceMatcher(None, text1_norm, text2_norm).ratio()


def compare_ground_truth_evidence(parsed: Dict, expected: Dict) -> Dict[str, Any]:
    """Compare LLM output against expected evidence with field-by-field fuzzy matching.

    Only fields with non-empty ground truth data count towards the alignment
    score. Empty ground truth fields are skipped.
    """
    alignment = {
        'malicious_match': None,
        'field_matches': {},
        'matches': 0,
        'total_checks': 0,
        'score': 0.0,
        'expected_evidence': expected.get('evidence', {}),
        'detected_evidence': parsed['evidence'],
    }

    alignment['total_checks'] += 1
    expected_mal = expected.get('malicious', 'YES')
    if parsed['malicious'] == expected_mal:
        alignment['malicious_match'] = True
        alignment['matches'] += 1
    else:
        alignment['malicious_match'] = False

    ev_block = expected.get('evidence', {})

    def _expected(field: str) -> list:
        # "expected" is the FULL forensic inventory in
        # the base field. The `attack_*` sidecars (the curated attack-only
        # subset) are no longer used for scoring — they suppressed real,
        # artifact-present evidence (esp. on benign files, where attack_* is
        # empty) from the scored expected. attack_* are kept as interpretation
        # metadata only. See known_issues.
        return ev_block.get(field, [])

    expected_ids = set(ev_block.get('event_ids', []))
    detected_ids = set(parsed['evidence']['event_ids'])

    if expected_ids:
        alignment['total_checks'] += 1
        overlap = expected_ids.intersection(detected_ids)
        match_ratio = len(overlap) / len(expected_ids)
        alignment['field_matches']['event_ids'] = {
            'expected': sorted(expected_ids),
            'detected': sorted(detected_ids),
            'overlap': sorted(overlap),
            'score': match_ratio * 100,
        }
        if match_ratio >= 0.5:
            alignment['matches'] += 1

    expected_procs = _expected('processes')
    if expected_procs:
        alignment['total_checks'] += 1
        detected_procs = [p.lower() for p in parsed['evidence']['processes']]
        matches = 0
        for exp_proc in expected_procs:
            exp_name = Path(exp_proc.replace('\\', '/')).name.lower()
            for det_proc in detected_procs:
                det_name = (
                    Path(det_proc.replace('\\', '/')).name.lower()
                    if '\\' in det_proc or '/' in det_proc
                    else det_proc
                )
                if fuzzy_match(exp_name, det_name) >= FUZZY_MATCH_THRESHOLDS['processes']:
                    matches += 1
                    break
        match_ratio = matches / len(expected_procs)
        alignment['field_matches']['processes'] = {
            'expected': expected_procs,
            'detected': parsed['evidence']['processes'],
            'score': match_ratio * 100,
        }
        if match_ratio >= 0.5:
            alignment['matches'] += 1

    expected_accts = _expected('accounts')
    if expected_accts:
        alignment['total_checks'] += 1
        detected_accts = [a.lower() for a in parsed['evidence']['accounts']]
        matches = sum(
            1 for exp in expected_accts
            if any(fuzzy_match(exp.lower(), det) >= FUZZY_MATCH_THRESHOLDS['accounts'] for det in detected_accts)
        )
        match_ratio = matches / len(expected_accts)
        alignment['field_matches']['accounts'] = {
            'expected': expected_accts,
            'detected': parsed['evidence']['accounts'],
            'score': match_ratio * 100,
        }
        if match_ratio >= 0.5:
            alignment['matches'] += 1

    expected_cmds = _expected('commands')
    if expected_cmds:
        alignment['total_checks'] += 1
        detected_cmds = parsed['evidence']['commands']
        matches = 0
        for exp_cmd in expected_cmds:
            exp_lower = exp_cmd.lower()
            for det_cmd in detected_cmds:
                det_lower = det_cmd.lower()
                if (
                    exp_lower in det_lower
                    or det_lower in exp_lower
                    or fuzzy_match(exp_lower, det_lower) >= FUZZY_MATCH_THRESHOLDS['commands']
                ):
                    matches += 1
                    break
        match_ratio = matches / len(expected_cmds)
        alignment['field_matches']['commands'] = {
            'expected': [c[:100] for c in expected_cmds],
            'detected': [c[:100] for c in detected_cmds],
            'score': match_ratio * 100,
        }
        if match_ratio >= 0.5:
            alignment['matches'] += 1

    expected_net = ev_block.get('network', [])
    if expected_net:
        alignment['total_checks'] += 1
        detected_net = parsed['evidence']['network']
        matches = sum(
            1 for exp in expected_net
            if any(
                exp.lower() == det.lower() or fuzzy_match(exp, det) >= FUZZY_MATCH_THRESHOLDS['network']
                for det in detected_net
            )
        )
        match_ratio = matches / len(expected_net)
        alignment['field_matches']['network'] = {
            'expected': expected_net,
            'detected': detected_net,
            'score': match_ratio * 100,
        }
        if match_ratio >= 0.5:
            alignment['matches'] += 1

    expected_reg = ev_block.get('registry', [])
    if expected_reg:
        alignment['total_checks'] += 1
        detected_reg = parsed['evidence']['registry']
        matches = 0
        for exp_r in expected_reg:
            exp_norm = exp_r.lower().replace('\\', '/').replace('//', '/')
            for det_r in detected_reg:
                det_norm = det_r.lower().replace('\\', '/').replace('//', '/')
                if exp_norm in det_norm or det_norm in exp_norm:
                    matches += 1
                    break
        match_ratio = matches / len(expected_reg)
        alignment['field_matches']['registry'] = {
            'expected': expected_reg,
            'detected': detected_reg,
            'score': match_ratio * 100,
        }
        if match_ratio >= 0.5:
            alignment['matches'] += 1

    # Alignment scores EVIDENCE ONLY. The verdict (malicious yes/no) is scored
    # in Interpretation (detection_scoring) — folding it into this average too
    # double-counted a correct guess (an earlier rubric did; the current one does not). The
    # malicious_match / matches / total_checks fields still report it for
    # display purposes.
    if alignment['field_matches']:
        field_pcts = [fm.get('score', 0.0) for fm in alignment['field_matches'].values()]
        alignment['score'] = sum(field_pcts) / len(field_pcts)
    else:
        # No expected evidence to align against — leave the score undefined so
        # the structural-extraction fallback applies downstream.
        alignment['score'] = None

    return alignment
