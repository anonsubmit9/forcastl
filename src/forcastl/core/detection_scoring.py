"""20-point composite scoring for corpus detection runs."""

from __future__ import annotations

from typing import Any, Dict, Optional


_NEGATION_CUES = (
    "no ", "not ", "n't", "without", "rather than", "lack", "absence of",
    "no indication", "no evidence", "no sign", "nothing ", "isn't", "aren't",
)


def _referenced(item: str, field: str, exp_lower: str) -> bool:
    """Did the explanation reference this evidence item — verbatim or by a
    natural short form? Models cite paths by basename (``net.exe``) and accounts
    by username (``helpdesk-svc``), so requiring the exact full string
    (``C:\\Windows\\System32\\net.exe``) under-counts genuine grounding."""
    il = str(item).strip().lower()
    if not il or il == "-":
        return False
    forms = {il}
    if field in ("processes", "registry", "commands"):
        forms.add(il.replace("\\", "/").rstrip("/").split("/")[-1])   # path basename
        first = il.split(" ", 1)[0]                                    # command's exe
        forms.add(first.replace("\\", "/").split("/")[-1])
    if field == "accounts":
        forms.add(il.split("\\")[-1])                                  # user after domain\
    return any(len(f) >= 3 and f in exp_lower for f in forms if f)


def _present_unnegated(text: str, words) -> bool:
    """True if any of *words* occurs in *text* without a negation cue in the
    ~30 chars preceding it — so a benign explanation ("no malicious activity",
    "not an attack") is not read as a malicious conclusion."""
    for w in words:
        start = 0
        while (i := text.find(w, start)) != -1:
            if not any(cue in text[max(0, i - 30):i] for cue in _NEGATION_CUES):
                return True
            start = i + len(w)
    return False


def score_reasoning(parsed: Dict, validation: Dict, is_malicious: bool) -> Dict[str, Any]:
    """Score the quality of the LLM's reasoning (4 points total)."""
    explanation = parsed.get('explanation') or ''
    exp_lower = explanation.lower()
    score = 0
    details = []

    if len(explanation) >= 50:
        score += 1
        details.append('substantive')

    # Evidence-grounded: explanation references >=2 of the evidence fields it
    # extracted (matched verbatim or by basename/username short form).
    evidence_refs = 0
    for field in ('event_ids', 'processes', 'accounts', 'commands', 'network', 'registry'):
        items = parsed['evidence'].get(field, [])
        if any(_referenced(item, field, exp_lower) for item in items):
            evidence_refs += 1
    if evidence_refs >= 2:
        score += 1
        details.append('evidence-grounded')

    # Consistent: the explanation's conclusion matches the verdict, negation-
    # aware (a benign explanation that says "no malicious activity" still counts
    # as a benign conclusion).
    mal_present = _present_unnegated(
        exp_lower, ('malicious', 'attack', 'compromise', 'unauthorized', 'suspicious'))
    ben_present = any(
        w in exp_lower for w in ('benign', 'legitimate', 'normal', 'routine', 'no indication'))
    if is_malicious and mal_present:
        score += 1
        details.append('consistent')
    elif not is_malicious and ben_present and not mal_present:
        score += 1
        details.append('consistent')

    sec_terms = [
        'credential', 'privilege', 'lateral', 'exfiltrat', 'persistence',
        'escalat', 'brute', 'injection', 'hijack', 'dump', 'enumerate',
        'reconnaissance', 'exploit', 'payload', 'obfuscat', 'evasion',
    ]
    if any(t in exp_lower for t in sec_terms):
        score += 1
        details.append('domain-aware')

    return {'score': score, 'max': 4, 'details': details}


def grade_from_total(total: float) -> str:
    """Map total score (0-20) to a letter grade."""
    if total >= 17:
        return 'A'
    if total >= 14:
        return 'B'
    if total >= 10:
        return 'C'
    return 'D'


def compute_score_breakdown(
    alignment: Optional[Dict],
    hallucination: Dict,
    reasoning: Dict,
    validation: Dict,
    parsed: Dict,
    is_malicious: bool,
    expected_malicious: Optional[str],
) -> Dict[str, Any]:
    """Compute the 20-point composite score."""
    if alignment and alignment.get('score') is not None:
        extraction = round(6 * alignment['score'] / 100, 1)
    else:
        extraction = 0.0
        if validation.get('is_valid'):
            extraction += 2.0
        populated = validation.get('evidence_fields_populated', 0)
        extraction += min(populated, 4)
    extraction = min(extraction, 6.0)

    interpretation = 0.0
    if expected_malicious is not None:
        gt_is_mal = expected_malicious == 'YES'
        if is_malicious == gt_is_mal:
            interpretation += 4.0
    else:
        if parsed.get('malicious') is not None:
            interpretation += 2.0

    if validation.get('evidence_fields_populated', 0) >= 2:
        interpretation += 1.0

    if 'consistent' in reasoning.get('details', []):
        interpretation += 1.0

    interpretation = min(interpretation, 6.0)

    hall_score = hallucination.get('score', 4)
    reason_score = reasoning.get('score', 0)

    total = round(extraction + interpretation + hall_score + reason_score, 1)

    return {
        'extraction': extraction,
        'interpretation': interpretation,
        'hallucination': hall_score,
        'reasoning': reason_score,
        'total': total,
        'grade': grade_from_total(total),
    }
