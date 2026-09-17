"""Field-level hallucination detection against sampled artefact evidence."""

from __future__ import annotations

import html
import re
from pathlib import Path
from typing import Any, Dict, Optional, Set

from forcastl.config import FUZZY_MATCH_THRESHOLDS
from forcastl.core.ground_truth_compare import fuzzy_match

EVIDENCE_FIELDS = ('event_ids', 'processes', 'accounts', 'commands', 'network', 'registry')
EVIDENCE_FIELD_COUNT = 6

# Non-answer markers a model may echo from empty EVTX fields — never a fabrication.
_PLACEHOLDER_CLAIMS = {'-', '', 'n/a', 'none', 'null'}


def item_in_actual(item: str, actual_set: Set, field: str) -> bool:
    """Check if a claimed evidence item exists in the actual sampled data."""
    if not item or not actual_set:
        return False
    item_str = str(item).strip()

    if field == 'event_ids':
        return item_str in actual_set

    if field == 'processes':
        item_name = Path(item_str.replace('\\', '/')).name.lower()
        for act in actual_set:
            act_name = Path(str(act).replace('\\', '/')).name.lower()
            if fuzzy_match(item_name, act_name) >= FUZZY_MATCH_THRESHOLDS['processes']:
                return True
        return False

    if field == 'accounts':
        for act in actual_set:
            if fuzzy_match(item_str.lower(), str(act).lower()) >= FUZZY_MATCH_THRESHOLDS['accounts']:
                return True
        return False

    if field == 'commands':
        il = item_str.lower()
        for act in actual_set:
            al = str(act).lower()
            if il in al or al in il or fuzzy_match(item_str, str(act)) >= FUZZY_MATCH_THRESHOLDS['commands']:
                return True
        return False

    if field == 'network':
        il = item_str.lower()
        return any(il == str(a).lower() for a in actual_set)

    if field == 'registry':
        il = item_str.lower().replace('\\', '/').replace('//', '/')
        for act in actual_set:
            al = str(act).lower().replace('\\', '/').replace('//', '/')
            if il in al or al in il:
                return True
        return False

    return False


def build_cross_field_corpus(sampled_evidence: Dict) -> set:
    """Flatten every string value across evidence fields (lowercase)."""
    corpus = set()
    for items in sampled_evidence.values():
        if not items:
            continue
        for item in items:
            corpus.add(str(item).lower())
    return corpus


def claim_supported_anywhere(claim: str, corpus: set) -> bool:
    """Substring fallback against the cross-field corpus."""
    if not claim or not corpus:
        return False
    cl = str(claim).lower().strip()
    if len(cl) < 4:
        return False
    return any(cl in s for s in corpus)


def _normalize_artefact(text: str) -> str:
    """A lowercased, HTML-unescaped, whitespace-collapsed view of the artefact for
    substring matching. We keep TWO views joined together so a claim matches if it
    appears in either:

    - **tag-stripped** — so a value split across adjacent elements (a scheduled task's
      ``<Command>X</Command><Arguments>Y</Arguments>``) reads as ``X Y``.
    - **unescaped, tags intact** — so an angle-bracketed *value* (a proxy bypass
      ``<local>`` / ``<none>``) survives instead of being mistaken for a tag and stripped.
    """
    unescaped = html.unescape(str(text or ""))
    full = re.sub(r"\s+", " ", unescaped).lower()
    no_tags = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", unescaped)).lower()
    # Joined with a separator that can't appear inside a claim, so the two views can't
    # accidentally match across their boundary.
    return full + " ␟ " + no_tags


def present_in_artefact(item: str, artefact_norm: str) -> bool:
    """True if a claimed value appears verbatim in the artefact the model saw.

    Credits values that are genuinely in the artefact but not surfaced by field
    extraction — e.g. the System ``<Computer>`` host (which a model reasonably
    reports as a network indicator) or a command inside a ``TaskContent`` blob —
    so a correct read is not scored as a fabrication. Conservative substring
    match with a length floor so short tokens can't match spuriously; callers
    exclude ``event_ids`` (kept to exact matching)."""
    if not artefact_norm:
        return False
    c = re.sub(r"\s+", " ", html.unescape(str(item))).strip().lower()
    return len(c) >= 4 and c in artefact_norm


def _all_parts_in_artefact(item: str, artefact_norm: str) -> bool:
    """True when a multi-value claim is a list of values that are each present.

    Models sometimes pack several real evidence values into one field entry,
    joined by ``", "`` — e.g. a 7045 trace listing five service binaries, the
    LSA secret keys of a DAMP registry dump, or ``xp_cmdshell, 0, 1, RECONFIGURE``.
    The joined string is not a verbatim substring of the artefact, but it is not a
    fabrication if every comma-separated part is itself present. Only reached as a
    fallback (the whole item already failed the substring check); requires >=2
    parts of length >=4 so a lone value still goes through the normal check.
    """
    if not artefact_norm or "," not in item:
        return False
    parts = [p.strip() for p in str(item).split(",")]
    parts = [p for p in parts if len(p) >= 4]
    return len(parts) >= 2 and all(present_in_artefact(p, artefact_norm) for p in parts)


def _matches_decoded_ioc(item: str, decoded_iocs_norm: list) -> bool:
    """True if a claim matches a curated decoded IOC (substring either way).

    Decoded IOCs are values that exist in the artefact ONLY in encoded form
    (e.g. a char-code-joined PowerShell payload that resolves to a Mimikatz
    download URL). A model that deobfuscates and reports the real IOC is doing
    the intended analysis, not fabricating — but the artefact-substring check
    can't see through the encoding. This curated allowlist credits those reads.
    Substring both directions so ``10.23.123.11`` matches the fuller
    ``https://10.23.123.11:443/Invoke-Mimikatz.ps1`` and vice versa.
    """
    if not decoded_iocs_norm:
        return False
    c = re.sub(r"\s+", " ", html.unescape(str(item))).strip().lower()
    if len(c) < 4:
        return False
    return any(c in ioc or ioc in c for ioc in decoded_iocs_norm)


def detect_hallucinations(
    parsed: Dict,
    sampled_evidence: Optional[Dict],
    artefact_text: Optional[str] = None,
    decoded_iocs: Optional[list] = None,
) -> Dict[str, Any]:
    """Detect evidence items fabricated by the LLM (not in source data).

    A claim is a hallucination only if it is absent from the sampled evidence,
    the cross-field corpus, the curated ``decoded_iocs`` allowlist, AND
    ``artefact_text`` — the raw artefact the model was shown. The artefact-text
    check (all fields except ``event_ids``) credits values that are really
    present but missed by field extraction; ``decoded_iocs`` additionally
    credits values present only in ENCODED form (a correctly-deobfuscated
    payload IOC), so honest reads are not penalized as fabrications.
    """
    if not sampled_evidence:
        return {
            'hallucinated': {},
            'total_claimed': 0,
            'total_hallucinated': 0,
            'ratio': 0,
            'score': 4,
        }

    hallucinated = {}
    total_claimed = 0
    total_hallucinated = 0
    cross_field_corpus = None
    artefact_norm = _normalize_artefact(artefact_text) if artefact_text else None
    decoded_iocs_norm = [
        re.sub(r"\s+", " ", html.unescape(str(d))).strip().lower()
        for d in (decoded_iocs or []) if str(d).strip()
    ]

    for field in EVIDENCE_FIELDS:
        claimed = parsed['evidence'].get(field, [])
        actual = sampled_evidence.get(field, set())
        field_hallucinated = []
        real_claims = 0

        for item in claimed:
            # Placeholder / non-answer markers ("-", empty) are not claims — a
            # model echoing the EVTX empty-field marker isn't fabricating evidence.
            if str(item).strip().lower() in _PLACEHOLDER_CLAIMS:
                continue
            real_claims += 1
            if item_in_actual(item, actual, field):
                continue
            if cross_field_corpus is None:
                cross_field_corpus = build_cross_field_corpus(sampled_evidence)
            if claim_supported_anywhere(item, cross_field_corpus):
                continue
            # Final fallback: was the value actually in the artefact the model
            # saw? event_ids stay exact-matched (never credited by substring).
            if field != 'event_ids' and present_in_artefact(item, artefact_norm):
                continue
            # Multi-value enumeration: the model packed several real values into
            # one field entry — credit if every comma-separated part is present.
            if field != 'event_ids' and _all_parts_in_artefact(item, artefact_norm):
                continue
            # Curated allowlist: a correctly-deobfuscated payload IOC present
            # only in encoded form in the artefact (event_ids excluded).
            if field != 'event_ids' and _matches_decoded_ioc(item, decoded_iocs_norm):
                continue
            field_hallucinated.append(item)

        hallucinated[field] = field_hallucinated
        total_claimed += real_claims
        total_hallucinated += len(field_hallucinated)

    ratio = min(1.0, total_hallucinated / EVIDENCE_FIELD_COUNT)
    score = round(4 * (1 - ratio), 1)

    return {
        'hallucinated': hallucinated,
        'total_claimed': total_claimed,
        'total_hallucinated': total_hallucinated,
        'ratio': ratio,
        'score': max(0, score),
    }
