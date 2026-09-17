#!/usr/bin/env python3
"""Unified response parser for structured LLM output.

Standalone functions extracted from ``core.detector`` and
``core.benchmark_scoring`` so that every consumer shares a single
parsing path.
"""

import re
from collections import Counter
from typing import Dict, Any, List, Tuple


# ---------------------------------------------------------------------------
# Prompt-echo detector
# ---------------------------------------------------------------------------

# Tier 1: bracketed placeholders / explicit instruction phrases. A real
# answer never contains these literal strings — flag unconditionally.
_PLACEHOLDER_PATTERNS = [
    (r"\[YES for attack behavior", "placeholder:malicious"),
    (r"\[list all Event IDs you found", "placeholder:event_ids"),
    (r"\[list any process names", "placeholder:processes"),
    (r"\[list any usernames", "placeholder:accounts"),
    (r"\[list any command lines", "placeholder:commands"),
    (r"\[list only exact IPs", "placeholder:network"),
    (r"\[list any registry keys", "placeholder:registry"),
    (r"\[Write 2-3 sentences explaining", "placeholder:explanation"),
    (r"ANSWER:\s*\[copy/paste EXACTLY", "placeholder:answer"),
    (r"RESPOND IN THIS EXACT FORMAT", "instruction:respond_format"),
    (r"Analyze the logs and respond in this EXACT format", "instruction:analyze_format"),
]

# Tier 2: instruction-style imperatives that *can* legitimately appear in an
# EXPLANATION ("the actor did NOT use a recognised tool…"). These only count
# as echo when the response is missing the core structure (no MALICIOUS/
# EVIDENCE/EXPLANATION), i.e. the model is regurgitating rules in place of
# producing an answer.
_RULE_ECHO_PATTERNS = [
    (r"Do NOT use ANY other data sources", "rule_echo:no_external_data"),
    (r"Follow the format EXACTLY", "rule_echo:format"),
    (r"Every evidence item you output MUST", "rule_echo:verbatim"),
    (r"Use ONLY information found in the event data", "rule_echo:event_data_only"),
    (r"copied verbatim from the event-log data above", "rule_echo:verbatim_copy"),
    (r"Do NOT (?:infer|invent) (?:or invent )?values", "rule_echo:no_invent"),
]


def looks_like_prompt_echo(response: str) -> Tuple[bool, str]:
    """Return ``(True, reason)`` when the response is regurgitating the prompt.

    Two tiers of detection, by precision:

      - **Placeholder / instruction echo (always flagged)** — output contains
        a bracketed template field like ``[YES for attack behavior, NO ...]``
        or a literal prompt phrase like ``RESPOND IN THIS EXACT FORMAT`` that
        cannot appear in a real answer.
      - **Repetition loop (always flagged)** — the same non-trivial line
        appears ≥5 times, indicating a sampler collapse.
      - **Rule echo (only when structurally incomplete)** — imperative
        instruction lines (``Do NOT use ANY other data sources``, ``Follow
        the format EXACTLY``) that the model regurgitates instead of an
        answer. These can also appear inside a real EXPLANATION, so they
        only count as echo when the response is missing the core
        ``MALICIOUS:`` / ``EVIDENCE:`` / ``EXPLANATION:`` structure.
    """
    if not response:
        return False, ""

    for pattern, reason in _PLACEHOLDER_PATTERNS:
        if re.search(pattern, response, re.IGNORECASE):
            return True, reason

    lines = [l.strip() for l in response.splitlines() if l.strip()]
    if lines:
        most, n = Counter(lines).most_common(1)[0]
        if n >= 5 and len(most) >= 20:
            return True, "repetition_loop"

    has_verdict = re.search(r"MALICIOUS:\s*(YES|NO)\b", response, re.IGNORECASE) is not None
    has_evidence = re.search(r"EVIDENCE:", response, re.IGNORECASE) is not None
    has_explanation = re.search(r"EXPLANATION:", response, re.IGNORECASE) is not None
    if not (has_verdict and has_evidence and has_explanation):
        for pattern, reason in _RULE_ECHO_PATTERNS:
            if re.search(pattern, response, re.IGNORECASE):
                return True, reason

    return False, ""


def is_incomplete_response(response: str) -> Tuple[bool, str]:
    """Detect a response the model never actually answered — empty, or with no
    ``MALICIOUS: YES/NO`` verdict (e.g. a reasoning model that spent its entire
    output budget on the think trace before emitting the structured answer).

    Such a response must NOT default to a benign classification — that silently
    becomes a false negative on attack files — so the caller routes it to the
    error bucket. A truncated-but-classified response (verdict present,
    EXPLANATION cut off) is still usable and is NOT flagged here.

    Returns ``(is_incomplete, reason)``.
    """
    if not response or not response.strip():
        return True, "empty_response"
    cleaned = clean_response(response)
    if re.search(r"MALICIOUS:\s*(YES|NO)\b", cleaned, re.IGNORECASE) is None:
        return True, "no_verdict"
    return False, ""

# ---------------------------------------------------------------------------
# Module-level constants – regex patterns for structured LLM responses
# ---------------------------------------------------------------------------

_NEXT_FIELD = r'(?=\s*\n\s*-?\s*(?:Event IDs|Processes|Accounts|Commands|Network|Registry|EXPLANATION)\s*:|\Z)'
PATTERNS = {
    'malicious': r'MALICIOUS:\s*(YES|NO)',
    'evidence_section': r'EVIDENCE:',
    'event_ids': r'Event IDs:\s*([^\n]+)',
    'processes': r'Processes:\s*([^\n]+)',
    'accounts': r'Accounts:\s*([^\n]+)',
    'commands': r'Commands:\s*([\s\S]+?)' + _NEXT_FIELD,
    'network': r'Network:\s*([^\n]+)',
    'registry': r'Registry:\s*([\s\S]+?)' + _NEXT_FIELD,
    'explanation': r'EXPLANATION:\s*([^\n]+(?:\n(?!MALICIOUS|EVIDENCE)[^\n]+)*)',
}


# ---------------------------------------------------------------------------
# clean_response  (extracted from MaliciousDetector._clean_response)
# ---------------------------------------------------------------------------

def clean_response(text: str) -> str:
    """Clean LLM response – remove markdown blocks and normalize formatting."""
    cleaned = text.strip()

    # Remove markdown code blocks
    cleaned = re.sub(r'```(?:bash|shell|python|text)?\s*\n?', '', cleaned)
    cleaned = re.sub(r'```\s*$', '', cleaned)

    # Remove markdown bold markers: **text** → text
    cleaned = re.sub(r'\*\*([^*]+)\*\*', r'\1', cleaned)
    # Remove stray leading ** (LLMs sometimes prefix fields with **)
    cleaned = re.sub(r'(?:^|\n)\*\*\s*', '\n', cleaned)

    # Remove brackets from MALICIOUS field and normalize case: [yes] → YES
    cleaned = re.sub(r'MALICIOUS:\s*\[?(YES|NO)\]?',
                     lambda m: f'MALICIOUS: {m.group(1).upper()}',
                     cleaned, flags=re.IGNORECASE)

    # Normalize field names (handle variations)
    cleaned = re.sub(r'(?:^|\n)Process Names?:', r'\nProcesses:', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'(?:^|\n)Account Names?:', r'\nAccounts:', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'(?:^|\n)Command Lines?:', r'\nCommands:', cleaned, flags=re.IGNORECASE)

    # Remove repeated EVIDENCE sections (hallucination)
    sections = cleaned.split('EVIDENCE:')
    if len(sections) > 2:
        # Keep only first EVIDENCE section, drop subsequent ones
        cleaned = sections[0] + 'EVIDENCE:' + sections[1]

    return cleaned.strip()


# ---------------------------------------------------------------------------
# split_list  (extracted from benchmark_scoring._split_list)
# ---------------------------------------------------------------------------

def split_list(raw: str, prefer_semicolon: bool = False) -> List[str]:
    """Split a raw evidence field value into a list of items."""
    if not raw:
        return []
    value = raw.strip()
    if value.lower() in {"none", "n/a"}:
        return []
    if prefer_semicolon and ";" in value:
        parts = value.split(";")
    elif prefer_semicolon:
        parts = [value]
    else:
        parts = value.split(",")
    return [p.strip() for p in parts if p.strip() and p.strip().lower() not in {"none", "n/a"}]


# ---------------------------------------------------------------------------
# parse_structured_response
# (based on MaliciousDetector._parse_structured_response with evidence_blob)
# ---------------------------------------------------------------------------

def parse_structured_response(text: str, *, clean: bool = True) -> Dict[str, Any]:
    """Extract all fields from a structured LLM response.

    Parameters
    ----------
    text : str
        Raw LLM response text.
    clean : bool
        If *True* (default), run ``clean_response`` on *text* first.

    Returns
    -------
    dict
        ``{malicious, evidence, explanation, evidence_blob}``
    """
    if clean:
        response = clean_response(text)
    else:
        response = text

    parsed: Dict[str, Any] = {
        'malicious': None,
        'evidence': {
            'event_ids': [],
            'processes': [],
            'accounts': [],
            'commands': [],
            'network': [],
            'registry': [],
        },
        'explanation': None,
        'evidence_blob': '',
    }

    # Extract MALICIOUS field
    match = re.search(PATTERNS['malicious'], response, re.IGNORECASE)
    if match:
        parsed['malicious'] = match.group(1).upper()

    # Collect raw field values for evidence_blob before cleaning
    raw_field_values: List[str] = []

    # Extract evidence fields
    for field in ['event_ids', 'processes', 'accounts', 'commands', 'network', 'registry']:
        match = re.search(PATTERNS[field], response, re.IGNORECASE)
        if match:
            value = match.group(1).strip()

            # Capture raw value for evidence_blob
            if value.lower() not in ['none', 'n/a', '']:
                raw_field_values.append(value)

            if value.lower() not in ['none', 'n/a', '']:
                # Use split_list with prefer_semicolon for commands/registry
                if field in ['commands', 'registry']:
                    items = split_list(value, prefer_semicolon=True)
                else:
                    items = split_list(value)

                # Clean each item
                cleaned_items = []
                for item in items:
                    item_clean = item.strip()
                    # Strip parenthetical descriptions only for event IDs:
                    # "4688 (Process Creation)" → "4688"
                    if field == 'event_ids':
                        item_clean = re.sub(r'\s*\([^)]+\)', '', item_clean).strip()
                    # Strip brackets: "[4625]" → "4625"
                    item_clean = item_clean.strip('[]')
                    # Normalize account claims with trailing SID annotation:
                    # "user (S-1-...)" -> "user"
                    if field == 'accounts':
                        item_clean = re.sub(r'\s*\(S-\d-[^)]+\)\s*$', '', item_clean, flags=re.IGNORECASE)
                        # Normalize "SID (user)" -> "user"
                        sid_wrapped = re.match(r'^S-\d-[^\s]*\s+\(([^)]+)\)$', item_clean, flags=re.IGNORECASE)
                        if sid_wrapped:
                            item_clean = sid_wrapped.group(1).strip()
                    if field == 'network':
                        # Normalize "ip-or-host (label)" -> "ip-or-host"
                        item_clean = re.sub(r'\s*\([^)]+\)\s*$', '', item_clean).strip()
                    # Strip "x2" or "multiple instances" suffixes
                    item_clean = re.sub(r'\s+\(x\d+\)|\s+\(multiple.*?\)', '', item_clean, flags=re.IGNORECASE)

                    if item_clean and item_clean.lower() not in ['none', 'n/a']:
                        cleaned_items.append(item_clean)

                # De-duplicate while preserving order to avoid overweighting repeats.
                seen: set = set()
                deduped_items: List[str] = []
                for ci in cleaned_items:
                    key = ci.lower()
                    if key in seen:
                        continue
                    seen.add(key)
                    deduped_items.append(ci)

                parsed['evidence'][field] = deduped_items

    # Build evidence_blob: space-joined lowercase raw field values
    parsed['evidence_blob'] = ' '.join(raw_field_values).lower()

    # Extract EXPLANATION
    match = re.search(PATTERNS['explanation'], response, re.IGNORECASE | re.DOTALL)
    if match:
        parsed['explanation'] = match.group(1).strip()

    return parsed
