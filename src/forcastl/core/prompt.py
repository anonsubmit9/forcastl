#!/usr/bin/env python3
"""
Simple Prompt Manager - One standard prompt for MITRE ATT&CK LLM validation
"""

import logging

_logger = logging.getLogger(__name__)


SUPPORTED_ARTEFACT_TYPES = {"EVTX", "CSV"}


_DATA_MARKER = "WINDOWS EVENT LOG DATA:\n"
_RULES_MARKER = "\nCRITICAL RULES:\n"


def split_simple_malicious_prompt(prompt: str) -> tuple:
    """Split a generate_simple_malicious_prompt result into (system, user).

    The static instructions and CRITICAL RULES go into ``system`` so the
    Anthropic API can cache them across requests; the variable XML payload
    goes into ``user``. If markers are missing (caller built the prompt
    differently), returns ``("", prompt)`` so the whole thing ships as the
    user message — caching just won't fire.
    """
    data_idx = prompt.find(_DATA_MARKER)
    rules_idx = prompt.find(_RULES_MARKER)
    if data_idx == -1 or rules_idx == -1 or rules_idx <= data_idx:
        # The standard prompt always carries both markers; their absence means
        # the prompt wasn't built by generate_simple_malicious_prompt. Warn so a
        # silently-disabled prompt cache is diagnosable rather than invisible.
        _logger.warning(
            "split_simple_malicious_prompt: cache markers not found "
            "(data=%s, rules=%s); shipping whole prompt as user message, "
            "prompt caching disabled for this request",
            data_idx != -1, rules_idx != -1,
        )
        return "", prompt

    header = prompt[:data_idx].rstrip()
    xml_payload = prompt[data_idx + len(_DATA_MARKER):rules_idx].strip()
    rules = prompt[rules_idx:].lstrip("\n")

    system = header + "\n\n" + rules
    user = _DATA_MARKER + xml_payload
    return system, user


class PromptManager:
    """Simple prompt manager with one standard template"""

    def generate_simple_malicious_prompt(self, raw_xml_logs: str) -> str:
        """Generate a structured prompt for malicious activity detection"""
        return f"""You are a cybersecurity analyst analyzing Windows Event Log data.

Analyze the logs and respond in this EXACT format (do not add ANY other text).

A single event in isolation can be benign while the pattern across events is the attack signal — consider relationships across events (paired state changes on the same identifier, escalating privilege chains, sequential commands by the same actor) before concluding.

MALICIOUS: [YES for attack behavior, NO for routine/benign activity]

EVIDENCE:
- Event IDs: [list all Event IDs you found, comma-separated]
- Processes: [list any process names/executables you found]
- Accounts: [list any usernames you found]
- Commands: [list any command lines you found]
- Network: [list only exact IPs/hostnames copied verbatim from the logs; otherwise "None"]
- Registry: [list any registry keys you found]

EXPLANATION:
[Write 2-3 sentences explaining why this is or is not malicious based on the evidence above]

WINDOWS EVENT LOG DATA:
{raw_xml_logs}

CRITICAL RULES:
1. Use ONLY information found in the event data above
2. Follow the format EXACTLY as shown
3. Do NOT add extra sections or text
4. If a field has no data, write "None"
5. Do NOT infer or invent values (no guessed IPs/hosts/users/processes/registry paths)
6. Every evidence item you output MUST be copied verbatim from the event-log data above. If you cannot find the exact substring, write "None" for that field.
7. Network evidence must be exact and verbatim. If you output any network indicator not present in the logs, your answer is wrong.
8. Do NOT output placeholder/public sample indicators unless literally present in logs
"""

    def generate_benchmark_prompt(
        self,
        artefact_type: str,
        scenario_prompt: str,
        artefact_data: str,
    ) -> str:
        """Generate benchmark prompt for current-scope artefacts (EVTX/CSV)."""
        if artefact_type not in SUPPORTED_ARTEFACT_TYPES:
            raise ValueError(
                f"Unsupported artefact_type {artefact_type!r}. "
                f"Supported types: {sorted(SUPPORTED_ARTEFACT_TYPES)}"
            )

        return f"""You are a senior digital forensic analyst.

SCENARIO:
{scenario_prompt}

Respond in this EXACT format (no extra sections):

MALICIOUS: [YES for attack behavior, NO for routine/benign activity]

EVIDENCE:
- Event IDs: [comma-separated list or None]
- Processes: [comma-separated list or None]
- Accounts: [comma-separated list or None]
- Commands: [comma-separated list or None]
- Network: [comma-separated list or None]
- Registry: [comma-separated list or None]

EXPLANATION:
[2-4 sentences. Use only evidence present in data. If evidence is insufficient for any claim, state: "No evidence found in dataset".]

ARTEFACT TYPE: {artefact_type}
EVENT LOG DATA:
{artefact_data}

CRITICAL RULES:
1. Use ONLY information from the provided event-log data
2. Every evidence item you output MUST be copied verbatim from the event-log data above (exact substring).
3. Keep output strictly in the required format
4. If a field has no evidence, write "None"
"""
