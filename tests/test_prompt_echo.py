"""Regression tests for the prompt-echo detector.

When aggressively quantized models (e.g. MoE at MXFP8) collapse on long
inputs they regurgitate the prompt scaffold instead of analysing. The
benchmark previously scored those regurgitations as positive detections,
poisoning the FP and hallucination metrics. ``looks_like_prompt_echo``
catches the three observed failure shapes so ``process_file`` can route
them to ``status='error'`` instead.

Failure samples here are taken verbatim from a real qwen3.6:35b-a3b-mxfp8
run that produced incorrect MALICIOUS verdicts on benign files.
"""
import unittest

from forcastl.core.response_parser import looks_like_prompt_echo


# Verbatim from the broken run output —
#   File: BENIGN-ID4738-Helpdesk password reset for locked user.csv
# Detector wrongly scored this 'MALICIOUS, confidence 80%'.
PLACEHOLDER_ECHO = """9. Do NOT use ANY other data sources (e.g., internet searches)

RESPOND IN THIS EXACT FORMAT:

MALICIOUS: [YES for attack behavior, NO for routine/benign activity]

EVIDENCE:
- Event IDs: [list all Event IDs you found, comma-separated]
- Processes: [list any process names/executables you found]
- Accounts: [list any usernames you found]
- Commands: [list any command lines you found]
- Network: [list only exact IPs/hostnames copied verbatim from the logs; otherwise "None"]

EXPLANATION:
"""

# Verbatim — rules 1-4 echoed repeatedly until the model hit --max-tokens.
REPETITION_LOOP = "\n\n---\n\n".join([
    '1. Use ONLY information found in the event data above\n'
    '2. Follow the format EXACTLY as shown\n'
    '3. If a field has no data, write "None"\n'
    '4. Every evidence item you output MUST be copied verbatim from the '
    'event-log data above. If you cannot find the exact substring, write '
    '"None" for that field.'
] * 6)

# Verbatim from the broken run — instruction echo with empty scaffold.
INSTRUCTION_ECHO = """9. Do NOT use ANY other data sources (no internet searches, no external tools)

---

1. Analyze the event log data above and respond with:

MALICIOUS: [YES for attack behavior, NO for routine/benign activity]

EVIDENCE:

EXPLANATION:
"""

# Verbatim from a foundation-sec:latest run — the model confabulated a "rule
# 9" that wasn't in the prompt and an ANSWER: placeholder that also wasn't.
# Structurally empty: no MALICIOUS field, no EVIDENCE, no EXPLANATION.
FOUNDATION_SEC_RULE_ECHO = """9. Do NOT use ANY other data sources (e.g., OSINT)

ANSWER: [copy/paste EXACTLY as shown above]
"""

# Rule echo without bracketed placeholders — the model regurgitates the
# CRITICAL RULES section instead of producing a verdict. No MALICIOUS/
# EVIDENCE/EXPLANATION structure, so the tier-2 rule-echo path should fire.
BARE_RULE_ECHO = """Use ONLY information found in the event data above.
Follow the format EXACTLY as shown.
Every evidence item you output MUST be copied verbatim from the event-log
data above.
"""

# A well-formed benign response from the same run — must NOT trigger.
WELL_FORMED_BENIGN = """MALICIOUS: NO

EVIDENCE:
- Event IDs: 4624
- Processes: C:\\Windows\\System32\\services.exe
- Accounts: BKP01$, svc-veeam
- Commands: None
- Network: None
- Registry: None

EXPLANATION:
This log shows a routine service logon (LogonType 5) where the computer
account BKP01$ authenticates as the svc-veeam service account through
services.exe. Standard automated backup operation, no malicious indicators.
"""

# Real malicious response with a high-confidence verdict — must NOT trigger.
WELL_FORMED_MALICIOUS = """MALICIOUS: YES

EVIDENCE:
- Event IDs: 33205
- Processes: None
- Accounts: sa
- Commands: Login failed for user 'sa'. Reason: An error occurred while evaluating the password. [CLIENT: 10.23.23.9]
- Network: 10.23.23.9
- Registry: None

EXPLANATION:
Two consecutive failed login attempts for the highly privileged 'sa' account
from a single source IP within a 20-second window — classic brute-force or
credential-stuffing signature against SQL Server.
"""


class TestPromptEchoDetector(unittest.TestCase):
    """Locks in detection of the three observed failure shapes."""

    def test_placeholder_echo_is_caught(self):
        is_echo, reason = looks_like_prompt_echo(PLACEHOLDER_ECHO)
        self.assertTrue(is_echo)
        self.assertTrue(reason.startswith("placeholder:"),
                        f"expected placeholder reason, got {reason!r}")

    def test_repetition_loop_is_caught(self):
        is_echo, reason = looks_like_prompt_echo(REPETITION_LOOP)
        self.assertTrue(is_echo)
        self.assertEqual(reason, "repetition_loop")

    def test_instruction_echo_is_caught(self):
        is_echo, reason = looks_like_prompt_echo(INSTRUCTION_ECHO)
        self.assertTrue(is_echo)
        # Either the placeholder line or the bare instruction phrase can win
        # the first match; both indicate the same failure mode.
        self.assertTrue(reason.startswith(("placeholder:", "instruction:")),
                        f"expected echo reason, got {reason!r}")

    def test_foundation_sec_rule_echo_is_caught(self):
        is_echo, reason = looks_like_prompt_echo(FOUNDATION_SEC_RULE_ECHO)
        self.assertTrue(is_echo,
                        "foundation-sec's confabulated 'rule 9' + ANSWER placeholder "
                        "should be caught")
        self.assertTrue(reason.startswith(("placeholder:", "rule_echo:")),
                        f"expected placeholder/rule_echo reason, got {reason!r}")

    def test_bare_rule_echo_without_structure_is_caught(self):
        is_echo, reason = looks_like_prompt_echo(BARE_RULE_ECHO)
        self.assertTrue(is_echo,
                        "rule imperatives without MALICIOUS/EVIDENCE/EXPLANATION "
                        "structure should be flagged as echo")
        self.assertTrue(reason.startswith("rule_echo:"),
                        f"expected rule_echo reason, got {reason!r}")

    def test_rule_phrasing_inside_explanation_does_not_false_positive(self):
        # A real response that *quotes* a rule-like imperative inside its
        # EXPLANATION must not be flagged as echo. The tier-2 rule patterns
        # are gated on the response being structurally incomplete.
        response = """MALICIOUS: NO

EVIDENCE:
- Event IDs: 4624
- Processes: services.exe
- Accounts: SYSTEM
- Commands: None
- Network: None
- Registry: None

EXPLANATION:
The actor did NOT use any other data sources beyond the standard Windows
auth subsystem — services.exe authenticating SYSTEM is the canonical
service-logon path. Routine activity.
"""
        is_echo, reason = looks_like_prompt_echo(response)
        self.assertFalse(is_echo,
                         f"false positive on legitimate explanation: {reason!r}")

    def test_well_formed_benign_passes_through(self):
        is_echo, reason = looks_like_prompt_echo(WELL_FORMED_BENIGN)
        self.assertFalse(is_echo, f"false positive on clean response: {reason!r}")
        self.assertEqual(reason, "")

    def test_well_formed_malicious_passes_through(self):
        is_echo, reason = looks_like_prompt_echo(WELL_FORMED_MALICIOUS)
        self.assertFalse(is_echo, f"false positive on clean response: {reason!r}")
        self.assertEqual(reason, "")

    def test_empty_response_passes_through(self):
        # Empty / missing responses are caught earlier in the pipeline
        # (Error: prefix or no-events path); the echo detector should not
        # claim them.
        self.assertEqual(looks_like_prompt_echo(""), (False, ""))
        self.assertEqual(looks_like_prompt_echo(None), (False, ""))


if __name__ == "__main__":
    unittest.main()
