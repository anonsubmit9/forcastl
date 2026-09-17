"""is_incomplete_response: empty / no-verdict responses must be flagged so they
are bucketed as errors instead of silently defaulting to a benign verdict."""
import unittest

from forcastl.core.response_parser import is_incomplete_response


class TestIncompleteResponse(unittest.TestCase):
    def test_empty(self):
        for r in ("", "   ", "\n\n\n"):
            inc, why = is_incomplete_response(r)
            self.assertTrue(inc)
            self.assertEqual(why, "empty_response")

    def test_no_verdict(self):
        # Reasoning trace with no structured MALICIOUS verdict.
        r = "Let me think about this. The events show some activity that could be..."
        inc, why = is_incomplete_response(r)
        self.assertTrue(inc)
        self.assertEqual(why, "no_verdict")

    def test_truncated_but_classified_is_usable(self):
        # Verdict + evidence present, EXPLANATION cut off -> still a real detection.
        r = ("MALICIOUS: YES\n\nEVIDENCE:\n- Event IDs: 4688\n"
             "- Processes: C:\\Windows\\System32\\netsh.exe\n")
        inc, _ = is_incomplete_response(r)
        self.assertFalse(inc)

    def test_benign_verdict_usable(self):
        inc, _ = is_incomplete_response("MALICIOUS: NO\n\nEXPLANATION: routine.")
        self.assertFalse(inc)

    def test_bracketed_verdict_usable(self):
        inc, _ = is_incomplete_response("MALICIOUS: [yes]\nEVIDENCE:\n- Event IDs: 1")
        self.assertFalse(inc)


if __name__ == "__main__":
    unittest.main()
