"""split_simple_malicious_prompt: cache split + the missing-marker warning."""
import unittest

from forcastl.core.prompt import (
    PromptManager, split_simple_malicious_prompt, _DATA_MARKER, _RULES_MARKER,
)


class SplitPromptTests(unittest.TestCase):
    def test_real_prompt_splits_into_system_and_user(self):
        prompt = PromptManager().generate_simple_malicious_prompt("<Event/>")
        system, user = split_simple_malicious_prompt(prompt)
        self.assertTrue(system)                       # static prefix + rules
        self.assertIn("CRITICAL RULES", system)
        self.assertTrue(user.startswith(_DATA_MARKER))
        self.assertIn("<Event/>", user)

    def test_missing_markers_returns_whole_prompt_and_warns(self):
        # A prompt not built by generate_simple_malicious_prompt → no split,
        # caching disabled — and now that's logged, not silent.
        with self.assertLogs("forcastl.core.prompt", level="WARNING") as cm:
            system, user = split_simple_malicious_prompt("just some text, no markers")
        self.assertEqual(system, "")
        self.assertEqual(user, "just some text, no markers")
        self.assertTrue(any("caching disabled" in m for m in cm.output))

    def test_markers_in_wrong_order_does_not_split(self):
        # RULES before DATA → invalid layout → fall back to whole-prompt user msg.
        weird = _RULES_MARKER + "x" + _DATA_MARKER + "y"
        with self.assertLogs("forcastl.core.prompt", level="WARNING"):
            system, user = split_simple_malicious_prompt(weird)
        self.assertEqual(system, "")
        self.assertEqual(user, weird)


if __name__ == "__main__":
    unittest.main()
