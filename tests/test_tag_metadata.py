"""tag_metadata test-set classification.

Locks the fix for the D-clobber footgun: `test_set:D` (benign control) has no
derivation path, so a re-run of tag_metadata must PRESERVE an existing 'D' rather
than silently rewrite every benign sample to A/B/C.
"""
import unittest

from tools.tag_metadata import _classify_test_set, _resolve_curated


class TestResolveCurated(unittest.TestCase):
    """difficulty/test_set are curated: preserve an existing label, derive only when
    missing or when --recompute forces it. Guards against the silent corpus-wide
    re-derive that would erase hand-curated APT difficulty and benign test_set:D."""

    def test_existing_label_preserved_by_default(self):
        self.assertEqual(_resolve_curated("hard", "easy", recompute=False), "hard")
        self.assertEqual(_resolve_curated("D", "A", recompute=False), "D")

    def test_missing_label_uses_derived(self):
        self.assertEqual(_resolve_curated(None, "medium", recompute=False), "medium")
        self.assertEqual(_resolve_curated("", "A", recompute=False), "A")

    def test_recompute_overrides_curation(self):
        self.assertEqual(_resolve_curated("hard", "easy", recompute=True), "easy")


class TestClassifyTestSet(unittest.TestCase):
    def test_existing_D_is_preserved(self):
        # A benign control already in D stays in D, regardless of signal stats.
        self.assertEqual(
            _classify_test_set("BENIGN-x.evtx", {}, {}, total_events=2,
                               signal_events=2, current_test_set="D"),
            "D",
        )

    def test_no_current_set_classifies_A(self):
        self.assertEqual(
            _classify_test_set("ID1-x.evtx", {}, {}, total_events=2, signal_events=2),
            "A",
        )

    def test_only_D_is_preserved_not_abc(self):
        # A/B/C are derived, so a current 'A' on an obfuscated file still becomes 'B'.
        self.assertEqual(
            _classify_test_set("empire-payload.evtx", {}, {}, current_test_set="A"),
            "B",
        )

    def test_obfuscation_classifies_B(self):
        self.assertEqual(
            _classify_test_set("wmimplant-run.evtx", {"commands": []}, {}),
            "B",
        )

    def test_noise_heavy_classifies_C(self):
        self.assertEqual(
            _classify_test_set("ID1-x.evtx", {}, {}, total_events=100, signal_events=5),
            "C",
        )


if __name__ == "__main__":
    unittest.main()
