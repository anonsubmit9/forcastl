"""Contractual locks on the corpus size and shape.

These assert the *canonical* counts so accidental corpus drift (a dropped GT
entry, a mislabel, a botched regeneration) fails CI instead of passing
silently. When you intentionally change the corpus, update the constants here
in the same commit — that is the point: the change becomes explicit and
reviewable.

The corpus is 328 files (219 malicious / 109 benign); GT, metadata, and on-disk
CSVs align 1:1. See internal/known_issues.md.
"""
import json
import unittest
from collections import Counter
from pathlib import Path

from forcastl.core.csv_evidence import build_csv_index, resolve_csv

REPO = Path(__file__).resolve().parents[1]

# ── Canonical numbers (update intentionally, never to "make the test pass") ──
GT_TOTAL = 328
# 2026-06-12: ALL-REAL corpus reset. Purged all 41 hand-authored synthetic files —
# they had EvtxECmd-fidelity gaps and were a provenance liability. Imported 63 real
# benign near-miss slices from
# NextronSystems/evtx-baseline (Apache-2.0, EvtxECmd-converted). Corpus is now 100%
# real: 265 folder_structure (CC0 mdecrevoisier) + 63 evtx-baseline = 328.
# Label split 219 malicious / 109 benign. The 109 benign = 63 evtx-baseline + 46 folder_structure
# attack-dataset slices relabeled benign on in-artifact intent (provenance unchanged, label flipped);
# 44 carry a GT label_review with the per-file forensic reason. Relabeled kinds: OpenSSH
# install/activate, non-priv user/group ops, defensive/neutral 4738 flag changes, low-count/
# auth-mode-rejection failed logins, read-only discovery (net/netsh/auditpol/schtasks), and a
# net-zero SeDenyServiceLogonRight grant+remove.
GT_MALICIOUS = 219
GT_BENIGN = 109
GT_DIFFICULTY = {"easy": 306, "medium": 9, "hard": 13}
METADATA_TOTAL = 328
METADATA_EXCLUDED = 0
CORE_EVIDENCE_FIELDS = {"event_ids", "processes", "accounts", "commands", "network", "registry"}


def _load(name):
    return json.loads((REPO / "data" / name).read_text(encoding="utf-8"))


class CorpusSizeLocks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gt = _load("ground_truth_evidence.json")["files"]
        cls.md = _load("metadata.json")["files"]

    def test_ground_truth_total(self):
        self.assertEqual(len(self.gt), GT_TOTAL)
        self.assertEqual(self.gt and _load("ground_truth_evidence.json")["_metadata"]["total_files"], GT_TOTAL)

    def test_label_split(self):
        c = Counter(v.get("malicious") for v in self.gt.values())
        self.assertEqual(c.get("YES"), GT_MALICIOUS)
        self.assertEqual(c.get("NO"), GT_BENIGN)
        self.assertEqual(GT_MALICIOUS + GT_BENIGN, GT_TOTAL)

    def test_difficulty_distribution(self):
        c = Counter(v.get("difficulty") for v in self.gt.values())
        self.assertEqual(dict(c), GT_DIFFICULTY)
        self.assertEqual(sum(GT_DIFFICULTY.values()), GT_TOTAL)

    def test_metadata_total_and_excluded(self):
        self.assertEqual(len(self.md), METADATA_TOTAL)
        self.assertEqual(sum(1 for v in self.md.values() if v.get("excluded")), METADATA_EXCLUDED)

    def test_every_gt_entry_is_well_formed(self):
        for name, entry in self.gt.items():
            self.assertIn(entry.get("malicious"), {"YES", "NO"}, name)
            self.assertTrue(CORE_EVIDENCE_FIELDS.issubset(entry.get("evidence", {}).keys()), name)

    def test_every_gt_entry_resolves_to_a_csv(self):
        """No orphan GT entries (the inverse gap that skewed the validator)."""
        idx = build_csv_index(str(REPO / "data" / "csv"))
        missing = [name for name in self.gt if resolve_csv(name, idx) is None]
        self.assertEqual(missing, [], f"GT entries with no CSV: {missing}")

    def test_no_gt_entry_is_metadata_excluded(self):
        """Excluded-from-corpus files must not carry a scored GT entry."""
        bad = [n for n in self.gt if self.md.get(n, {}).get("excluded")]
        self.assertEqual(bad, [], f"GT entries marked excluded in metadata: {bad}")

    def test_metadata_and_gt_keys_align_exactly(self):
        """After the 2026-06-04 trim, metadata and GT cover the same 300 files."""
        self.assertEqual(set(self.md), set(self.gt))


if __name__ == "__main__":
    unittest.main()
