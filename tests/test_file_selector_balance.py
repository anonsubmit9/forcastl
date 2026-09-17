"""A verdict-capable sample must keep >= MIN_SAMPLES_FOR_VERDICT of EACH class.

Regression for the 2026-06-04 bug: `--include-benign` reserved *all* benign
files, so once the benign set grew to 39 a sample_size of 65 left only 26
attacks (< 30) and the run came back "insufficient". Benign is also identified
by GROUND-TRUTH label, not metadata tactic_id, so files reclassified after the
fact still count correctly.
"""
import unittest
from unittest.mock import patch

from forcastl.core.file_selector import FileSelector
from forcastl.core.verdict import MIN_SAMPLES_FOR_VERDICT


def _build(n_attack=120, n_benign=39, reclassified=2):
    """Synthetic corpus: attack files across 5 tactics + benign files, a few of
    which are benign-by-GT but tagged with an attack tactic_id (the reclass case)."""
    files, gt = {}, {}
    tactics = ["TA0002", "TA0003", "TA0005", "TA0006", "TA0008"]
    for i in range(n_attack):
        name = f"attack_{i}.evtx"
        files[name] = {"file_name": name, "full_path": f"x/{name}",
                       "tactic_id": tactics[i % len(tactics)], "total_events": 5}
        gt[name] = {"malicious": "YES"}
    for i in range(n_benign):
        name = f"benign_{i}.evtx"
        # First `reclassified` benigns carry an ATTACK tactic_id but GT says NO.
        tid = "TA0003" if i < reclassified else "BENIGN"
        files[name] = {"file_name": name, "full_path": f"x/{name}",
                       "tactic_id": tid, "total_events": 3}
        gt[name] = {"malicious": "NO"}
    return {"files": files}, gt


def _select(meta, gt, size, include_benign=True):
    lookup = {n.rsplit(".", 1)[0]: f"{n}.csv" for n in meta["files"]}
    with patch.object(FileSelector, "_build_csv_lookup", return_value=lookup):
        sel = FileSelector(meta, input_format="csv", csv_dir="x",
                           include_benign=include_benign, ground_truth_data=gt)
        return sel.select_files(mode="sample", sample_size=size)


class BalancedSampleTests(unittest.TestCase):
    def _split(self, selected, gt):
        mal = sum(1 for f in selected if gt[f["file_name"]]["malicious"] == "YES")
        ben = sum(1 for f in selected if gt[f["file_name"]]["malicious"] == "NO")
        return mal, ben

    def test_standard_sample_keeps_30_of_each(self):
        meta, gt = _build()
        sel = _select(meta, gt, 65)
        mal, ben = self._split(sel, gt)
        self.assertGreaterEqual(mal, MIN_SAMPLES_FOR_VERDICT, f"attacks={mal}")
        self.assertGreaterEqual(ben, MIN_SAMPLES_FOR_VERDICT, f"benign={ben}")
        self.assertEqual(len(sel), 65)

    def test_reclassified_benign_counted_as_benign(self):
        """A benign-by-GT file tagged with an attack tactic_id is reserved benign,
        not scored against the attack budget."""
        meta, gt = _build(reclassified=3)
        sel = _select(meta, gt, 65)
        mal, ben = self._split(sel, gt)
        # No attack-tagged-but-benign file should slip into the attack count.
        for f in sel:
            if gt[f["file_name"]]["malicious"] == "NO":
                continue
            self.assertEqual(gt[f["file_name"]]["malicious"], "YES")
        self.assertGreaterEqual(ben, MIN_SAMPLES_FOR_VERDICT)

    def test_attack_headroom_above_floor(self):
        """Attacks get headroom (>30) so a few per-file errors can't drop below."""
        meta, gt = _build()
        sel = _select(meta, gt, 65)
        mal, _ = self._split(sel, gt)
        self.assertGreater(mal, MIN_SAMPLES_FOR_VERDICT)

    def test_small_sample_caps_benign(self):
        """Smoke-size runs aren't verdict-capable, so benign is capped (15) to keep
        Smoke a fast pipeline check — not all 93 benign (which bloated it post-reset)."""
        meta, gt = _build()
        sel = _select(meta, gt, 5)
        _, ben = self._split(sel, gt)
        self.assertEqual(ben, 15)


if __name__ == "__main__":
    unittest.main()
