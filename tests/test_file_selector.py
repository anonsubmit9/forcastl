"""Tests for core/file_selector.py — csv_only filter and tag filtering."""
import unittest
from unittest.mock import patch

from forcastl.core.file_selector import FileSelector


def _meta(files):
    return {"files": files}


class CsvOnlyFilterTests(unittest.TestCase):
    """csv_only entries must be invisible to evtx runs but visible to csv runs."""

    def setUp(self):
        self.files = {
            "real.evtx": {
                "file_name": "real.evtx",
                "full_path": "data/evtx/real.evtx",
                "tactic_id": "TA0001",
                "total_events": 5,
            },
            "benign-synth.evtx": {
                "file_name": "benign-synth.evtx",
                "full_path": "data/evtx/_benign/benign-synth.evtx",
                "tactic_id": "BENIGN",
                "total_events": 3,
                "csv_only": True,
            },
        }

    def test_evtx_mode_excludes_csv_only_files(self):
        sel = FileSelector(_meta(self.files), input_format="evtx")
        selected = sel.select_files(mode="all")
        paths = {f["full_path"] for f in selected}
        self.assertIn("data/evtx/real.evtx", paths)
        self.assertNotIn("data/evtx/_benign/benign-synth.evtx", paths)

    def test_csv_mode_includes_csv_only_files(self):
        # In csv mode the selector also requires a matching CSV. Stub the
        # lookup so both entries appear to have matches.
        with patch.object(FileSelector, "_build_csv_lookup",
                          return_value={"real": "x.csv", "benign-synth": "y.csv"}):
            sel = FileSelector(_meta(self.files), input_format="csv",
                               csv_dir="data/csv")
        selected = sel.select_files(mode="all")
        paths = {f["full_path"] for f in selected}
        self.assertIn("data/evtx/real.evtx", paths)
        self.assertIn("data/evtx/_benign/benign-synth.evtx", paths)

    def test_excluded_flag_still_takes_precedence(self):
        self.files["benign-synth.evtx"]["excluded"] = True
        with patch.object(FileSelector, "_build_csv_lookup",
                          return_value={"real": "x.csv", "benign-synth": "y.csv"}):
            sel = FileSelector(_meta(self.files), input_format="csv",
                               csv_dir="data/csv")
        selected = sel.select_files(mode="all")
        paths = {f["full_path"] for f in selected}
        self.assertNotIn("data/evtx/_benign/benign-synth.evtx", paths)


class TestSetFilterTests(unittest.TestCase):
    """Verify the `test_set` filter picks exactly the requested bucket."""

    def setUp(self):
        self.files = {
            "a.evtx": {"file_name": "a.evtx", "full_path": "x/a.evtx", "tactic_id": "TA0001"},
            "b.evtx": {"file_name": "b.evtx", "full_path": "x/b.evtx", "tactic_id": "TA0001"},
            "d.evtx": {"file_name": "d.evtx", "full_path": "x/d.evtx", "tactic_id": "BENIGN"},
        }
        self.gt = {
            "a.evtx": {"test_set": "A"},
            "b.evtx": {"test_set": "B"},
            "d.evtx": {"test_set": "D"},
        }

    def test_test_set_D_returns_only_benign(self):
        sel = FileSelector(_meta(self.files), input_format="evtx",
                           test_set="D", ground_truth_data=self.gt)
        selected = sel.select_files(mode="all")
        names = {f["file_name"] for f in selected}
        self.assertEqual(names, {"d.evtx"})


class IncludeBenignSamplingTests(unittest.TestCase):
    """include_benign reserves all BENIGN-tactic slots before round-robin fills."""

    def _pool(self):
        # 2 benign + a large attack tactic that would dominate normal sampling.
        files = {"b1.csv": {"file_name": "b1.csv", "full_path": "b/b1.evtx",
                            "tactic_id": "BENIGN"},
                 "b2.csv": {"file_name": "b2.csv", "full_path": "b/b2.evtx",
                            "tactic_id": "BENIGN"}}
        for i in range(40):
            k = f"a{i}.csv"
            files[k] = {"file_name": k, "full_path": f"a/{k}",
                        "tactic_id": "TA0001"}
        return files

    def test_default_sampling_may_omit_benign(self):
        # Baseline: without include_benign, round-robin weights toward big tactic
        files = self._pool()
        sel = FileSelector(_meta(files), input_format="evtx")
        selected = sel.select_files(mode="sample", sample_size=5)
        benign = [f for f in selected if f["tactic_id"] == "BENIGN"]
        self.assertEqual(len(selected), 5)
        # Even split would put 2 benign + 3 attack, but the big-bucket bias
        # means at most a couple benign appear. Assert it's at most 2.
        self.assertLessEqual(len(benign), 2)

    def test_include_benign_guarantees_all_benign_in_sample(self):
        files = self._pool()
        sel = FileSelector(_meta(files), input_format="evtx", include_benign=True)
        selected = sel.select_files(mode="sample", sample_size=5)
        benign = [f for f in selected if f["tactic_id"] == "BENIGN"]
        attack = [f for f in selected if f["tactic_id"] == "TA0001"]
        self.assertEqual(len(benign), 2, "all benign files should be reserved")
        self.assertGreaterEqual(len(attack), 1, "remaining slots filled by attack")
        self.assertEqual(len(selected), 5)

    def test_include_benign_reserves_all_benigns_even_when_sample_size_smaller(self):
        """When include_benign=True, ALL benign files are reserved even if
        sample_size is smaller than the benign count. The earlier behavior
        (slice [:max_files] dropped benigns to fit) defeated the FP-rate
        measurement the flag exists for. Audit-flagged regression bug —
        this test pins the corrected semantics."""
        files = self._pool()
        sel = FileSelector(_meta(files), input_format="evtx", include_benign=True)
        selected = sel.select_files(mode="sample", sample_size=1)
        benign = [f for f in selected if f["tactic_id"] == "BENIGN"]
        attack = [f for f in selected if f["tactic_id"] != "BENIGN"]
        self.assertEqual(len(benign), 2,
                         "all benigns must be reserved regardless of sample_size")
        self.assertGreaterEqual(len(attack), 1,
                                "at least 1 attack file must remain so recall is measurable")


if __name__ == "__main__":
    unittest.main()

class PrefilterSamplingTests(unittest.TestCase):
    """Tag filters apply to the pool BEFORE sampling, so sample_size counts
    matching files (a post-sample filter silently returned fewer files)."""

    def setUp(self):
        # 20 easy + 6 hard files in one tactic.
        self.files = {}
        self.gt = {}
        for i in range(20):
            k = f"easy{i}.evtx"
            self.files[k] = {"file_name": k, "full_path": f"x/{k}", "tactic_id": "TA0001"}
            self.gt[k] = {"difficulty": "easy"}
        for i in range(6):
            k = f"hard{i}.evtx"
            self.files[k] = {"file_name": k, "full_path": f"x/{k}", "tactic_id": "TA0001"}
            self.gt[k] = {"difficulty": "hard"}

    def test_sample_counts_filtered_files(self):
        sel = FileSelector(_meta(self.files), input_format="evtx",
                           difficulty="hard", ground_truth_data=self.gt)
        selected = sel.select_files(mode="sample", sample_size=5)
        names = {f["file_name"] for f in selected}
        self.assertEqual(len(selected), 5)
        self.assertTrue(all(n.startswith("hard") for n in names))

    def test_sample_capped_by_matching_pool(self):
        sel = FileSelector(_meta(self.files), input_format="evtx",
                           difficulty="hard", ground_truth_data=self.gt)
        selected = sel.select_files(mode="sample", sample_size=50)
        self.assertEqual(len(selected), 6)

    def test_selection_is_deterministic(self):
        sel1 = FileSelector(_meta(self.files), input_format="evtx")
        sel2 = FileSelector(_meta(self.files), input_format="evtx")
        a = [f["file_name"] for f in sel1.select_files(mode="sample", sample_size=10)]
        b = [f["file_name"] for f in sel2.select_files(mode="sample", sample_size=10)]
        self.assertEqual(a, b)
