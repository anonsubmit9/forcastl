"""add_sample.py — the single-file corpus-expansion wrapper.

Exercises the real add path against throwaway COPIES of the catalogues (so the
committed 300-file corpus is never touched) plus one throwaway CSV under
data/csv/_benign that the test removes afterward. Confirms the entry is
written correctly, the validator stays clean, the lock constants reflect +1, and
re-running is idempotent.
"""
import csv
import json
import shutil
import unittest
from pathlib import Path

import pytest

from forcastl import config
from tools.add_sample import add_sample
from forcastl.core.csv_evidence import DEFAULT_CSV_DIR

_COLS = [
    "RecordNumber", "EventRecordId", "TimeCreated", "EventId", "Level", "Provider",
    "Channel", "ProcessId", "ThreadId", "Computer", "ChunkNumber", "UserId",
    "MapDescription", "UserName", "RemoteHost", "PayloadData1", "PayloadData2",
    "PayloadData3", "PayloadData4", "PayloadData5", "PayloadData6", "ExecutableInfo",
    "HiddenRecord", "SourceFile", "Keywords", "ExtraDataOffset", "Payload",
]


def _write_csv(path: Path) -> None:
    def row(rn):
        d = {c: "" for c in _COLS}
        d.update(
            RecordNumber=str(rn), EventId="4624", Channel="Security",
            Provider="Microsoft-Windows-Security-Auditing", Computer="PYTEST.offsec.lan",
            Payload=json.dumps({"EventData": {
                "TargetUserName": "pytest-user", "LogonType": "2",
                "SubjectUserName": "PYTEST$", "IpAddress": "-"}}),
        )
        return d
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=_COLS)
        w.writeheader()
        w.writerow(row(1))
        w.writerow(row(2))


class TestAddSample(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(config.OUTPUTS_DIR) / "_pytest_add_sample"
        self.tmp.mkdir(parents=True, exist_ok=True)
        self.gt = self.tmp / "gt.json"
        self.meta = self.tmp / "meta.json"
        self.report = self.tmp / "report.json"
        shutil.copy(config.GROUND_TRUTH_FILE, self.gt)
        shutil.copy(config.METADATA_FILE, self.meta)
        # Throwaway CSV must live under the real corpus root (add_sample enforces it).
        self.csv = Path(DEFAULT_CSV_DIR) / "_benign" / "BENIGN-PYTEST-add-sample.csv"
        _write_csv(self.csv)
        self.key = f"{self.csv.stem}.evtx"
        with open(self.gt, encoding="utf-8") as f:
            self.before_benign = sum(
                1 for v in json.load(f)["files"].values()
                if str(v.get("malicious")).upper() == "NO")

    def tearDown(self):
        self.csv.unlink(missing_ok=True)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self):
        return add_sample(
            str(self.csv), "NO", test_set="D", source="synthetic",
            keywords=["benign", "pytest"], gt_path=self.gt, meta_path=self.meta,
            report_path=self.report,
        )

    @pytest.mark.slow
    def test_adds_entry_validates_and_counts(self):
        summary = self._run()
        gt = json.loads(self.gt.read_text(encoding="utf-8"))["files"]
        meta = json.loads(self.meta.read_text(encoding="utf-8"))["files"]

        # Entry written, keyed by .evtx, label + evidence + curated tags present.
        self.assertIn(self.key, gt)
        entry = gt[self.key]
        self.assertEqual(entry["malicious"], "NO")
        self.assertEqual(entry["evidence"]["event_ids"], ["4624"])
        self.assertIn("pytest-user", entry["evidence"]["accounts"])
        self.assertEqual(entry["evidence"]["attack_accounts"], [])  # benign → empty
        self.assertEqual(entry["test_set"], "D")
        self.assertEqual(entry["explanation_keywords"], ["benign", "pytest"])

        # Metadata mirror: csv_only synthetic benign.
        self.assertEqual(meta[self.key]["tactic_id"], "BENIGN")
        self.assertTrue(meta[self.key]["csv_only"])
        self.assertEqual(meta[self.key]["test_set"], "D")

        # Validator: no fabrications. `false_claims` (a GT value absent from the
        # source) is the hard correctness invariant. `missed_evidence` (the typed
        # extractor would surface a value GT omits) is NOT asserted to be 0: ground
        # truth is hand-curated via the GT Explorer and may deliberately omit
        # extractor values (a curation choice, not an error). The new entry's own
        # completeness is covered by the evidence assertions above.
        self.assertEqual(summary["validator"]["false_claims"], 0)
        self.assertEqual(summary["locks"]["GT_TOTAL"], len(gt))
        self.assertEqual(summary["locks"]["GT_BENIGN"], self.before_benign + 1)
        self.assertEqual(summary["locks"]["METADATA_TOTAL"], len(meta))

    @pytest.mark.slow
    def test_idempotent(self):
        self._run()
        first_gt = self.gt.read_text(encoding="utf-8")
        first_meta = self.meta.read_text(encoding="utf-8")
        self._run()
        self.assertEqual(self.gt.read_text(encoding="utf-8"), first_gt)
        self.assertEqual(self.meta.read_text(encoding="utf-8"), first_meta)

    @pytest.mark.slow
    def test_keys_align_after_add(self):
        self._run()
        gt = json.loads(self.gt.read_text(encoding="utf-8"))["files"]
        meta = json.loads(self.meta.read_text(encoding="utf-8"))["files"]
        # The corpus invariant test_corpus_sizes locks: metadata keys == GT keys.
        self.assertEqual(set(gt), set(meta))


if __name__ == "__main__":
    unittest.main()
