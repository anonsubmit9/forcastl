"""Tests for the ground-truth explorer/annotator endpoints (webapp/gt_explorer.py)."""
import json
import shutil
import unittest
from pathlib import Path
from urllib.parse import quote

from fastapi.testclient import TestClient

from forcastl import config
from forcastl.webapp import gt_explorer
from forcastl.webapp.app import app

client = TestClient(app)


class TestGtExplorerRead(unittest.TestCase):
    def test_list_files(self):
        r = client.get("/api/gt/files")
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertGreater(d["total"], 0)
        self.assertEqual(d["fields"],
                         ["event_ids", "processes", "accounts", "commands", "network", "registry"])
        row = d["files"][0]
        self.assertIn(row["malicious"], {"YES", "NO"})
        self.assertIn("counts", row)

    def test_get_file_returns_events_and_evidence(self):
        name = client.get("/api/gt/files").json()["files"][0]["name"]
        r = client.get("/api/gt/file/" + quote(name, safe=""))
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertEqual(d["name"], name)
        self.assertIsInstance(d["events"], list)
        self.assertTrue(set(d["evidence"].keys()) ==
                        {"event_ids", "processes", "accounts", "commands", "network", "registry"})

    def test_unknown_file_404(self):
        r = client.get("/api/gt/file/" + quote("does-not-exist.evtx", safe=""))
        self.assertEqual(r.status_code, 404)


class TestGtExplorerEdit(unittest.TestCase):
    def setUp(self):
        # Edit a temp COPY of the GT so the real corpus is never mutated.
        self._tmp = Path(config.OUTPUTS_DIR) / "_test_gt_explorer.json"
        shutil.copy(config.GROUND_TRUTH_FILE, self._tmp)
        self._tmplog = Path(config.OUTPUTS_DIR) / "_test_gt_edits.jsonl"
        self._orig_gt, self._orig_log = gt_explorer._GT_PATH, gt_explorer._EDIT_LOG
        gt_explorer._GT_PATH = self._tmp
        gt_explorer._EDIT_LOG = self._tmplog

    def tearDown(self):
        gt_explorer._GT_PATH, gt_explorer._EDIT_LOG = self._orig_gt, self._orig_log
        for p in (self._tmp, self._tmplog):
            p.unlink(missing_ok=True)

    def _file_with_a_token(self):
        """Find a file + a >=4-char token that appears in its source artefact."""
        for f in client.get("/api/gt/files").json()["files"]:
            d = client.get("/api/gt/file/" + quote(f["name"], safe="")).json()
            for ev in d["events"]:
                for fl in ev["fields"]:
                    for tok in str(fl["value"]).split():
                        if len(tok) >= 4 and tok.isascii():
                            return f["name"], tok
        return None, None

    def test_add_rejects_value_not_in_artefact(self):
        name = client.get("/api/gt/files").json()["files"][0]["name"]
        r = client.post("/api/gt/file/" + quote(name, safe="") + "/evidence",
                        json={"field": "processes", "value": "ZZ_NOT_IN_SOURCE_42", "op": "add"})
        self.assertEqual(r.status_code, 422)

    def test_add_then_remove_artefact_present_value(self):
        name, tok = self._file_with_a_token()
        self.assertIsNotNone(name, "no artefact token found in corpus")
        # add
        r = client.post("/api/gt/file/" + quote(name, safe="") + "/evidence",
                        json={"field": "commands", "value": tok, "op": "add"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(any(tok.lower() == v.lower() for v in r.json()["evidence"]["commands"]))
        # remove
        r2 = client.post("/api/gt/file/" + quote(name, safe="") + "/evidence",
                         json={"field": "commands", "value": tok, "op": "remove"})
        self.assertEqual(r2.status_code, 200)
        self.assertFalse(any(tok.lower() == v.lower() for v in r2.json()["evidence"]["commands"]))

    def test_batch_applies_valid_and_reports_rejected(self):
        name, tok = self._file_with_a_token()
        self.assertIsNotNone(name)
        body = {"adds": [{"field": "commands", "value": tok},
                         {"field": "processes", "value": "ZZ_NOT_IN_SOURCE_99"}],
                "removes": []}
        r = client.post("/api/gt/file/" + quote(name, safe="") + "/evidence/batch", json=body)
        self.assertEqual(r.status_code, 200, r.text)
        d = r.json()
        self.assertEqual(d["applied"]["adds"], 1)
        self.assertEqual(len(d["rejected"]), 1)
        self.assertEqual(d["rejected"][0]["reason"], "not-in-artefact")
        self.assertTrue(any(tok.lower() == v.lower() for v in d["evidence"]["commands"]))
        # batch remove it back out
        r2 = client.post("/api/gt/file/" + quote(name, safe="") + "/evidence/batch",
                         json={"adds": [], "removes": [{"field": "commands", "value": tok}]})
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r2.json()["applied"]["removes"], 1)

    def test_review_toggle_persists_in_listing(self):
        self._rev = Path(gt_explorer._REVIEW_PATH).with_suffix(".test.json")
        orig = gt_explorer._REVIEW_PATH
        gt_explorer._REVIEW_PATH = self._rev
        try:
            name = client.get("/api/gt/files").json()["files"][0]["name"]
            r = client.post("/api/gt/file/" + quote(name, safe="") + "/review", json={"reviewed": True})
            self.assertEqual(r.status_code, 200)
            self.assertTrue(r.json()["reviewed"])
            self.assertGreaterEqual(r.json()["reviewed_count"], 1)
            listing = client.get("/api/gt/files").json()
            self.assertTrue(next(f for f in listing["files"] if f["name"] == name)["reviewed"])
            self.assertGreaterEqual(listing["reviewed_count"], 1)
            # unmark
            client.post("/api/gt/file/" + quote(name, safe="") + "/review", json={"reviewed": False})
            self.assertFalse(next(f for f in client.get("/api/gt/files").json()["files"] if f["name"] == name)["reviewed"])
        finally:
            gt_explorer._REVIEW_PATH = orig
            self._rev.unlink(missing_ok=True)

    def test_batch_label_change_relabels_with_audit(self):
        name = client.get("/api/gt/files").json()["files"][0]["name"]
        cur = client.get("/api/gt/file/" + quote(name, safe="")).json()["malicious"]
        flip = "NO" if cur == "YES" else "YES"
        r = client.post("/api/gt/file/" + quote(name, safe="") + "/evidence/batch",
                        json={"adds": [], "removes": [], "label": flip, "label_reason": "test relabel"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["malicious"], flip)
        self.assertEqual(r.json()["applied"]["label"], 1)
        entry = json.loads(self._tmp.read_text(encoding="utf-8"))["files"][name]
        self.assertEqual(entry["malicious"], flip)
        self.assertEqual(entry["label_review"]["reason"], "test relabel")
        self.assertEqual(entry["label_review"]["source"], "manual-gui")

    def test_bad_field_400(self):
        name = client.get("/api/gt/files").json()["files"][0]["name"]
        r = client.post("/api/gt/file/" + quote(name, safe="") + "/evidence",
                        json={"field": "not_a_field", "value": "x", "op": "add"})
        self.assertEqual(r.status_code, 400)


if __name__ == "__main__":
    unittest.main()
