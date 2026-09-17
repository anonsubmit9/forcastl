"""Consensus logic for the cross-model label audit (tools.cross_model_audit)."""
import unittest

from tools.cross_model_audit import (
    collect_signals, find_verdict_disagreements, find_hallucination_consensus, gt_label,
)


def _manifest(model, rows):
    return (model, {"model": model, "files": rows})


def _row(fname, malicious, status="processed", hall=0.0):
    return {"filename": fname, "status": status, "malicious": malicious,
            "hallucination_rate": hall}


GT = {"a.evtx": {"malicious": "YES"}, "b.evtx": {"malicious": "NO"},
      "c.csv": {"malicious": "YES"}}


class GtLabelTests(unittest.TestCase):
    def test_csv_to_evtx_fallback(self):
        gt = {"x.evtx": {"malicious": "YES"}}
        self.assertEqual(gt_label(gt, "x.csv"), "YES")

    def test_direct_hit(self):
        self.assertEqual(gt_label(GT, "c.csv"), "YES")


class ConsensusTests(unittest.TestCase):
    def setUp(self):
        # 3 models. On a.evtx (GT=YES) all say NO → disagreement. On b.evtx
        # (GT=NO) all say NO → agreement (no flag). c.csv: only 2 processed it.
        self.manifests = [
            _manifest("m1", [_row("a.evtx", False, hall=0.2), _row("b.evtx", False),
                             _row("c.csv", True)]),
            _manifest("m2", [_row("a.evtx", False, hall=0.1), _row("b.evtx", False),
                             _row("c.csv", True)]),
            _manifest("m3", [_row("a.evtx", False, hall=0.3), _row("b.evtx", False)]),
        ]
        self.verdicts, self.hall = collect_signals(self.manifests)

    def test_verdict_disagreement_flagged(self):
        d = find_verdict_disagreements(self.verdicts, GT, min_models=3)
        self.assertEqual([x["file"] for x in d], ["a.evtx"])
        self.assertEqual(d[0]["gt_label"], "YES")

    def test_agreement_not_flagged(self):
        # b.evtx: all say NO and GT=NO → not a disagreement.
        d = find_verdict_disagreements(self.verdicts, GT, min_models=3)
        self.assertNotIn("b.evtx", [x["file"] for x in d])

    def test_min_models_gate(self):
        # c.csv processed by only 2 → excluded at min_models=3.
        d = find_verdict_disagreements(self.verdicts, GT, min_models=3)
        self.assertNotIn("c.csv", [x["file"] for x in d])

    def test_hallucination_consensus(self):
        # a.evtx: all 3 have hall>0 → consensus.
        h = find_hallucination_consensus(self.hall, min_models=3)
        self.assertEqual([x["file"] for x in h], ["a.evtx"])

    def test_skips_unprocessed_rows(self):
        manifests = [_manifest("m1", [_row("z.evtx", True, status="error")])]
        verdicts, _ = collect_signals(manifests)
        self.assertNotIn("z.evtx", verdicts)


if __name__ == "__main__":
    unittest.main()
