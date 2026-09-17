"""compute_detection scores and writes result['detection']; display_result only reads it."""
import io
import unittest
from contextlib import redirect_stdout

from forcastl.reporting.console_display import compute_detection, display_result


class _FakeDetector:
    def __init__(self):
        self.calls = 0

    def detect(self, *a, **k):
        self.calls += 1
        return {
            "is_malicious": True, "confidence": 90,
            "parsed": {"malicious": "YES", "evidence": {f: [] for f in
                       ["event_ids", "processes", "accounts", "commands", "network", "registry"]},
                       "explanation": "x"},
            "validation": {"is_valid": True, "issues": [], "evidence_fields_populated": 1},
            "alignment": None,
        }


def _result(status="processed"):
    return {"file_path": "x/a.csv", "status": status, "llm_response": "MALICIOUS: YES"}


def _file_info():
    return {"tactic_id": "TA0001", "file_name": "a.csv"}


class ComputeDisplaySplitTests(unittest.TestCase):
    def test_compute_writes_detection(self):
        det = _FakeDetector()
        r = _result()
        out = compute_detection(r, _file_info(), det)
        self.assertIs(r["detection"], out)
        self.assertEqual(det.calls, 1)

    def test_error_status_gets_benign_stub_without_detect(self):
        det = _FakeDetector()
        r = _result(status="error")
        out = compute_detection(r, _file_info(), det)
        self.assertEqual(det.calls, 0)            # no scoring on error rows
        self.assertFalse(out["is_malicious"])
        self.assertIn("error", out["validation"]["issues"])

    def test_display_does_not_recompute_when_detection_present(self):
        det = _FakeDetector()
        r = _result()
        compute_detection(r, _file_info(), det)
        with redirect_stdout(io.StringIO()):
            display_result(r, _file_info(), det)
        self.assertEqual(det.calls, 1)            # compute ran once; display reads it

    def test_display_is_a_noop_without_detection_and_no_detector(self):
        r = _result()
        with redirect_stdout(io.StringIO()) as buf:
            display_result(r, _file_info(), detector=None)
        self.assertNotIn("detection", r)
        self.assertEqual(buf.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
