"""Run durability: the hard-timeout watchdog, the keep-awake guard, and the
detection checkpoint/resume path that lets an interrupted run continue without
repeating the paid model calls already made."""
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from forcastl import config
from forcastl.core.runtime import run_with_timeout, keep_awake, CallTimeout
from forcastl.cli.detect import MaliciousActivityDetector


class RunWithTimeoutTests(unittest.TestCase):
    def test_returns_value(self):
        self.assertEqual(run_with_timeout(lambda a, b: a + b, 5, 19, 23), 42)

    def test_propagates_exception(self):
        with self.assertRaises(KeyError):
            run_with_timeout(lambda: {}["missing"], 5)

    def test_aborts_on_overrun(self):
        start = time.time()
        with self.assertRaises(CallTimeout):
            run_with_timeout(lambda: time.sleep(10), 0.3)
        self.assertLess(time.time() - start, 2.0, "watchdog did not abort promptly")

    def test_zero_timeout_means_no_limit(self):
        self.assertEqual(run_with_timeout(lambda: 7, 0), 7)


class KeepAwakeTests(unittest.TestCase):
    def test_enters_and_exits_cleanly(self):
        with keep_awake("unit-test"):
            pass  # best-effort; must never raise regardless of platform tooling

    def test_no_op_when_tool_missing(self):
        # Even if the platform helper can't be spawned, the run must proceed.
        with mock.patch("subprocess.Popen", side_effect=FileNotFoundError):
            with keep_awake("unit-test"):
                pass


class ResumeTests(unittest.TestCase):
    def _detector(self, processed_log):
        d = object.__new__(MaliciousActivityDetector)
        d.delay = 0
        d.resume = False
        d._get_model_id = lambda: "fake-model"

        def process_file(full_path, file_info):
            processed_log.append(full_path)
            return {"file_path": full_path, "status": "processed",
                    "llm_response": "MALICIOUS: NO", "response_time": 0.1,
                    "evidence_set": {"a", "b"}}  # a set exercises the _json_safe fallback

        d.process_file = process_file
        d.compute_detection = lambda result, file_info: None
        d.display_result = lambda result, file_info: None
        return d

    def test_checkpoint_written_then_resume_skips_completed(self):
        files = [{"full_path": f"F{i}.evtx"} for i in range(5)]
        with TemporaryDirectory() as tmp:
            with mock.patch.object(config, "OUTPUTS_DIR", Path(tmp)):
                # Pass 1: an "interrupted" run that only got through the first 3.
                log1 = []
                d1 = self._detector(log1)
                d1.run_detection(files[:3], run_num=1)
                self.assertEqual(log1, ["F0.evtx", "F1.evtx", "F2.evtx"])
                ckpt = d1._resume_path(1)
                self.assertTrue(ckpt.exists())
                self.assertEqual(len(ckpt.read_text(encoding="utf-8").splitlines()), 3)

                # Pass 2: --resume over ALL 5 — the first 3 are skipped, only 2 run.
                log2 = []
                d2 = self._detector(log2)
                d2.resume = True
                results = d2.run_detection(files, run_num=1)
                self.assertEqual(log2, ["F3.evtx", "F4.evtx"])
                self.assertEqual(len(results), 5)  # 3 reloaded + 2 freshly run
                self.assertEqual(len(ckpt.read_text(encoding="utf-8").splitlines()), 5)

    def test_clear_checkpoints_removes_files(self):
        with TemporaryDirectory() as tmp:
            with mock.patch.object(config, "OUTPUTS_DIR", Path(tmp)):
                d = self._detector([])
                d.run_detection([{"full_path": "F0.evtx"}], run_num=1)
                self.assertTrue(d._resume_path(1).exists())
                d.clear_resume_checkpoints(1)
                self.assertFalse(d._resume_path(1).exists())


if __name__ == "__main__":
    unittest.main()
