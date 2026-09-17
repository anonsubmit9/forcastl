import unittest

from forcastl.cli.detect import MaliciousActivityDetector


class DetectorForTest(MaliciousActivityDetector):
    def _load_metadata(self):
        return {"files": {}}


class FakeParser:
    def __init__(self, events):
        self._events = list(events)

    def parse_csv_file(self, _path):
        return list(self._events)

    def format_for_llm_pure_raw_xml(self, events):
        return "\n".join(event["_raw_xml"] for event in events)


class FakePromptManager:
    def __init__(self):
        self.last_formatted_logs = None

    def generate_simple_malicious_prompt(self, raw_xml_logs):
        self.last_formatted_logs = raw_xml_logs
        return f"PROMPT\n{raw_xml_logs}"


def _make_event(event_id: str, raw_xml: str):
    return {
        "Event": {
            "System": {"EventID": event_id},
        },
        "_raw_xml": raw_xml,
    }


class TestMaliciousActivityDetectorEventCap(unittest.TestCase):
    def test_process_file_caps_events_before_prompt(self):
        detector = DetectorForTest(max_events=2)
        detector.parser = FakeParser([
            _make_event("1", "<Event>1</Event>"),
            _make_event("2", "<Event>2</Event>"),
            _make_event("3", "<Event>3</Event>"),
        ])
        detector.prompt_manager = FakePromptManager()
        detector.send_to_llm = lambda prompt: ("MALICIOUS: YES", 0.25)
        detector.file_selector._find_csv_for_evtx = lambda _p: "sample.csv"

        result = detector.process_file("sample.evtx", {"file_name": "sample.evtx"})

        self.assertTrue(result["event_cap_applied"])
        self.assertEqual(result["original_event_count"], 3)
        self.assertEqual(result["effective_event_count"], 2)
        self.assertEqual(
            detector.prompt_manager.last_formatted_logs,
            "<Event>1</Event>\n<Event>2</Event>",
        )
        self.assertNotIn("<Event>3</Event>", result["prompt"])

    def test_process_file_leaves_events_untouched_without_cap(self):
        detector = DetectorForTest(max_events=None)
        detector.parser = FakeParser([
            _make_event("1", "<Event>1</Event>"),
            _make_event("2", "<Event>2</Event>"),
        ])
        detector.prompt_manager = FakePromptManager()
        detector.send_to_llm = lambda prompt: ("MALICIOUS: YES", 0.25)
        detector.file_selector._find_csv_for_evtx = lambda _p: "sample.csv"

        result = detector.process_file("sample.evtx", {"file_name": "sample.evtx"})

        self.assertFalse(result["event_cap_applied"])
        self.assertEqual(result["original_event_count"], 2)
        self.assertEqual(result["effective_event_count"], 2)
        self.assertIn("<Event>2</Event>", result["prompt"])


class TestExecuteRuns(unittest.TestCase):
    """Control-flow coverage for the multi-run helper.

    Ensures that `execute_runs` actually calls `run_detection` N times and
    updates `detector.runs` to the true executed count — the invariant that
    keeps canonical metadata honest in both single-model and multi-model
    comparison paths.
    """

    def _detector_with_counted_run(self):
        det = DetectorForTest()
        det.runs = 0  # ensure it's updated only via execute_runs

        call_log = []

        def fake_run_detection(test_files, run_num=1):
            call_log.append(list(test_files))
            # Unique sentinel per call so we can assert ordering.
            return [{"run_index": len(call_log), "file": test_files[0]}]

        det.run_detection = fake_run_detection
        return det, call_log

    def test_executes_requested_number_of_runs(self):
        det, call_log = self._detector_with_counted_run()
        test_files = [{"file_name": "a.evtx"}]

        all_runs = det.execute_runs(test_files, runs=3)

        self.assertEqual(len(call_log), 3)
        self.assertEqual(len(all_runs), 3)
        self.assertEqual([r[0]["run_index"] for r in all_runs], [1, 2, 3])

    def test_updates_runs_attribute_to_true_count(self):
        det, _ = self._detector_with_counted_run()
        det.execute_runs([{"file_name": "a.evtx"}], runs=3)
        self.assertEqual(det.runs, 3)

    def test_runs_defaults_to_one(self):
        det, call_log = self._detector_with_counted_run()
        det.execute_runs([{"file_name": "a.evtx"}])
        self.assertEqual(len(call_log), 1)
        self.assertEqual(det.runs, 1)

    def test_zero_or_negative_runs_clamped_to_one(self):
        """Passing 0 or a negative must not silently execute nothing and
        then report `runs=0` in the contract."""
        det, call_log = self._detector_with_counted_run()
        det.execute_runs([{"file_name": "a.evtx"}], runs=0)
        self.assertEqual(len(call_log), 1)
        self.assertEqual(det.runs, 1)

    def test_each_run_receives_same_file_list(self):
        det, call_log = self._detector_with_counted_run()
        files = [{"file_name": "a.evtx"}, {"file_name": "b.evtx"}]
        det.execute_runs(files, runs=3)
        # Same files, in the same order, handed to every run.
        for files_seen in call_log:
            self.assertEqual(
                [f["file_name"] for f in files_seen],
                ["a.evtx", "b.evtx"],
            )


class TestFatalAbortPreservesCheckpoint(unittest.TestCase):
    """A non-recoverable backend error (no credit / bad key) must STOP the run and
    leave the checkpoint intact — not plow through the rest stamping errors and
    then clear the checkpoint on 'completion' (the 2026-06-12 opus quota-out)."""

    def test_classifier_only_fires_on_non_recoverable_errors(self):
        from forcastl.cli.detect import _is_fatal_api_error
        self.assertTrue(_is_fatal_api_error(
            {"status": "error", "llm_response": "Error: ... credit balance is too low ..."}))
        self.assertTrue(_is_fatal_api_error(
            {"status": "error", "error": "insufficient_quota"}))
        # Transient / recoverable — must NOT abort the whole run.
        self.assertFalse(_is_fatal_api_error(
            {"status": "error", "llm_response": "Error: 429 rate limit, retry later"}))
        self.assertFalse(_is_fatal_api_error(
            {"status": "context_exceeded", "llm_response": "Error: context too long"}))
        self.assertFalse(_is_fatal_api_error(
            {"status": "processed", "llm_response": "[+] MALICIOUS"}))

    def test_run_detection_aborts_and_keeps_only_completed_files(self):
        import json
        import tempfile
        from pathlib import Path
        from forcastl.cli.detect import FatalRunAbort

        det = DetectorForTest(delay=0)
        with tempfile.TemporaryDirectory() as td:
            ckpt = Path(td) / "ckpt.jsonl"
            det._resume_path = lambda run_num=1: ckpt
            det.compute_detection = lambda result, file_info: None
            det.display_result = lambda result, file_info: None
            outcomes = {
                "good.evtx": {"file_path": "good.evtx", "status": "processed",
                              "llm_response": "[+] MALICIOUS", "response_time": 0.1},
                "bad.evtx": {"file_path": "bad.evtx", "status": "error",
                             "error": "credit balance is too low",
                             "llm_response": "Error: credit balance is too low"},
            }
            det.process_file = lambda fp, fi: outcomes[fi["full_path"]]
            files = [{"full_path": "good.evtx", "file_name": "good.evtx"},
                     {"full_path": "bad.evtx", "file_name": "bad.evtx"}]

            with self.assertRaises(FatalRunAbort):
                det.run_detection(files, run_num=1)

            lines = [json.loads(x) for x in ckpt.read_text(encoding="utf-8").splitlines() if x.strip()]
            # Only the genuinely-completed file is checkpointed; the fatal file is
            # NOT (so --resume retries it), and the loop stopped (no third file).
            self.assertEqual([r["_key"] for r in lines], ["good.evtx"])


if __name__ == "__main__":
    unittest.main()
