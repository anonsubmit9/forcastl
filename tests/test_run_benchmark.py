"""Tests for run_benchmark.py — the testcase-contract benchmark runner.

Coverage for this phase:

  - per-case failures do not abort subsequent cases
  - summary counts include failed cases broken down by status
  - manifest is written with benchmark contract + effective config
  - actual executed run count / temperature / model are stamped truthfully
  - manifest is produced alongside the existing scoring sheet CSV
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import requests

from forcastl import config
import forcastl.cli.benchmark as rb


# ── Fixtures ────────────────────────────────────────────────────────────────

_FAKE_TESTCASE_FILES = [
    "data/benchmark_cases/FAKE-001.json",
    "data/benchmark_cases/FAKE-002.json",
    "data/benchmark_cases/FAKE-003.json",
]


def _fake_testcase(tc_id: str):
    return {
        "id": tc_id,
        "artefact_type": "EVTX",
        "difficulty": "Easy",
        "scenario_prompt": "Analyze.",
        "expected_findings": [{"indicator": "cmd.exe"}],
        "hallucination_traps": [],
        "artefact_file": f"fake/{tc_id}.evtx",
    }


def _perfect_score():
    return {
        "Extraction": 6, "Interpretation": 6,
        "NoHallucination": 4, "Reasoning": 4,
        "TotalScore": 20, "Grade": "A",
    }


def _args(**overrides):
    """Build a simple args namespace for run_benchmark."""
    import types
    defaults = dict(
        testcases=["data/benchmark_cases/*.json"],
        server="http://example",
        model="test-model",
        runs=1,
        timeout=10,
        max_tokens=1000,
        temperature=0.1,
        delay=0.0,
        output_csv=None,
        output_json=None,
    )
    defaults.update(overrides)
    return types.SimpleNamespace(**defaults)


def _patched_run(args, *, send_fn, load_side_effect=None, load_return_value=None):
    """Run the benchmark with all external I/O stubbed out.

    ``load_side_effect`` / ``load_return_value`` let individual tests drive
    ``load_test_case`` behavior (e.g. raise for one path to simulate a
    malformed testcase JSON file).
    """
    if load_side_effect is None and load_return_value is None:
        # Default: three well-formed fake testcases.
        load_side_effect = [
            _fake_testcase("FAKE-001"),
            _fake_testcase("FAKE-002"),
            _fake_testcase("FAKE-003"),
        ]
    testcase_paths = [Path(p) for p in _FAKE_TESTCASE_FILES]

    with tempfile.TemporaryDirectory() as tmpdir:
        with mock.patch.object(config, "OUTPUTS_DIR", Path(tmpdir)):
            with mock.patch.object(rb, "_discover_testcases", return_value=testcase_paths):
                load_kw = (
                    {"side_effect": load_side_effect}
                    if load_side_effect is not None
                    else {"return_value": load_return_value}
                )
                with mock.patch.object(rb, "load_test_case", **load_kw):
                    with mock.patch.object(rb, "_load_artefact_data", return_value="<Event/>"):
                        with mock.patch.object(
                            rb, "PromptManager",
                            return_value=mock.MagicMock(
                                generate_benchmark_prompt=lambda *a, **kw: "PROMPT"
                            ),
                        ):
                            with mock.patch.object(rb, "EVTXParser", return_value=mock.MagicMock()):
                                with mock.patch.object(
                                    rb, "score_benchmark_response",
                                    return_value=_perfect_score(),
                                ):
                                    manifest = rb.run_benchmark(args, send_fn=send_fn)
                                    # Load the manifest back from disk so we also
                                    # exercise serialisation.
                                    manifest_path = manifest["outputs"]["manifest"]
                                    with open(manifest_path, encoding="utf-8") as f:
                                        manifest_on_disk = json.load(f)
                                    scoring_csv = manifest["outputs"]["scoring_csv"]
                                    scoring_rows = []
                                    if Path(scoring_csv).exists():
                                        with open(scoring_csv, encoding="utf-8") as f:
                                            import csv as _csv
                                            scoring_rows = list(_csv.DictReader(f))
                                    return manifest, manifest_on_disk, scoring_rows


# ── Tests ───────────────────────────────────────────────────────────────────

class PerCaseFaultToleranceTests(unittest.TestCase):

    def test_one_timeout_does_not_abort_run(self):
        """If the first testcase times out, the remaining two must still run."""
        calls = {"count": 0}

        def flaky_send(**kwargs):
            calls["count"] += 1
            if calls["count"] == 1:
                raise requests.exceptions.Timeout("simulated")
            return "LLM RESPONSE"

        manifest, _, scoring_rows = _patched_run(_args(runs=1), send_fn=flaky_send)
        summary = manifest["summary"]
        self.assertEqual(summary["total_case_runs"], 3)
        self.assertEqual(summary["processed"], 2)
        self.assertEqual(summary["failed"], 1)
        # The failure must be classified, not generic.
        self.assertEqual(summary["by_status"].get("timeout"), 1)
        # Scoring CSV only carries the 2 successful cases.
        self.assertEqual(len(scoring_rows), 2)

    def test_one_http_error_does_not_abort_run(self):
        calls = {"count": 0}

        def partially_broken_send(**kwargs):
            calls["count"] += 1
            if calls["count"] == 2:
                raise requests.exceptions.HTTPError("500 Internal Server Error")
            return "LLM RESPONSE"

        manifest, _, _ = _patched_run(_args(runs=1), send_fn=partially_broken_send)
        self.assertEqual(manifest["summary"]["processed"], 2)
        self.assertEqual(manifest["summary"]["by_status"].get("http_error"), 1)

    def test_all_cases_fail_still_produces_manifest(self):
        def always_fails(**kwargs):
            raise requests.exceptions.ConnectionError("no route")

        manifest, _, scoring_rows = _patched_run(_args(runs=1), send_fn=always_fails)
        # Run completes with all failures recorded.
        self.assertEqual(manifest["summary"]["processed"], 0)
        self.assertEqual(manifest["summary"]["failed"], 3)
        self.assertEqual(manifest["summary"]["by_status"].get("http_error"), 3)
        # Scoring CSV is written but has header + zero rows.
        self.assertEqual(len(scoring_rows), 0)
        # Per-case entries still appear in the manifest, each with error detail.
        self.assertEqual(len(manifest["cases"]), 3)
        for case in manifest["cases"]:
            self.assertEqual(case["status"], "http_error")
            self.assertIn("ConnectionError", case["error"])
            self.assertIsNone(case["total_score"])


class ManifestShapeTests(unittest.TestCase):

    def _ok_send(self, **kwargs):
        return "LLM RESPONSE"

    def test_manifest_includes_benchmark_contract_and_effective_config(self):
        manifest, on_disk, _ = _patched_run(_args(), send_fn=self._ok_send)
        for man in (manifest, on_disk):
            self.assertIn("benchmark_contract", man)
            contract = man["benchmark_contract"]
            self.assertIn("effective_config", contract)
            self.assertIn("run_tier", contract)
            # Testcase runs carry their own mode label.
            self.assertEqual(contract["effective_config"]["mode"], "testcases")

    def test_manifest_stamps_truthful_executed_runs_and_temperature(self):
        """The contract must reflect what actually ran, not what a user wished."""
        manifest, _, _ = _patched_run(
            _args(runs=3, temperature=0.0, model="actual-model"),
            send_fn=self._ok_send,
        )
        contract = manifest["benchmark_contract"]
        self.assertEqual(contract["effective_config"]["runs"], 3)
        self.assertEqual(contract["effective_config"]["temperature"], 0.0)
        self.assertEqual(manifest["model"], "actual-model")
        # 3 runs × 3 cases = 9 case-runs
        self.assertEqual(manifest["summary"]["total_case_runs"], 9)
        self.assertEqual(len(manifest["cases"]), 9)

    def test_manifest_kind_and_identity_fields(self):
        manifest, _, _ = _patched_run(_args(), send_fn=self._ok_send)
        self.assertEqual(manifest["kind"], "testcase_benchmark")
        self.assertIn("run_id", manifest)
        self.assertIn("started_at", manifest)
        self.assertIn("finished_at", manifest)
        self.assertIn("server", manifest)

    def test_manifest_includes_testcase_suite_identity(self):
        manifest, _, _ = _patched_run(_args(), send_fn=self._ok_send)
        suite = manifest["testcase_suite"]
        self.assertEqual(suite["total_cases"], 3)
        self.assertEqual(
            suite["testcase_ids"],
            ["FAKE-001", "FAKE-002", "FAKE-003"],
        )
        self.assertEqual(suite["artefact_types"], {"EVTX": 3})
        self.assertIn("patterns", suite)


class SummaryAccountingTests(unittest.TestCase):

    def test_failure_breakdown_surfaced_in_summary(self):
        """Mix of timeout + http + successes: all three statuses must appear."""
        outcomes = iter([
            requests.exceptions.Timeout("to"),
            "ok",
            requests.exceptions.HTTPError("500"),
        ])

        def mixed_send(**kwargs):
            nxt = next(outcomes)
            if isinstance(nxt, Exception):
                raise nxt
            return nxt

        manifest, _, _ = _patched_run(_args(runs=1), send_fn=mixed_send)
        by = manifest["summary"]["by_status"]
        self.assertEqual(by.get("processed"), 1)
        self.assertEqual(by.get("timeout"), 1)
        self.assertEqual(by.get("http_error"), 1)
        self.assertEqual(manifest["summary"]["failed"], 2)

    def test_processed_only_average_ignores_failures(self):
        """Failed cases do not pull the processed score average toward zero —
        they are accounted for via failed/by_status, not via score math."""
        outcomes = iter([
            "ok",
            requests.exceptions.Timeout("to"),
            "ok",
        ])

        def mixed_send(**kwargs):
            nxt = next(outcomes)
            if isinstance(nxt, Exception):
                raise nxt
            return nxt

        manifest, _, _ = _patched_run(_args(runs=1), send_fn=mixed_send)
        self.assertEqual(manifest["summary"]["avg_total_score"], 20.0)


class ArtefactsTests(unittest.TestCase):

    def _ok_send(self, **kwargs):
        return "LLM RESPONSE"

    def test_manifest_and_csv_written_side_by_side(self):
        # _patched_run loads both files from disk while the tmpdir is still
        # live. If loading succeeded (non-empty scoring_rows + manifest_on_disk
        # populated), both artefacts were written. Checking ``.exists()``
        # after the context manager tore the tmpdir down would always fail.
        manifest, manifest_on_disk, scoring_rows = _patched_run(_args(), send_fn=self._ok_send)
        self.assertIn("scoring_csv", manifest["outputs"])
        self.assertIn("manifest", manifest["outputs"])
        # Manifest round-tripped through disk successfully.
        self.assertEqual(manifest_on_disk["kind"], "testcase_benchmark")
        # Scoring CSV header preserved.
        self.assertEqual(len(scoring_rows), 3)
        self.assertEqual(scoring_rows[0]["Model"], "test-model")
        self.assertEqual(scoring_rows[0]["TotalScore"], "20")


class TestcaseLoadFaultToleranceTests(unittest.TestCase):
    """A malformed or missing testcase JSON file must not abort the whole
    run — it should be recorded as `testcase_load_error` and the remaining
    testcases should still execute."""

    def _ok_send(self, **kwargs):
        return "LLM RESPONSE"

    def test_one_malformed_testcase_does_not_abort_run(self):
        # First path raises as if its JSON is invalid; other two load cleanly.
        side_effect = [
            ValueError("malformed JSON at line 3"),
            _fake_testcase("FAKE-002"),
            _fake_testcase("FAKE-003"),
        ]
        manifest, on_disk, scoring_rows = _patched_run(
            _args(runs=1), send_fn=self._ok_send, load_side_effect=side_effect,
        )
        summary = manifest["summary"]
        # Results = 1 load failure + 2 executed successes
        self.assertEqual(summary["total_case_runs"], 3)
        self.assertEqual(summary["processed"], 2)
        self.assertEqual(summary["failed"], 1)
        self.assertEqual(summary["by_status"].get("testcase_load_error"), 1)
        self.assertEqual(summary["by_status"].get("processed"), 2)
        # The scoring CSV still carries the successful cases.
        self.assertEqual(len(scoring_rows), 2)
        self.assertEqual({row["TestID"] for row in scoring_rows},
                         {"FAKE-002", "FAKE-003"})
        # Manifest round-trip preserves the load-failure entry.
        load_entries = [c for c in on_disk["cases"]
                        if c["status"] == "testcase_load_error"]
        self.assertEqual(len(load_entries), 1)

    def test_load_failure_entry_carries_path_and_error_detail(self):
        side_effect = [
            ValueError("malformed JSON"),
            _fake_testcase("FAKE-002"),
            _fake_testcase("FAKE-003"),
        ]
        manifest, _, _ = _patched_run(
            _args(runs=1), send_fn=self._ok_send, load_side_effect=side_effect,
        )
        lf = next(c for c in manifest["cases"] if c["status"] == "testcase_load_error")
        # Path to the bad file must be preserved for debugging (OS-agnostic compare).
        self.assertEqual(Path(lf["path"]), Path(_FAKE_TESTCASE_FILES[0]))
        # Fallback id = filename stem because the real id is unreadable.
        self.assertEqual(lf["testcase_id"], Path(_FAKE_TESTCASE_FILES[0]).stem)
        # Exception detail carried through.
        self.assertIn("ValueError", lf["error"])
        self.assertIn("malformed JSON", lf["error"])
        # Score fields are all None on a load failure.
        self.assertIsNone(lf["total_score"])
        self.assertIsNone(lf["grade"])
        # `run` is None because the failure happened before any run was attempted.
        self.assertIsNone(lf["run"])

    def test_all_testcases_fail_to_load_still_writes_manifest(self):
        side_effect = [
            ValueError("bad-1"),
            FileNotFoundError("bad-2"),
            ValueError("bad-3"),
        ]
        manifest, on_disk, scoring_rows = _patched_run(
            _args(runs=2), send_fn=self._ok_send, load_side_effect=side_effect,
        )
        # All three paths failed -> 3 load-failure entries, 0 executions.
        self.assertEqual(on_disk["summary"]["processed"], 0)
        self.assertEqual(on_disk["summary"]["failed"], 3)
        self.assertEqual(on_disk["summary"]["by_status"].get("testcase_load_error"), 3)
        # All-failed run still produces the manifest + empty scoring sheet.
        self.assertEqual(scoring_rows, [])
        self.assertEqual(on_disk["kind"], "testcase_benchmark")
        # testcase_suite reflects: 3 discovered paths, 0 loaded, 3 load failures.
        suite = on_disk["testcase_suite"]
        self.assertEqual(suite["total_cases"], 0)
        self.assertEqual(suite["discovered_count"], 3)
        self.assertEqual(suite["load_failure_count"], 3)
        # OS-agnostic path comparison.
        self.assertEqual(
            {Path(p) for p in suite["load_failure_paths"]},
            {Path(p) for p in _FAKE_TESTCASE_FILES},
        )

    def test_successfully_loaded_cases_execute_normally_after_earlier_failure(self):
        """Load-failure at position 0 must not block execution at positions 1 and 2,
        including capturing their per-case execution failures too."""
        side_effect = [
            ValueError("malformed-0"),
            _fake_testcase("FAKE-002"),
            _fake_testcase("FAKE-003"),
        ]
        send_calls = {"count": 0}

        def send_with_one_timeout(**kwargs):
            send_calls["count"] += 1
            if send_calls["count"] == 1:
                raise requests.exceptions.Timeout("sim")
            return "LLM RESPONSE"

        manifest, _, _ = _patched_run(
            _args(runs=1), send_fn=send_with_one_timeout,
            load_side_effect=side_effect,
        )
        by = manifest["summary"]["by_status"]
        self.assertEqual(by.get("testcase_load_error"), 1)
        self.assertEqual(by.get("timeout"), 1)
        self.assertEqual(by.get("processed"), 1)
        # 1 load-failure + 2 execution attempts = 3 entries total
        self.assertEqual(manifest["summary"]["total_case_runs"], 3)

    def test_suite_metadata_reports_loaded_vs_discovered_when_partial_failure(self):
        side_effect = [
            _fake_testcase("FAKE-001"),
            ValueError("malformed-1"),
            _fake_testcase("FAKE-003"),
        ]
        manifest, _, _ = _patched_run(
            _args(runs=1), send_fn=self._ok_send, load_side_effect=side_effect,
        )
        suite = manifest["testcase_suite"]
        self.assertEqual(suite["total_cases"], 2)          # loaded
        self.assertEqual(suite["discovered_count"], 3)     # found on disk
        self.assertEqual(suite["load_failure_count"], 1)
        self.assertEqual(
            [Path(p) for p in suite["load_failure_paths"]],
            [Path(_FAKE_TESTCASE_FILES[1])],
        )
        # `testcase_ids` lists only successfully loaded cases (real ids).
        self.assertEqual(suite["testcase_ids"], ["FAKE-001", "FAKE-003"])


class SafeLoadHelperTests(unittest.TestCase):
    """Unit coverage for _safe_load_testcases isolation semantics."""

    def test_splits_loaded_and_failed(self):
        paths = [Path("a.json"), Path("b.json"), Path("c.json")]
        good = {"id": "CASE-A", "artefact_type": "EVTX"}

        def fake_loader(p):
            if str(p) == "b.json":
                raise ValueError("bad schema")
            return good if str(p) == "a.json" else {"id": "CASE-C", "artefact_type": "EVTX"}

        with mock.patch.object(rb, "load_test_case", side_effect=fake_loader):
            loaded, failures = rb._safe_load_testcases(paths)
        self.assertEqual(len(loaded), 2)
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["path"], "b.json")
        self.assertEqual(failures[0]["status"], "testcase_load_error")
        self.assertEqual(failures[0]["testcase_id"], "b")  # filename stem fallback
        self.assertIn("ValueError", failures[0]["error"])


class CorpusScopeTests(unittest.TestCase):
    """Testcase benchmark must stamp a corpus-scope block that flags the
    malicious-only nature of the current suite, parallel to the detection
    HTML's corpus-scope banner."""

    def _ok_send(self, **kwargs):
        return "LLM RESPONSE"

    def test_manifest_includes_corpus_scope_for_malicious_only_suite(self):
        """Default fixture (all 3 cases have expected_findings) = malicious-only."""
        manifest, on_disk, _ = _patched_run(_args(), send_fn=self._ok_send)
        for m in (manifest, on_disk):
            self.assertIn("corpus_scope", m)
            cs = m["corpus_scope"]
            self.assertFalse(cs["has_benign_controls"])
            self.assertEqual(cs["malicious_count"], 3)
            self.assertEqual(cs["benign_count"], 0)
            self.assertIn("malicious-only", cs["note"].lower())
            self.assertIn("false-positive rate", cs["note"].lower())

    def test_corpus_scope_detects_benign_case_via_empty_findings(self):
        """A testcase with empty expected_findings is treated as a benign control."""
        tcs = [
            _fake_testcase("MAL-1"),
            _fake_testcase("BEN-1"),
            _fake_testcase("MAL-2"),
        ]
        tcs[1]["expected_findings"] = []  # make the middle one benign
        manifest, _, _ = _patched_run(
            _args(), send_fn=self._ok_send, load_side_effect=tcs,
        )
        cs = manifest["corpus_scope"]
        self.assertTrue(cs["has_benign_controls"])
        self.assertEqual(cs["benign_count"], 1)
        self.assertEqual(cs["malicious_count"], 2)

    def test_corpus_scope_helper_recognizes_explicit_benign_text(self):
        """Textual benign markers in scenario/notes also count."""
        tc = _fake_testcase("CASE-1")
        tc["notes"] = "This is a benign baseline case; not malicious."
        self.assertTrue(rb._is_benign_testcase(tc))

    def test_corpus_scope_helper_rejects_malicious_default(self):
        self.assertFalse(rb._is_benign_testcase(_fake_testcase("M-1")))


class CanonicalPresetCliTests(unittest.TestCase):
    """CLI-level integration for ``--canonical`` on run_benchmark.py.

    Exercises the preset-application path in ``main()``: arg parsing +
    ``apply_canonical_preset()`` + parser.error on conflicts. We patch
    ``run_benchmark()`` so the test doesn't actually try to execute cases.
    """

    def _invoke_main(self, argv):
        """Drive run_benchmark.py's main() with fabricated argv. Returns
        whatever args run_benchmark() would have been called with (captured
        via a mock), or raises SystemExit on parser.error."""
        captured = {}

        def _capture(args, **kwargs):
            captured["args"] = args
            return {}

        with mock.patch.object(rb, "run_benchmark", side_effect=_capture):
            with mock.patch("sys.argv", ["run_benchmark.py"] + argv):
                rb.main()
        return captured.get("args")

    def test_canonical_fills_in_temperature_and_runs(self):
        args = self._invoke_main(["--model", "m", "--canonical"])
        self.assertEqual(args.temperature, 0.0)
        self.assertEqual(args.runs, 3)

    def test_canonical_rejects_non_zero_temperature(self):
        with self.assertRaises(SystemExit):
            self._invoke_main(
                ["--model", "m", "--canonical", "--temperature", "0.5"],
            )

    def test_canonical_rejects_runs_below_min(self):
        with self.assertRaises(SystemExit):
            self._invoke_main(
                ["--model", "m", "--canonical", "--runs", "1"],
            )

    def test_canonical_accepts_explicit_matching_flags(self):
        args = self._invoke_main(
            ["--model", "m", "--canonical", "--temperature", "0.0", "--runs", "3"],
        )
        self.assertEqual(args.temperature, 0.0)
        self.assertEqual(args.runs, 3)

    def test_non_canonical_invocation_preserves_defaults(self):
        """Without --canonical, temperature stays at 0.1 and runs at 3
        (run_benchmark.py's own defaults). The preset must not run."""
        args = self._invoke_main(["--model", "m"])
        self.assertFalse(getattr(args, "canonical", False))
        # run_benchmark.py's own default for --temperature is 0.1, for --runs is 3.
        self.assertEqual(args.temperature, 0.1)
        self.assertEqual(args.runs, 3)

    def test_canonical_stamps_truthful_contract(self):
        """End-to-end stamp check: the contract built from preset-applied args
        passes canonical shape validation."""
        args = self._invoke_main(["--model", "m", "--canonical"])
        # Simulate the same contract build run_benchmark does internally.
        from forcastl.benchmark_contract import build_contract_metadata
        contract = build_contract_metadata(
            mode="testcases",            # testcase runner's mode label
            sample_size=3,
            max_events=None,
            difficulty=None,
            test_set=None,
            input_format="evtx",
            context_window=None,
            max_tokens=args.max_tokens,
            temperature=args.temperature,
            runs=args.runs,
        )
        # The testcase runner's mode is not "all", so it won't be canonical_valid;
        # but temperature and runs must be truthfully stamped at canonical values.
        self.assertEqual(contract["effective_config"]["temperature"], 0.0)
        self.assertEqual(contract["effective_config"]["runs"], 3)


class ExceptionClassificationTests(unittest.TestCase):

    def test_timeout_classified(self):
        self.assertEqual(
            rb._classify_exception(requests.exceptions.Timeout("t")),
            "timeout",
        )

    def test_http_error_classified(self):
        self.assertEqual(
            rb._classify_exception(requests.exceptions.HTTPError("500")),
            "http_error",
        )

    def test_connection_error_classified_as_http(self):
        self.assertEqual(
            rb._classify_exception(requests.exceptions.ConnectionError("boom")),
            "http_error",
        )

    def test_value_error_classified_as_artefact(self):
        self.assertEqual(
            rb._classify_exception(ValueError("bad artefact")),
            "artefact_error",
        )

    def test_parse_error_classified(self):
        self.assertEqual(
            rb._classify_exception(KeyError("choices")),
            "parse_error",
        )

    def test_unknown_exception_falls_through_to_error(self):
        class Wat(BaseException):
            pass
        self.assertEqual(rb._classify_exception(Wat()), "error")


if __name__ == "__main__":
    unittest.main()
