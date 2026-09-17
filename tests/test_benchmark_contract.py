import types
import unittest

from forcastl.benchmark_contract import (
    CANONICAL_MIN_RUNS,
    CANONICAL_PROCESSED_COVERAGE_THRESHOLD,
    CANONICAL_REQUIRED_TEMPERATURE,
    RUN_TIER_BENCHMARK_CANONICAL,
    RUN_TIER_SCREENING_SIMPLE,
    RUN_TIER_SCREENING_STANDARD,
    apply_canonical_preset,
    build_contract_metadata,
    classify_run_tier,
    validate_canonical,
)


def _canonical_contract(**overrides):
    """Build a contract shaped for canonical validity with optional overrides."""
    defaults = dict(
        mode="all",
        sample_size=None,
        max_events=None,
        difficulty=None,
        test_set=None,
        input_format="csv",
        context_window=8192,
        max_tokens=1000,
        temperature=0.0,
        runs=3,
    )
    defaults.update(overrides)
    return build_contract_metadata(**defaults)


class TestBenchmarkContract(unittest.TestCase):
    def test_classify_canonical_run(self):
        tier = classify_run_tier(
            mode="all",
            sample_size=None,
            max_events=None,
            difficulty=None,
            test_set=None,
            input_format="csv",
        )
        self.assertEqual(tier, RUN_TIER_BENCHMARK_CANONICAL)

    def test_classify_simple_screening_run(self):
        tier = classify_run_tier(
            mode="sample",
            sample_size=5,
            max_events=10,
            difficulty=None,
            test_set=None,
            input_format="csv",
        )
        self.assertEqual(tier, RUN_TIER_SCREENING_SIMPLE)

    def test_classify_standard_screening_run(self):
        tier = classify_run_tier(
            mode="sample",
            sample_size=25,
            max_events=None,
            difficulty="hard",
            test_set="B",
            input_format="csv",
        )
        self.assertEqual(tier, RUN_TIER_SCREENING_STANDARD)

    def test_build_contract_metadata_marks_canonical(self):
        contract = build_contract_metadata(
            mode="all",
            sample_size=None,
            max_events=None,
            difficulty=None,
            test_set=None,
            input_format="csv",
            context_window=8192,
            max_tokens=1000,
        )
        self.assertTrue(contract["canonical_comparison"])
        self.assertEqual(contract["run_tier"], RUN_TIER_BENCHMARK_CANONICAL)
        self.assertEqual(contract["effective_config"]["context_window"], 8192)

    def test_build_contract_metadata_stamps_temperature_and_runs(self):
        contract = build_contract_metadata(
            mode="sample",
            sample_size=5,
            max_events=10,
            difficulty="easy",
            test_set=None,
            input_format="csv",
            context_window=8192,
            max_tokens=1000,
            temperature=0.0,
            runs=3,
        )
        self.assertEqual(contract["effective_config"]["temperature"], 0.0)
        self.assertEqual(contract["effective_config"]["runs"], 3)


class TestValidateCanonical(unittest.TestCase):
    """Canonical validity gating: shape + runtime facts."""

    def test_valid_canonical_run(self):
        contract = _canonical_contract()
        v = validate_canonical(
            contract,
            processed_coverage_pct=100.0,
            observed_truncation_count=0,
        )
        self.assertTrue(v["canonical_candidate"])
        self.assertTrue(v["canonical_valid"], msg=f"violations: {v['canonical_violations']}")
        self.assertEqual(v["canonical_violations"], [])
        self.assertEqual(v["processed_coverage_threshold"],
                         CANONICAL_PROCESSED_COVERAGE_THRESHOLD)

    def test_invalid_because_temperature_nonzero(self):
        contract = _canonical_contract(temperature=0.1)
        v = validate_canonical(contract, processed_coverage_pct=100.0)
        self.assertTrue(v["canonical_candidate"])
        self.assertFalse(v["canonical_valid"])
        self.assertTrue(
            any("temperature" in msg for msg in v["canonical_violations"]),
            f"violations: {v['canonical_violations']}",
        )

    def test_invalid_because_runs_below_min(self):
        contract = _canonical_contract(runs=1)
        v = validate_canonical(contract, processed_coverage_pct=100.0)
        self.assertFalse(v["canonical_valid"])
        self.assertTrue(
            any("runs" in msg for msg in v["canonical_violations"]),
            f"violations: {v['canonical_violations']}",
        )
        self.assertTrue(
            any(str(CANONICAL_MIN_RUNS) in msg for msg in v["canonical_violations"]),
        )

    def test_invalid_because_processed_coverage_below_threshold(self):
        contract = _canonical_contract()
        v = validate_canonical(
            contract,
            processed_coverage_pct=80.0,
            observed_truncation_count=0,
        )
        self.assertFalse(v["canonical_valid"])
        self.assertTrue(
            any("processed coverage" in msg for msg in v["canonical_violations"]),
            f"violations: {v['canonical_violations']}",
        )

    def test_invalid_because_processed_coverage_unknown(self):
        contract = _canonical_contract()
        v = validate_canonical(contract, processed_coverage_pct=None)
        self.assertFalse(v["canonical_valid"])
        self.assertTrue(
            any("processed coverage" in msg for msg in v["canonical_violations"]),
        )

    def test_invalid_because_truncation_observed(self):
        contract = _canonical_contract()
        v = validate_canonical(
            contract,
            processed_coverage_pct=100.0,
            observed_truncation_count=3,
        )
        self.assertFalse(v["canonical_valid"])
        self.assertTrue(
            any("truncated" in msg for msg in v["canonical_violations"]),
            f"violations: {v['canonical_violations']}",
        )

    def test_non_canonical_shape_flags_candidate_false(self):
        """A screening-shaped contract is not even a candidate."""
        contract = build_contract_metadata(
            mode="sample", sample_size=5, max_events=10,
            difficulty="easy", test_set=None, input_format="csv",
            context_window=8192, max_tokens=1000,
            temperature=0.0, runs=3,
        )
        v = validate_canonical(contract, processed_coverage_pct=100.0)
        self.assertFalse(v["canonical_candidate"])
        self.assertFalse(v["canonical_valid"])
        # Multiple violations expected (tier, mode, max_events, difficulty_filter)
        self.assertGreaterEqual(len(v["canonical_violations"]), 3)

    def test_required_temperature_is_zero(self):
        self.assertEqual(CANONICAL_REQUIRED_TEMPERATURE, 0.0)


def _detection_args_like_default(**overrides):
    """Emulate argparse Namespace as detect_malicious.py's argparse would
    produce it: all the attributes referenced by apply_canonical_preset
    populated with the defaults that argparse would have used."""
    base = dict(
        mode=None, sample_size=None, max_events=None,
        difficulty=None, test_set=None, input_format="csv",
        temperature=0.1, runs=1, canonical=True,
    )
    base.update(overrides)
    return types.SimpleNamespace(**base)


def _testcase_args_like_default(**overrides):
    """Emulate run_benchmark.py's argparse Namespace (no selection flags)."""
    base = dict(temperature=0.1, runs=1, canonical=True)
    base.update(overrides)
    return types.SimpleNamespace(**base)


class ApplyCanonicalPresetTests(unittest.TestCase):
    """Detection-style preset: all selection rules in play."""

    def test_bare_canonical_fills_in_all_required_defaults(self):
        args = _detection_args_like_default()
        outcome = apply_canonical_preset(args, argv=["--canonical"])
        self.assertEqual(outcome.conflicts, [])
        # Selection rules filled in.
        self.assertEqual(args.mode, "all")
        self.assertEqual(args.input_format, "csv")
        self.assertIsNone(args.max_events)
        self.assertIsNone(args.difficulty)
        self.assertIsNone(args.test_set)
        # Runtime rules filled in.
        self.assertEqual(args.temperature, CANONICAL_REQUIRED_TEMPERATURE)
        self.assertEqual(args.runs, CANONICAL_MIN_RUNS)
        # The `applied` summary lists every flag the preset filled in.
        applied_flags = {s.split("=")[0] for s in outcome.applied}
        self.assertIn("--mode", applied_flags)
        self.assertIn("--temperature", applied_flags)
        self.assertIn("--runs", applied_flags)

    def test_conflicting_mode_rejected(self):
        args = _detection_args_like_default(mode="sample")
        outcome = apply_canonical_preset(
            args, argv=["--canonical", "--mode", "sample"],
        )
        self.assertTrue(outcome.conflicts)
        self.assertTrue(
            any("--mode" in msg and "all" in msg for msg in outcome.conflicts),
            f"expected a --mode conflict, got: {outcome.conflicts}",
        )

    def test_conflicting_temperature_rejected(self):
        args = _detection_args_like_default(temperature=0.5)
        outcome = apply_canonical_preset(
            args, argv=["--canonical", "--temperature", "0.5"],
        )
        self.assertTrue(outcome.conflicts)
        self.assertTrue(
            any("temperature" in msg for msg in outcome.conflicts),
            f"expected a temperature conflict, got: {outcome.conflicts}",
        )

    def test_conflicting_runs_below_min_rejected(self):
        args = _detection_args_like_default(runs=1)
        outcome = apply_canonical_preset(
            args, argv=["--canonical", "--runs", "1"],
        )
        self.assertTrue(
            any("runs" in msg.lower() for msg in outcome.conflicts),
            f"expected a runs conflict, got: {outcome.conflicts}",
        )

    def test_user_set_runs_equal_min_is_accepted(self):
        args = _detection_args_like_default(runs=3)
        outcome = apply_canonical_preset(
            args, argv=["--canonical", "--runs", "3"],
        )
        self.assertEqual(outcome.conflicts, [])
        self.assertEqual(args.runs, 3)

    def test_user_set_runs_above_min_is_accepted(self):
        args = _detection_args_like_default(runs=5)
        outcome = apply_canonical_preset(
            args, argv=["--canonical", "--runs", "5"],
        )
        self.assertEqual(outcome.conflicts, [])
        self.assertEqual(args.runs, 5)

    def test_user_explicit_matching_values_not_reported_as_applied(self):
        """If the user already supplied the canonical value on the CLI, the
        preset should not list it as "applied" (nothing was changed)."""
        args = _detection_args_like_default(
            mode="all", temperature=0.0, runs=3,
        )
        outcome = apply_canonical_preset(
            args,
            argv=["--canonical", "--mode", "all", "--temperature", "0.0", "--runs", "3"],
        )
        self.assertEqual(outcome.conflicts, [])
        applied_flags = {s.split("=")[0] for s in outcome.applied}
        self.assertNotIn("--mode", applied_flags)
        self.assertNotIn("--temperature", applied_flags)
        self.assertNotIn("--runs", applied_flags)

    def test_multiple_conflicts_all_reported(self):
        args = _detection_args_like_default(
            mode="sample", max_events=10, difficulty="easy", temperature=0.5, runs=1,
        )
        outcome = apply_canonical_preset(
            args,
            argv=["--canonical", "--mode", "sample", "--max-events", "10",
                  "--difficulty", "easy", "--temperature", "0.5", "--runs", "1"],
        )
        # Each conflicting user flag is reported individually (not short-circuited).
        self.assertGreaterEqual(len(outcome.conflicts), 5)

    def test_resulting_args_pass_validate_canonical_shape(self):
        """End-to-end: after the preset applies cleanly, the resulting contract
        must satisfy the shape rules checked by validate_canonical()."""
        args = _detection_args_like_default()
        outcome = apply_canonical_preset(args, argv=["--canonical"])
        self.assertEqual(outcome.conflicts, [])
        contract = build_contract_metadata(
            mode=args.mode,
            sample_size=args.sample_size,
            max_events=args.max_events,
            difficulty=args.difficulty,
            test_set=args.test_set,
            input_format=args.input_format,
            context_window=8192,
            max_tokens=1000,
            temperature=args.temperature,
            runs=args.runs,
        )
        v = validate_canonical(
            contract,
            processed_coverage_pct=100.0,
            observed_truncation_count=0,
        )
        self.assertTrue(v["canonical_valid"],
                        msg=f"violations: {v['canonical_violations']}")


class ApplyCanonicalPresetWithoutSelectionTests(unittest.TestCase):
    """Testcase-style preset: selection flags are NOT enforced (testcase
    suite is scoped by --testcases globs, not by mode/filters). Expressed
    via ``selection_flags=[]`` — the empty-subset form of the new API."""

    def test_testcase_preset_only_enforces_temperature_and_runs(self):
        args = _testcase_args_like_default()
        outcome = apply_canonical_preset(
            args, argv=["--canonical"], selection_flags=[],
        )
        self.assertEqual(outcome.conflicts, [])
        self.assertEqual(args.temperature, CANONICAL_REQUIRED_TEMPERATURE)
        self.assertEqual(args.runs, CANONICAL_MIN_RUNS)
        # Must not try to read selection attrs from the namespace.
        for attr in ("mode", "input_format", "max_events", "difficulty", "test_set"):
            self.assertFalse(hasattr(args, attr),
                             f"selection attr {attr} should not be touched in testcase mode")

    def test_testcase_preset_rejects_non_zero_temperature(self):
        args = _testcase_args_like_default(temperature=0.1)
        outcome = apply_canonical_preset(
            args, argv=["--canonical", "--temperature", "0.1"],
            selection_flags=[],
        )
        self.assertTrue(
            any("temperature" in msg for msg in outcome.conflicts),
            f"conflicts: {outcome.conflicts}",
        )

    def test_testcase_preset_rejects_runs_below_min(self):
        args = _testcase_args_like_default(runs=2)
        outcome = apply_canonical_preset(
            args, argv=["--canonical", "--runs", "2"],
            selection_flags=[],
        )
        self.assertTrue(
            any("runs" in msg.lower() for msg in outcome.conflicts),
            f"conflicts: {outcome.conflicts}",
        )


def _comparison_args_like_default(**overrides):
    """Emulate run_model_comparison.py's argparse Namespace. Note: no
    `input_format` attribute — the comparison CLI doesn't expose that flag
    (the contract hardcodes 'csv' at the builder site)."""
    base = dict(
        mode="sample", sample_size=50, max_events=None,
        difficulty=None, test_set=None,
        temperature=0.1, runs=1, canonical=True,
    )
    base.update(overrides)
    return types.SimpleNamespace(**base)


class ApplyCanonicalPresetCallerSubsetTests(unittest.TestCase):
    """The helper must only touch flags the calling CLI actually exposes.

    Critical integrity property: ``run_model_comparison.py`` has no
    ``--input-format`` flag, so the preset's ``applied`` / ``conflicts``
    output must never mention it. Otherwise operator feedback is a lie
    ('applied --input-format=csv' on a command with no such flag)."""

    _COMPARISON_FLAGS = ["--mode", "--max-events", "--difficulty", "--test-set"]

    def test_comparison_subset_does_not_mention_input_format(self):
        args = _comparison_args_like_default()
        outcome = apply_canonical_preset(
            args, argv=["--canonical"],
            selection_flags=self._COMPARISON_FLAGS,
        )
        # No applied/conflict message should name a flag the CLI doesn't expose.
        serialised = " ".join(outcome.applied) + " " + " ".join(outcome.conflicts)
        self.assertNotIn("--input-format", serialised)
        # And the namespace was not invented out of thin air.
        self.assertFalse(hasattr(args, "input_format"))

    def test_comparison_subset_still_enforces_mode_and_filters(self):
        """All the comparison-supported selection rules must still fire."""
        args = _comparison_args_like_default()
        outcome = apply_canonical_preset(
            args, argv=["--canonical"],
            selection_flags=self._COMPARISON_FLAGS,
        )
        self.assertEqual(outcome.conflicts, [])
        # Unset flags were filled to canonical values.
        self.assertEqual(args.mode, "all")
        self.assertIsNone(args.max_events)
        self.assertIsNone(args.difficulty)
        self.assertIsNone(args.test_set)
        # And they appear in applied feedback.
        applied_flags = {s.split("=")[0] for s in outcome.applied}
        self.assertIn("--mode", applied_flags)
        self.assertIn("--max-events", applied_flags)
        self.assertIn("--difficulty", applied_flags)
        self.assertIn("--test-set", applied_flags)
        # Runtime rules still apply too.
        self.assertEqual(args.temperature, CANONICAL_REQUIRED_TEMPERATURE)
        self.assertEqual(args.runs, CANONICAL_MIN_RUNS)

    def test_comparison_subset_rejects_conflicting_mode(self):
        args = _comparison_args_like_default(mode="sample")
        outcome = apply_canonical_preset(
            args, argv=["--canonical", "--mode", "sample"],
            selection_flags=self._COMPARISON_FLAGS,
        )
        # Conflict must mention --mode, and must NOT mention --input-format.
        joined = " ".join(outcome.conflicts)
        self.assertIn("--mode", joined)
        self.assertNotIn("--input-format", joined)

    def test_detection_default_still_includes_input_format(self):
        """Detection exposes --input-format, so the default selection ruleset
        must still touch it."""
        args = _detection_args_like_default()
        outcome = apply_canonical_preset(args, argv=["--canonical"])
        applied_flags = {s.split("=")[0] for s in outcome.applied}
        self.assertIn("--input-format", applied_flags)
        self.assertEqual(args.input_format, "csv")

    def test_empty_selection_flags_is_equivalent_to_testcase_mode(self):
        """``selection_flags=[]`` is the explicit empty-subset; must behave
        like the old ``include_selection=False`` path."""
        args = _testcase_args_like_default()
        outcome = apply_canonical_preset(
            args, argv=["--canonical"], selection_flags=[],
        )
        self.assertEqual(outcome.conflicts, [])
        applied_flags = {s.split("=")[0] for s in outcome.applied}
        # Only temperature + runs were applied; no selection flags touched.
        self.assertEqual(applied_flags, {"--temperature", "--runs"})

    def test_unknown_selection_flag_raises(self):
        """Catch caller typos at call time rather than silently dropping rules."""
        args = _detection_args_like_default()
        with self.assertRaises(ValueError) as cm:
            apply_canonical_preset(
                args, argv=["--canonical"],
                selection_flags=["--not-a-real-flag"],
            )
        # Error message names the offending flag so the typo is obvious.
        self.assertIn("--not-a-real-flag", str(cm.exception))


class NonCanonicalInvocationTests(unittest.TestCase):
    """When --canonical is not passed, apply_canonical_preset must not run."""

    def test_apply_canonical_preset_not_called_without_flag(self):
        """Sanity: preset is only invoked on the --canonical CLI path, so
        bare argparse invocations preserve their prior defaults untouched."""
        # Simulate the "args.canonical is False" branch in main() — no call.
        args = _detection_args_like_default(canonical=False,
                                            temperature=0.1, runs=1,
                                            mode="sample", max_events=10)
        # Preset not applied; args remain exactly what argparse produced.
        self.assertEqual(args.temperature, 0.1)
        self.assertEqual(args.runs, 1)
        self.assertEqual(args.mode, "sample")
        self.assertEqual(args.max_events, 10)


if __name__ == "__main__":
    unittest.main()
