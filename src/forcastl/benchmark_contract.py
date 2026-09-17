from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional


BENCHMARK_VERSION = "2026.03"
BENCHMARK_MODE = "operational_raw_forensics"
CORPUS_VERSION = "forcastl_evtx_corpus_v1"
PROMPT_VERSION = "simple_malicious_prompt_v1"
PARSER_VERSION = "evtx_parser_v1"
# Frozen scoring contract (v1). A change to the scoring math must bump
# SCORING_VERSION; runs scored under different SCORING_VERSION values are not comparable.
# Behavior: alignment scores the 6 evidence fields only (verdict not
# double-counted in Extraction + Interpretation); the testcase trap penalty
# scales with traps hit; "expected" is the FULL forensic inventory present in
# the artifact (the `attack_*` curated-subset precedence is retired from
# scoring — models get recall credit for any real value they report).
SCORING_VERSION = "forcastl_scoring_20pt_v1"

RUN_TIER_SCREENING_SIMPLE = "screening_simple"
RUN_TIER_SCREENING_STANDARD = "screening_standard"
RUN_TIER_BENCHMARK_CANONICAL = "benchmark_canonical"

# Canonical validity requires the run to have processed at least this percentage
# of selected files. A run where 50% of files errored is not a canonical benchmark
# even if the contract shape is right.
CANONICAL_PROCESSED_COVERAGE_THRESHOLD = 95.0

# Canonical validity requires deterministic sampling and repeated runs.
CANONICAL_REQUIRED_TEMPERATURE = 0.0
CANONICAL_MIN_RUNS = 3

CANONICAL_COMPARISON_BASIS = {
    "mode": "all",
    "sample_size": None,
    "max_events": None,
    "difficulty_filter": None,
    "test_set_filter": None,
    "input_format": "csv",
}


def classify_run_tier(
    *,
    mode: Optional[str],
    sample_size: Optional[int],
    max_events: Optional[int],
    difficulty: Optional[str],
    test_set: Optional[str],
    input_format: Optional[str],
) -> str:
    if (
        mode == "all"
        and not max_events
        and not difficulty
        and not test_set
        and (input_format or "csv") == "csv"
    ):
        return RUN_TIER_BENCHMARK_CANONICAL

    if mode == "sample" and max_events and max_events <= 10 and (sample_size or 0) <= 5:
        return RUN_TIER_SCREENING_SIMPLE

    return RUN_TIER_SCREENING_STANDARD


def build_contract_metadata(
    *,
    mode: Optional[str],
    sample_size: Optional[int],
    max_events: Optional[int],
    difficulty: Optional[str],
    test_set: Optional[str],
    input_format: Optional[str],
    context_window: Optional[int],
    max_tokens: Optional[int],
    temperature: Optional[float] = None,
    runs: Optional[int] = None,
) -> Dict[str, Any]:
    run_tier = classify_run_tier(
        mode=mode,
        sample_size=sample_size,
        max_events=max_events,
        difficulty=difficulty,
        test_set=test_set,
        input_format=input_format,
    )

    return {
        "benchmark_version": BENCHMARK_VERSION,
        "benchmark_mode": BENCHMARK_MODE,
        "corpus_version": CORPUS_VERSION,
        "prompt_version": PROMPT_VERSION,
        "parser_version": PARSER_VERSION,
        "scoring_version": SCORING_VERSION,
        "run_tier": run_tier,
        "canonical_comparison": run_tier == RUN_TIER_BENCHMARK_CANONICAL,
        "effective_config": {
            "mode": mode,
            "sample_size": sample_size,
            "max_events": max_events,
            "difficulty_filter": difficulty,
            "test_set_filter": test_set,
            "input_format": input_format,
            "context_window": context_window,
            "max_output_tokens": max_tokens,
            "temperature": temperature,
            "runs": runs,
        },
        "canonical_comparison_basis": CANONICAL_COMPARISON_BASIS,
    }


def validate_canonical(
    contract: Dict[str, Any],
    *,
    processed_coverage_pct: Optional[float] = None,
    observed_truncation_count: int = 0,
    coverage_threshold: float = CANONICAL_PROCESSED_COVERAGE_THRESHOLD,
) -> Dict[str, Any]:
    """Evaluate whether a run actually satisfies canonical benchmark rules.

    Returns a dict with:
      - canonical_candidate (bool): run_tier == benchmark_canonical (shape-only).
      - canonical_valid (bool): all canonical rules satisfied.
      - canonical_violations (list[str]): specific, user-readable reasons.
      - processed_coverage_pct (float | None): echoed back for transparency.
      - processed_coverage_threshold (float): the threshold used.
      - observed_truncation_count (int): number of artefacts truncated at runtime.

    A run is only `canonical_valid=True` if:
      - run_tier is benchmark_canonical (shape-only classification)
      - mode == "all", input_format == "csv"
      - max_events is None, no difficulty filter, no test-set filter
      - temperature == 0.0
      - runs >= CANONICAL_MIN_RUNS
      - observed_truncation_count == 0
      - processed_coverage_pct >= coverage_threshold
    """
    effective = (contract or {}).get("effective_config") or {}
    run_tier = (contract or {}).get("run_tier")
    candidate = run_tier == RUN_TIER_BENCHMARK_CANONICAL

    violations: List[str] = []

    if not candidate:
        violations.append(f"run_tier is {run_tier!r}, not {RUN_TIER_BENCHMARK_CANONICAL!r}")

    mode = effective.get("mode")
    if mode != "all":
        violations.append(f"mode is {mode!r}, canonical requires 'all'")

    input_format = (effective.get("input_format") or "").lower()
    if input_format != "csv":
        violations.append(f"input_format is {effective.get('input_format')!r}, canonical requires 'csv'")

    if effective.get("max_events") is not None:
        violations.append(f"max_events={effective.get('max_events')} configured, canonical requires unset")

    if effective.get("difficulty_filter"):
        violations.append(f"difficulty_filter={effective.get('difficulty_filter')!r} set, canonical requires no filter")

    if effective.get("test_set_filter"):
        violations.append(f"test_set_filter={effective.get('test_set_filter')!r} set, canonical requires no filter")

    temperature = effective.get("temperature")
    if temperature is None or float(temperature) != CANONICAL_REQUIRED_TEMPERATURE:
        violations.append(
            f"temperature={temperature!r}, canonical requires exactly {CANONICAL_REQUIRED_TEMPERATURE}"
        )

    runs_val = effective.get("runs")
    if runs_val is None or int(runs_val) < CANONICAL_MIN_RUNS:
        violations.append(
            f"runs={runs_val!r}, canonical requires >= {CANONICAL_MIN_RUNS}"
        )

    if observed_truncation_count and observed_truncation_count > 0:
        violations.append(
            f"{observed_truncation_count} artefact(s) truncated at runtime; canonical requires none"
        )

    coverage_violated = (
        processed_coverage_pct is None
        or processed_coverage_pct < coverage_threshold
    )
    if coverage_violated:
        shown = "unknown" if processed_coverage_pct is None else f"{processed_coverage_pct:.1f}%"
        violations.append(
            f"processed coverage {shown} below canonical threshold of {coverage_threshold:.1f}%"
        )

    return {
        "canonical_candidate": candidate,
        "canonical_valid": not violations,
        "canonical_violations": violations,
        "processed_coverage_pct": processed_coverage_pct,
        "processed_coverage_threshold": coverage_threshold,
        "observed_truncation_count": observed_truncation_count,
    }


def is_canonical_facing(canonical_validity: Optional[Dict[str, Any]]) -> bool:
    """Single source of truth for "should the report be laid out as a
    benchmark record?".

    True when the run is either canonical-valid or a canonical-candidate
    (shape is canonical even if runtime-only rules fail). False for
    screening runs — those keep their existing layout.
    """
    if not canonical_validity:
        return False
    return bool(canonical_validity.get("canonical_candidate"))


# CLI rules that must hold for a canonical benchmark run. Pairs of
# (cli_flag, args_attr, required_value, display_text). `None` for a required
# value means the flag must be unset / its argparse-default.
CANONICAL_CLI_SELECTION_RULES: List = [
    ("--mode", "mode", "all", "all"),
    ("--input-format", "input_format", "csv", "csv"),
    ("--max-events", "max_events", None, "<unset>"),
    ("--difficulty", "difficulty", None, "<unset>"),
    ("--test-set", "test_set", None, "<unset>"),
]


def _flag_on_cli(flag: str, argv: Optional[List[str]]) -> bool:
    """True iff ``flag`` appears as a literal argv element.

    Matches ``--flag`` (value follows in next argv slot) and ``--flag=VALUE``.
    Checked against real argv rather than `args`-attribute equality because
    argparse defaults are indistinguishable from an explicit user match.
    """
    if not argv:
        return False
    return any(a == flag or a.startswith(flag + "=") for a in argv)


def apply_canonical_preset(
    args,
    argv: Optional[List[str]],
    *,
    selection_flags: Optional[Iterable[str]] = None,
) -> "CanonicalPresetOutcome":
    """Apply the canonical-benchmark preset to parsed ``args`` in place.

    The preset always enforces:

      - ``temperature == CANONICAL_REQUIRED_TEMPERATURE`` (0.0)
      - ``runs >= CANONICAL_MIN_RUNS`` (3)

    Selection rules (``--mode``, ``--input-format``, ``--max-events``,
    ``--difficulty``, ``--test-set``) are applied *only* for the flags the
    calling CLI actually exposes. Callers declare their supported subset via
    ``selection_flags``:

      - ``None`` (default) — apply every rule in ``CANONICAL_CLI_SELECTION_RULES``.
        Suitable for detection, which exposes every selection flag.
      - An explicit iterable of flag strings (e.g.
        ``["--mode", "--max-events", "--difficulty", "--test-set"]``) — apply
        only those rules. Used by multi-model comparison, which pins input
        format to ``csv`` at the contract level and has no CLI flag for it.
      - ``[]`` — apply no selection rules. Used by the testcase benchmark,
        which scopes its suite via ``--testcases`` globs.

    For flags the user did NOT pass on the command line, the preset sets the
    canonical value. For flags the user DID pass with a conflicting value, a
    conflict is recorded so the caller can reject the run. Silent override is
    deliberately not used — canonical benchmarks must be intentional, so a
    conflicting flag indicates a real misconfiguration.

    Raises ``ValueError`` if ``selection_flags`` contains an unknown flag
    name, to catch caller typos at import time rather than silently dropping
    rules.

    Returns a small outcome dict: ``applied`` lists flags the preset filled
    in, ``conflicts`` lists human-readable violation messages. The caller
    should surface applied flags on stdout and, if conflicts is non-empty,
    error out via ``argparse.ArgumentParser.error``.
    """
    applied: List[str] = []
    conflicts: List[str] = []

    if selection_flags is None:
        rules = list(CANONICAL_CLI_SELECTION_RULES)
    else:
        allowed = set(selection_flags)
        known = {rule[0] for rule in CANONICAL_CLI_SELECTION_RULES}
        unknown = allowed - known
        if unknown:
            raise ValueError(
                f"apply_canonical_preset: unknown selection_flags "
                f"{sorted(unknown)!r}. Valid flags: {sorted(known)!r}"
            )
        rules = [rule for rule in CANONICAL_CLI_SELECTION_RULES if rule[0] in allowed]

    for flag, attr, required, display in rules:
        if _flag_on_cli(flag, argv):
            cur = getattr(args, attr, None)
            if cur != required:
                conflicts.append(f"--canonical requires {flag}={display}, got {cur!r}")
        else:
            setattr(args, attr, required)
            applied.append(f"{flag}={display}")

    # Temperature: exactly 0.0
    if _flag_on_cli("--temperature", argv):
        if getattr(args, "temperature", None) != CANONICAL_REQUIRED_TEMPERATURE:
            conflicts.append(
                f"--canonical requires --temperature={CANONICAL_REQUIRED_TEMPERATURE}, "
                f"got {getattr(args, 'temperature', None)!r}"
            )
    else:
        args.temperature = CANONICAL_REQUIRED_TEMPERATURE
        applied.append(f"--temperature={CANONICAL_REQUIRED_TEMPERATURE}")

    # Runs: >= CANONICAL_MIN_RUNS
    if _flag_on_cli("--runs", argv):
        runs = getattr(args, "runs", 1) or 0
        if runs < CANONICAL_MIN_RUNS:
            conflicts.append(
                f"--canonical requires --runs >= {CANONICAL_MIN_RUNS}, got {runs}"
            )
    else:
        args.runs = CANONICAL_MIN_RUNS
        applied.append(f"--runs={CANONICAL_MIN_RUNS}")

    return CanonicalPresetOutcome(applied=applied, conflicts=conflicts)


class CanonicalPresetOutcome:
    """Tiny immutable result type; avoids a bare tuple at call sites."""

    __slots__ = ("applied", "conflicts")

    def __init__(self, *, applied: List[str], conflicts: List[str]):
        self.applied = applied
        self.conflicts = conflicts

    def __repr__(self) -> str:
        return f"CanonicalPresetOutcome(applied={self.applied!r}, conflicts={self.conflicts!r})"


def contract_metadata_lines(contract: Dict[str, Any]) -> list[str]:
    effective = contract.get("effective_config", {})
    return [
        f"Benchmark Version: {contract.get('benchmark_version', 'unknown')}",
        f"Benchmark Mode: {contract.get('benchmark_mode', 'unknown')}",
        f"Run Tier: {contract.get('run_tier', 'unknown')}",
        f"Corpus Version: {contract.get('corpus_version', 'unknown')}",
        f"Prompt Version: {contract.get('prompt_version', 'unknown')}",
        f"Parser Version: {contract.get('parser_version', 'unknown')}",
        f"Scoring Version: {contract.get('scoring_version', 'unknown')}",
        f"Canonical Comparison: {'yes' if contract.get('canonical_comparison') else 'no'}",
        f"Input Format: {effective.get('input_format') or 'unknown'}",
        f"Mode: {effective.get('mode') or 'unknown'}",
        f"Sample Size: {effective.get('sample_size') if effective.get('sample_size') is not None else 'n/a'}",
        f"Max Events: {effective.get('max_events') if effective.get('max_events') is not None else 'n/a'}",
        f"Difficulty Filter: {effective.get('difficulty_filter') or 'none'}",
        f"Test Set Filter: {effective.get('test_set_filter') or 'none'}",
        f"Context Window: {effective.get('context_window') if effective.get('context_window') is not None else 'n/a'}",
        f"Max Output Tokens: {effective.get('max_output_tokens') if effective.get('max_output_tokens') is not None else 'n/a'}",
        f"Temperature: {effective.get('temperature') if effective.get('temperature') is not None else 'n/a'}",
        f"Runs: {effective.get('runs') if effective.get('runs') is not None else 'n/a'}",
    ]
