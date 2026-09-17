"""Threshold-matrix tests for `core.verdict.compute_verdict`.

These tests pin the verdict semantics so future tuning of thresholds (or
adding a fourth driver) is intentional. The matrix covers every transition
boundary the user-facing report can hit.

Default thresholds (from config.VERDICT_THRESHOLDS):
  recall:        pass≥90, fail<60
  fp_rate:       pass≤10, fail>50
  hallucination: pass≤10, fail>40
"""

from forcastl.core.verdict import compute_verdict


# ── Clean-tier cases ─────────────────────────────────────────────────────────

def test_clean_pass():
    """All three drivers in the PASS range → tier=pass."""
    v = compute_verdict(
        recall_pct=95.0, fp_rate_pct=5.0, hallucination_pct=8.0,
        has_benign_samples=True,
    )
    assert v["tier"] == "pass"
    assert v["has_benign"] is True
    # Every reason should mention "within PASS range"
    assert all("within PASS range" in r for r in v["reasons"])


def test_partial_pass_no_benign():
    """No benign samples — fp rate is skipped, but recall + hallucination both
    pass, so verdict can still be PASS with a caveat appended."""
    v = compute_verdict(
        recall_pct=92.0, fp_rate_pct=None, hallucination_pct=5.0,
        has_benign_samples=False,
    )
    assert v["tier"] == "pass"
    assert any("FP rate not measured" in r for r in v["reasons"])
    assert v["has_benign"] is False


# ── Single-driver caution cases ───────────────────────────────────────────────

def test_caution_by_recall():
    """Recall in caution band (between fail-bound and pass-bound) → CAUTION."""
    v = compute_verdict(
        recall_pct=75.0, fp_rate_pct=5.0, hallucination_pct=5.0,
        has_benign_samples=True,
    )
    assert v["tier"] == "caution"
    # The caution reason should reference the PASS threshold the recall fell short of
    assert any("Detection rate 75.0% below PASS threshold" in r for r in v["reasons"])


def test_caution_by_fp_rate():
    v = compute_verdict(
        recall_pct=95.0, fp_rate_pct=25.0, hallucination_pct=5.0,
        has_benign_samples=True,
    )
    assert v["tier"] == "caution"
    assert any("FP rate 25.0% exceeds PASS threshold" in r for r in v["reasons"])


def test_caution_by_hallucination():
    v = compute_verdict(
        recall_pct=95.0, fp_rate_pct=5.0, hallucination_pct=25.0,
        has_benign_samples=True,
    )
    assert v["tier"] == "caution"
    assert any("Hallucination 25.0% exceeds PASS threshold" in r for r in v["reasons"])


# ── Single-driver fail cases ──────────────────────────────────────────────────

def test_fail_by_recall():
    v = compute_verdict(
        recall_pct=50.0, fp_rate_pct=5.0, hallucination_pct=5.0,
        has_benign_samples=True,
    )
    assert v["tier"] == "fail"
    assert any("Detection rate 50.0% below FAIL threshold" in r for r in v["reasons"])


def test_fail_by_fp_rate():
    v = compute_verdict(
        recall_pct=95.0, fp_rate_pct=80.0, hallucination_pct=5.0,
        has_benign_samples=True,
    )
    assert v["tier"] == "fail"
    assert any("FP rate 80.0% exceeds FAIL threshold" in r for r in v["reasons"])


def test_fail_by_hallucination():
    v = compute_verdict(
        recall_pct=95.0, fp_rate_pct=5.0, hallucination_pct=60.0,
        has_benign_samples=True,
    )
    assert v["tier"] == "fail"
    assert any("Hallucination 60.0% exceeds FAIL threshold" in r for r in v["reasons"])


# ── Worst-driver-wins ─────────────────────────────────────────────────────────

def test_fail_takes_worst_driver():
    """If one driver fails and one is just caution, tier is FAIL."""
    v = compute_verdict(
        recall_pct=50.0,        # FAIL
        fp_rate_pct=25.0,       # caution
        hallucination_pct=5.0,  # PASS
        has_benign_samples=True,
    )
    assert v["tier"] == "fail"
    # All three reasons should be present so the analyst sees full rationale
    assert len(v["reasons"]) == 3


def test_multi_driver_fail():
    v = compute_verdict(
        recall_pct=40.0, fp_rate_pct=70.0, hallucination_pct=50.0,
        has_benign_samples=True,
    )
    assert v["tier"] == "fail"


# ── Boundary conditions ───────────────────────────────────────────────────────

def test_recall_exactly_at_pass_bound_is_pass():
    """Recall exactly 90.0 → PASS (>= for higher-is-better drivers)."""
    v = compute_verdict(
        recall_pct=90.0, fp_rate_pct=5.0, hallucination_pct=5.0,
        has_benign_samples=True,
    )
    assert v["tier"] == "pass"


def test_recall_exactly_at_fail_bound_is_caution():
    """Recall exactly 60.0 → CAUTION (the strict `<` for FAIL means 60 stays caution)."""
    v = compute_verdict(
        recall_pct=60.0, fp_rate_pct=5.0, hallucination_pct=5.0,
        has_benign_samples=True,
    )
    assert v["tier"] == "caution"


def test_fp_rate_exactly_at_pass_bound_is_pass():
    """FP rate exactly 10.0 → PASS (`<=` for lower-is-better drivers)."""
    v = compute_verdict(
        recall_pct=95.0, fp_rate_pct=10.0, hallucination_pct=5.0,
        has_benign_samples=True,
    )
    assert v["tier"] == "pass"


def test_fp_rate_exactly_at_fail_bound_is_caution():
    """FP rate exactly 50.0 → CAUTION (strict `>` for FAIL)."""
    v = compute_verdict(
        recall_pct=95.0, fp_rate_pct=50.0, hallucination_pct=5.0,
        has_benign_samples=True,
    )
    assert v["tier"] == "caution"


# ── No-benign edge cases ──────────────────────────────────────────────────────

def test_no_benign_caution_by_hallucination():
    """When fp_rate isn't measured, a caution-tier hallucination still drives
    the verdict to CAUTION."""
    v = compute_verdict(
        recall_pct=95.0, fp_rate_pct=None, hallucination_pct=25.0,
        has_benign_samples=False,
    )
    assert v["tier"] == "caution"
    assert any("FP rate not measured" in r for r in v["reasons"])


def test_no_benign_fail_by_recall():
    v = compute_verdict(
        recall_pct=40.0, fp_rate_pct=None, hallucination_pct=5.0,
        has_benign_samples=False,
    )
    assert v["tier"] == "fail"


# ── Insufficient-data branch ──────────────────────────────────────────────────

def test_insufficient_when_no_recall():
    """No malicious samples → recall undefined → tier=insufficient (refuses to
    issue a verdict rather than guessing)."""
    v = compute_verdict(
        recall_pct=None, fp_rate_pct=5.0, hallucination_pct=5.0,
        has_benign_samples=True,
    )
    assert v["tier"] == "insufficient"
    assert v["drivers"]["recall_pct"] is None


# ── Output schema ─────────────────────────────────────────────────────────────

def test_drivers_payload_round_trip():
    """The `drivers` payload must carry the exact input values so consumers
    (UI/PDF) don't need to re-derive them."""
    v = compute_verdict(
        recall_pct=85.7, fp_rate_pct=25.0, hallucination_pct=8.4,
        has_benign_samples=True,
    )
    assert v["drivers"]["recall_pct"] == 85.7
    assert v["drivers"]["fp_rate_pct"] == 25.0
    assert v["drivers"]["hallucination_pct"] == 8.4


def test_reasons_in_display_order():
    """Reasons should appear in driver-display order: recall, fp_rate (when
    measured), hallucination, plus the no-benign caveat if applicable."""
    v = compute_verdict(
        recall_pct=95.0, fp_rate_pct=5.0, hallucination_pct=5.0,
        has_benign_samples=True,
    )
    # Expect 3 reasons in this order
    assert v["reasons"][0].startswith("Detection rate")
    assert v["reasons"][1].startswith("FP rate")
    assert v["reasons"][2].startswith("Hallucination")


def test_custom_thresholds_override():
    """Per-call threshold override should work — e.g. a stricter rubric for a
    high-stakes test set without touching config."""
    strict = {
        "recall":        {"pass": 99.0, "fail": 95.0},
        "fp_rate":       {"pass": 1.0,  "fail": 5.0},
        "hallucination": {"pass": 1.0,  "fail": 5.0},
    }
    v = compute_verdict(
        recall_pct=98.0, fp_rate_pct=2.0, hallucination_pct=2.0,
        has_benign_samples=True,
        thresholds=strict,
    )
    assert v["tier"] == "caution"  # would be PASS under default thresholds
