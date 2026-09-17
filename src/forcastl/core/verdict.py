"""Pure run-level verdict synthesis.

Inputs are three driver percentages (recall, fp_rate, hallucination) plus a
flag for whether benign samples were available; output is a tier (`pass` /
`caution` / `fail`) plus per-driver reasons that explain the tier so the
verdict is never opaque.

This module is import-light and side-effect-free by design: the only
non-trivial dependency is `config.VERDICT_THRESHOLDS`, which can be overridden
per-call via the `thresholds` argument for testing or tuning.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


# Driver direction: True = higher is better (recall), False = lower is better.
_DRIVER_DIRECTION = {
    "recall":        True,
    "fp_rate":       False,
    "hallucination": False,
}

# Human-friendly driver labels (used in reasons strings).
_DRIVER_LABEL = {
    "recall":        "Detection rate",
    "fp_rate":       "FP rate",
    "hallucination": "Hallucination",
}

_TIER_RANK = {"pass": 0, "caution": 1, "fail": 2}

# Minimum sample size before we'll issue a definitive PASS/CAUTION/FAIL verdict.
# Below this, results are reported as "insufficient data" with a plain-language
# explanation. 30 is the textbook small-sample threshold and gives Wilson 95%
# CI half-widths roughly in the ±15pp range for mid-range proportions.
MIN_SAMPLES_FOR_VERDICT = 30


def wilson_ci(successes: int, n: int, z: float = 1.96) -> Optional[tuple]:
    """Wilson 95% confidence interval for a binomial proportion, as percentages.

    Returns (lo_pct, hi_pct) or None when n == 0. Handles the edge cases the
    naive normal approximation breaks on (0/n, n/n, very small n) without
    producing nonsense like negative bounds.
    """
    if n <= 0:
        return None
    p = successes / n
    denom = 1.0 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / denom
    lo = max(0.0, center - half) * 100.0
    hi = min(1.0, center + half) * 100.0
    return (lo, hi)


def _classify_driver(value: float, bounds: Dict[str, float], higher_is_better: bool) -> str:
    """Return the tier this single driver lands in given its bounds.

    Bounds carry "pass" and "fail" thresholds; the space between is "caution".
    For higher-is-better drivers (recall): value >= pass → PASS, value < fail
    → FAIL. For lower-is-better drivers (fp_rate, hallucination): value <=
    pass → PASS, value > fail → FAIL.
    """
    pass_bound = bounds["pass"]
    fail_bound = bounds["fail"]
    if higher_is_better:
        if value >= pass_bound:
            return "pass"
        if value < fail_bound:
            return "fail"
        return "caution"
    else:
        if value <= pass_bound:
            return "pass"
        if value > fail_bound:
            return "fail"
        return "caution"


def _reason_for(driver: str, value: float, tier: str, bounds: Dict[str, float]) -> str:
    label = _DRIVER_LABEL[driver]
    pass_bound = bounds["pass"]
    fail_bound = bounds["fail"]
    if tier == "pass":
        return f"{label} {value:.1f}% within PASS range"
    if tier == "fail":
        comparator = "below" if _DRIVER_DIRECTION[driver] else "exceeds"
        return f"{label} {value:.1f}% {comparator} FAIL threshold ({fail_bound:.0f}%)"
    # caution
    comparator = "below" if _DRIVER_DIRECTION[driver] else "exceeds"
    return f"{label} {value:.1f}% {comparator} PASS threshold ({pass_bound:.0f}%)"


def compute_verdict(
    *,
    recall_pct: Optional[float],
    fp_rate_pct: Optional[float],
    hallucination_pct: float,
    has_benign_samples: bool,
    n_malicious: int = 0,
    n_benign: int = 0,
    tp: int = 0,
    fp: int = 0,
    thresholds: Optional[Dict[str, Dict[str, float]]] = None,
) -> Dict[str, Any]:
    """Synthesize a run-level verdict from the three drivers.

    Tier is the worst driver's tier; reasons accumulate per driver in display
    order (recall → fp → hallucination) so the report can show the full
    rationale. When `has_benign_samples` is False, fp_rate is skipped from the
    rule entirely (denominator was zero) and a "FP rate not measured" caveat is
    appended to reasons. When recall_pct is None (no malicious samples in
    scope), tier is "insufficient" — refuses to issue a verdict at all rather
    than guessing.

    Returns a dict with the schema documented in the verdict-feature plan:
      {"tier", "reasons", "drivers", "has_benign"}
    """
    from forcastl.config import VERDICT_THRESHOLDS  # local import keeps module side-effect-free at import time

    thresholds = thresholds or VERDICT_THRESHOLDS

    recall_ci = wilson_ci(tp, n_malicious) if n_malicious > 0 else None
    fp_rate_ci = wilson_ci(fp, n_benign) if (has_benign_samples and n_benign > 0) else None

    # No malicious samples → cannot decide. Report explicitly.
    # Both `tier="insufficient"` and `insufficient=True` are set so consumers
    # that check either convention (the recommendations engine reads the
    # boolean flag; the UI/PDF banner branch on tier OR flag) all agree.
    if recall_pct is None:
        return {
            "tier": "insufficient",
            "insufficient": True,
            "headline_sub": "No malicious ground truth available",
            "reasons": ["No malicious samples in scope; verdict cannot be computed."],
            "drivers": {
                "recall_pct": None,
                "recall_ci": None,
                "fp_rate_pct": fp_rate_pct,
                "fp_rate_ci": fp_rate_ci,
                "hallucination_pct": hallucination_pct,
                "n_malicious": n_malicious,
                "n_benign": n_benign,
            },
            "has_benign": has_benign_samples,
        }

    # Sample size too small for a credible PASS/CAUTION/FAIL.
    # Only enforced when the caller actually passes counts (n_malicious > 0);
    # legacy callers that omit counts skip this check and get the old behavior.
    # Pattern: "NEEDS MORE DATA — only N attacks tested. Score could be
    # anywhere from X% to Y%. Re-run with at least 30 attacks."
    small_attack_sample = 0 < n_malicious < MIN_SAMPLES_FOR_VERDICT
    small_benign_sample = has_benign_samples and 0 < n_benign < MIN_SAMPLES_FOR_VERDICT
    if small_attack_sample or small_benign_sample:
        reasons: List[str] = []
        if n_malicious < MIN_SAMPLES_FOR_VERDICT:
            base = (
                f"Only {n_malicious} attack sample(s) tested — too few for a "
                f"reliable score."
            )
            if recall_ci is not None:
                base += (
                    f" Detection rate could be anywhere from {recall_ci[0]:.0f}% "
                    f"to {recall_ci[1]:.0f}%."
                )
            reasons.append(base)
        if has_benign_samples and 0 < n_benign < MIN_SAMPLES_FOR_VERDICT:
            base = (
                f"Only {n_benign} benign sample(s) tested — false-positive rate "
                f"is unreliable."
            )
            if fp_rate_ci is not None:
                base += (
                    f" FP rate could be anywhere from {fp_rate_ci[0]:.0f}% "
                    f"to {fp_rate_ci[1]:.0f}%."
                )
            reasons.append(base)
        reasons.append(
            f"Re-run with at least {MIN_SAMPLES_FOR_VERDICT} attack and "
            f"{MIN_SAMPLES_FOR_VERDICT} benign samples for a reliable verdict."
        )
        return {
            "tier": "insufficient",
            "insufficient": True,
            "headline_sub": f"Sample size too small (n={n_malicious} attacks, {n_benign} benign)",
            "reasons": reasons,
            "drivers": {
                "recall_pct": recall_pct,
                "recall_ci": recall_ci,
                "fp_rate_pct": fp_rate_pct,
                "fp_rate_ci": fp_rate_ci,
                "hallucination_pct": hallucination_pct,
                "n_malicious": n_malicious,
                "n_benign": n_benign,
            },
            "has_benign": has_benign_samples,
        }

    drivers_to_check = ["recall", "hallucination"]
    driver_values = {
        "recall": recall_pct,
        "hallucination": hallucination_pct,
    }
    if has_benign_samples and fp_rate_pct is not None:
        drivers_to_check.insert(1, "fp_rate")  # display order: recall, fp, hall
        driver_values["fp_rate"] = fp_rate_pct

    per_driver_tiers: Dict[str, str] = {}
    reasons: List[str] = []
    for driver in drivers_to_check:
        bounds = thresholds[driver]
        value = driver_values[driver]
        tier = _classify_driver(value, bounds, _DRIVER_DIRECTION[driver])
        per_driver_tiers[driver] = tier
        reasons.append(_reason_for(driver, value, tier, bounds))

    if not has_benign_samples or fp_rate_pct is None:
        reasons.append("FP rate not measured (no benign samples in scope)")

    # Final tier = worst driver tier.
    final_tier = max(per_driver_tiers.values(), key=lambda t: _TIER_RANK[t])

    return {
        "tier": final_tier,
        "insufficient": False,
        "reasons": reasons,
        "drivers": {
            "recall_pct": recall_pct,
            "recall_ci": recall_ci,
            "fp_rate_pct": fp_rate_pct,
            "fp_rate_ci": fp_rate_ci,
            "hallucination_pct": hallucination_pct,
            "n_malicious": n_malicious,
            "n_benign": n_benign,
        },
        "has_benign": has_benign_samples,
    }
