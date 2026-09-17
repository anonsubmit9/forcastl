"""Smart Recommendations Engine.

Analyses per-file detection results and configuration to generate
actionable recommendations surfaced in the webapp and the run-level PDF report.
"""

import re
from pathlib import Path
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_recommendations(
    test_results: List[Dict],
    config: Dict,
    summary: Optional[Dict] = None,
) -> List[Dict]:
    """Return a sorted list of recommendation dicts.

    Each dict has the shape::

        {
            "id":             str,   # unique slug
            "category":       str,   # configuration | quality | per_file | verdict
            "severity":       str,   # critical | warning | info
            "title":          str,
            "description":    str,
            "affected_files": [...], # optional
            "data":           {},    # optional structured payload
        }

    *test_results* is the raw ``results`` list produced by the detector
    (each entry has ``file_path``, ``status``, ``detection``, ``llm_response``,
    ``response_time``, etc.).

    *config* carries run-level settings::

        {"max_tokens": int, "model_name": str}

    *summary* is the manifest summary dict (optional). When provided and it
    carries a ``verdict`` block, a verdict-tier recommendation is emitted so
    the rationale appears in the existing attention list alongside per-file
    alerts.
    """
    recs: List[Dict] = []
    recs.extend(_configuration_recommendations(test_results, config))
    recs.extend(_quality_recommendations(test_results, config))
    recs.extend(_per_file_recommendations(test_results, config))
    if summary:
        recs.extend(_verdict_recommendations(summary))

    severity_order = {"critical": 0, "warning": 1, "info": 2}
    recs.sort(key=lambda r: severity_order.get(r.get("severity", "info"), 9))
    return recs


def _verdict_recommendations(summary: Dict) -> List[Dict]:
    """Emit a single recommendation reflecting the run-level verdict tier.

    Skips PASS to avoid clutter. CAUTION → severity=warning, FAIL → critical,
    insufficient → info caveat. Carries verdict_reasons in ``data`` so the UI
    can show drivers alongside the title/description.
    """
    verdict = summary.get("verdict")
    if not isinstance(verdict, dict):
        return []
    tier = verdict.get("tier")
    insufficient = verdict.get("insufficient")
    reasons = verdict.get("reasons") or []

    if insufficient:
        # Two distinct insufficient shapes share a tier: no ground truth at
        # all vs. ground truth present but sample size below threshold. The
        # actionable fix differs (add labels vs. raise sample size), so the
        # description has to disambiguate.
        drivers = verdict.get("drivers") or {}
        n_mal = drivers.get("n_malicious") or 0
        if n_mal == 0:
            description = ("No malicious ground truth was available for this "
                           "run, so detection rate cannot be computed. Add a "
                           "labelled corpus to derive a verdict.")
        else:
            # Surface the verdict layer's own actionable reasons rather than
            # repeating the wrong remediation for a small-sample run.
            description = " ".join(reasons) if reasons else (
                "Sample size is below the threshold needed for a reliable "
                "verdict. Re-run with at least 30 attack and 30 benign samples."
            )
        return [{
            "id": "verdict-insufficient-data",
            "category": "verdict",
            "severity": "info",
            "title": "Verdict: insufficient data",
            "description": description,
            "data": {
                "tier": tier,
                "reasons": reasons,
                "drivers": drivers,
            },
        }]

    if tier == "fail":
        return [{
            "id": "verdict-fail",
            "category": "verdict",
            "severity": "critical",
            "title": "Verdict: FAIL — not suitable for production forensics",
            "description": ("This model breached at least one FAIL threshold. "
                            "Investigate the drivers below before considering "
                            "any deployment."),
            "data": {
                "tier": tier,
                "reasons": reasons,
                "drivers": verdict.get("drivers") or {},
            },
        }]

    if tier == "caution":
        return [{
            "id": "verdict-caution",
            "category": "verdict",
            "severity": "warning",
            "title": "Verdict: CAUTION — useful only with human review",
            "description": ("Performance is between the PASS and FAIL bars. "
                            "Review the drivers below; do not rely on this "
                            "model for unattended decisions."),
            "data": {
                "tier": tier,
                "reasons": reasons,
                "drivers": verdict.get("drivers") or {},
            },
        }]

    # PASS or any other tier — no recommendation needed.
    return []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _status(r: Dict) -> str:
    return (r.get("status") or "processed").strip().lower()


def _processed(results: List[Dict]) -> List[Dict]:
    return [r for r in results if _status(r) == "processed"]


def _filename(r: Dict) -> str:
    return Path(r.get("file_path", "")).name


# ---------------------------------------------------------------------------
# Token parsing
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(
    r"Context exceeded:\s*([\d,]+)\s*tokens?\s*>\s*([\d,]+)",
    re.IGNORECASE,
)


def _parse_estimated_tokens(llm_response: str) -> Optional[int]:
    """Extract the *estimated* token count from a context-exceeded message.

    Expected format: ``"Context exceeded: 7114 tokens > 6992"``
    Returns the first number (estimated tokens) or *None*.
    """
    if not llm_response:
        return None
    m = _TOKEN_RE.search(llm_response)
    if m:
        return int(m.group(1).replace(",", ""))
    return None


def _parse_budget_tokens(llm_response: str) -> Optional[int]:
    """Extract the *budget* (limit) token count from a context-exceeded message."""
    if not llm_response:
        return None
    m = _TOKEN_RE.search(llm_response)
    if m:
        return int(m.group(2).replace(",", ""))
    return None


# ---------------------------------------------------------------------------
# Configuration recommendations
# ---------------------------------------------------------------------------

def _configuration_recommendations(
    results: List[Dict],
    config: Dict,
) -> List[Dict]:
    recs: List[Dict] = []
    max_tokens = config.get("max_tokens") or 0

    # --- Context exceeded files ---
    exceeded = [
        r for r in results if _status(r) == "context_exceeded"
    ]
    if exceeded:
        gaps = []
        for r in exceeded:
            est = _parse_estimated_tokens(r.get("llm_response", ""))
            budget = _parse_budget_tokens(r.get("llm_response", ""))
            if est is not None and budget is not None:
                gaps.append({"file": _filename(r), "estimated": est, "budget": budget, "gap": est - budget})

        if gaps:
            smallest_gap = min(gaps, key=lambda g: g["gap"])
            suggested = max_tokens - smallest_gap["gap"] - 1 if max_tokens else None
            desc = (
                f"The closest file was only {smallest_gap['gap']} tokens over. "
            )
            if suggested and suggested > 0:
                recoverable = sum(1 for g in gaps if max_tokens - g["gap"] - 1 > 0)
                desc += (
                    f"Reducing max_tokens from {max_tokens} to {suggested} "
                    f"would recover {recoverable} file(s)."
                )
            recs.append({
                "id": "cfg-context-exceeded",
                "category": "configuration",
                "severity": "warning",
                "title": f"{len(exceeded)} file(s) exceeded context budget",
                "description": desc,
                "affected_files": [_filename(r) for r in exceeded],
                "data": {"gaps": gaps, "suggested_max_tokens": suggested},
            })
        else:
            recs.append({
                "id": "cfg-context-exceeded",
                "category": "configuration",
                "severity": "warning",
                "title": f"{len(exceeded)} file(s) exceeded context budget",
                "description": "Could not parse token details from the response.",
                "affected_files": [_filename(r) for r in exceeded],
            })

    # --- Files that errored out (timeouts / oversized / failures) ---
    # These produce no verdict and count as misses, so surface them explicitly —
    # otherwise a run that "failed on the biggest files" looks clean.
    errored = [r for r in results if _status(r) == "error"]
    if errored:
        timeout_s = config.get("timeout") or 0
        timeouts, oversized, other = [], [], []
        for r in errored:
            t = r.get("response_time", 0) or 0
            reason = (r.get("error_reason") or "").lower()
            if "timed out" in reason or (timeout_s and t >= timeout_s * 0.9):
                timeouts.append(_filename(r))
            elif t < 5:
                # Failed almost immediately — usually the prompt/events were too
                # large for the model's context window, or a connection refusal.
                oversized.append(_filename(r))
            else:
                other.append(_filename(r))
        bits = []
        if timeouts:
            bits.append(f"{len(timeouts)} timed out")
        if oversized:
            bits.append(f"{len(oversized)} failed immediately (events likely too large for the model's context window)")
        if other:
            bits.append(f"{len(other)} other failure(s)")
        desc = ("These files produced no verdict and count as missed detections. "
                + "; ".join(bits) + ".")
        if timeouts and timeout_s:
            desc += f" Raise the timeout (currently {timeout_s}s) to recover the ones that timed out."
        recs.append({
            "id": "cfg-files-errored",
            "category": "configuration",
            "severity": "warning",
            "title": f"{len(errored)} file(s) failed to process",
            "description": desc,
            "affected_files": [_filename(r) for r in errored],
            "data": {"timeouts": timeouts, "oversized": oversized,
                     "other": other, "timeout_s": timeout_s},
        })

    # --- Response time outliers (>3x average, need >= 3 files) ---
    proc = _processed(results)
    times = [(r, r.get("response_time", 0)) for r in proc if r.get("response_time")]
    if len(times) >= 3:
        avg_time = sum(t for _, t in times) / len(times)
        outliers = [(r, t) for r, t in times if t > avg_time * 3]
        if outliers:
            recs.append({
                "id": "cfg-slow-files",
                "category": "configuration",
                "severity": "info",
                "title": f"{len(outliers)} file(s) took >3x average response time",
                "description": f"Average response time was {avg_time:.1f}s. These files may benefit from content trimming or a higher timeout.",
                "affected_files": [_filename(r) for r, _ in outliers],
                "data": {"avg_time_s": round(avg_time, 1), "outlier_times": {_filename(r): round(t, 1) for r, t in outliers}},
            })

    return recs


# ---------------------------------------------------------------------------
# Quality recommendations
# ---------------------------------------------------------------------------

def _quality_recommendations(
    results: List[Dict],
    config: Dict,
) -> List[Dict]:
    recs: List[Dict] = []
    proc = _processed(results)
    if not proc:
        return recs

    # --- High hallucination (avg > 15%) ---
    hall_rates = [
        r.get("detection", {}).get("hallucination", {}).get("ratio", 0)
        for r in proc
        if r.get("detection", {}).get("hallucination") is not None
    ]
    if hall_rates:
        avg_hall = sum(hall_rates) / len(hall_rates)
        if avg_hall > 0.15:
            # Find worst hallucinated fields across all files
            field_counts: Dict[str, int] = {}
            for r in proc:
                hallucinated = ((r.get("detection") or {}).get("hallucination") or {}).get("hallucinated", {})
                if isinstance(hallucinated, dict):
                    for field, items in hallucinated.items():
                        if items:
                            count = len(items) if isinstance(items, list) else 1
                            field_counts[field] = field_counts.get(field, 0) + count
            worst = sorted(field_counts.items(), key=lambda x: -x[1])[:3]
            worst_str = ", ".join(f"{f} ({c})" for f, c in worst) if worst else "N/A"
            recs.append({
                "id": "qual-high-hallucination",
                "category": "quality",
                "severity": "warning",
                "title": f"High hallucination rate ({avg_hall * 100:.0f}%)",
                "description": f"Worst fields: {worst_str}.",
                "data": {"avg_hallucination_pct": round(avg_hall * 100, 1), "worst_fields": dict(worst)},
            })

    # --- Low alignment (avg < 80%) ---
    alignments = [
        r.get("detection", {}).get("alignment", {}).get("score", 0)
        for r in proc
        if r.get("detection", {}).get("alignment") is not None
    ]
    if alignments:
        avg_align = sum(alignments) / len(alignments)
        if avg_align < 80:
            # Find weakest per-field scores
            field_scores: Dict[str, List[float]] = {}
            for r in proc:
                fm = ((r.get("detection") or {}).get("alignment") or {}).get("field_matches", {})
                if isinstance(fm, dict):
                    for field, info in fm.items():
                        sc = info.get("score", 0) if isinstance(info, dict) else 0
                        field_scores.setdefault(field, []).append(sc)
            field_avgs = {f: sum(s) / len(s) for f, s in field_scores.items() if s}
            weakest = sorted(field_avgs.items(), key=lambda x: x[1])[:3]
            weakest_str = ", ".join(f"{f} ({v:.0f}%)" for f, v in weakest) if weakest else "N/A"
            recs.append({
                "id": "qual-low-alignment",
                "category": "quality",
                "severity": "warning",
                "title": f"Low average alignment ({avg_align:.0f}%)",
                "description": f"Weakest fields: {weakest_str}.",
                "data": {"avg_alignment_pct": round(avg_align, 1), "weakest_fields": dict(weakest)},
            })

    # --- Grade D files ---
    grade_d = [
        r for r in proc
        if r.get("detection", {}).get("score_breakdown", {}).get("grade") == "D"
    ]
    if grade_d:
        recs.append({
            "id": "qual-grade-d",
            "category": "quality",
            "severity": "warning",
            "title": f"{len(grade_d)} file(s) received grade D",
            "description": "Open the per-file CSV to inspect the failing extractions.",
            "affected_files": [_filename(r) for r in grade_d],
        })

    # --- All-malicious or all-benign (>= 3 processed) ---
    if len(proc) >= 3:
        mal_count = sum(
            1 for r in proc
            if r.get("detection", {}).get("is_malicious", False)
        )
        ben_count = len(proc) - mal_count
        if mal_count == len(proc):
            recs.append({
                "id": "qual-all-malicious",
                "category": "quality",
                "severity": "info",
                "title": "All files detected as malicious",
                "description": "Consider including known-benign samples for broader coverage.",
            })
        elif ben_count == len(proc):
            recs.append({
                "id": "qual-all-benign",
                "category": "quality",
                "severity": "info",
                "title": "All files detected as benign",
                "description": "Consider including known-malicious samples for broader coverage.",
            })

    # --- Low reasoning (avg < 2.5 / 4) ---
    # Keys MUST match the detail strings emitted by
    # core.detection_scoring.score_reasoning; the values are friendly display
    # labels. (Previously this set used the labels as keys, so 'references
    # evidence' / 'security language' never matched and always reported
    # missing-in-all.)
    trait_labels = {
        "substantive": "substantive",
        "evidence-grounded": "references evidence",
        "consistent": "consistent",
        "domain-aware": "security language",
    }
    reasoning_scores = []
    missing_traits: Dict[str, int] = {}
    all_traits = set(trait_labels)
    for r in proc:
        reasoning = (r.get("detection") or {}).get("reasoning") or {}
        if reasoning:
            reasoning_scores.append(reasoning.get("score", 0))
            present = set(reasoning.get("details", []))
            for trait in all_traits - present:
                missing_traits[trait] = missing_traits.get(trait, 0) + 1
    if reasoning_scores:
        avg_reasoning = sum(reasoning_scores) / len(reasoning_scores)
        if avg_reasoning < 2.5:
            worst_missing = sorted(missing_traits.items(), key=lambda x: -x[1])[:3]
            missing_str = ", ".join(
                f"{trait_labels[t]} (missing in {c})" for t, c in worst_missing
            ) if worst_missing else "N/A"
            recs.append({
                "id": "qual-low-reasoning",
                "category": "quality",
                "severity": "info",
                "title": f"Low reasoning quality (avg {avg_reasoning:.1f}/4)",
                "description": f"Most commonly missing: {missing_str}.",
                "data": {"avg_reasoning": round(avg_reasoning, 1), "missing_traits": dict(worst_missing)},
            })

    return recs


# ---------------------------------------------------------------------------
# Per-file recommendations
# ---------------------------------------------------------------------------

def _per_file_recommendations(
    results: List[Dict],
    config: Dict,
) -> List[Dict]:
    recs: List[Dict] = []
    proc = _processed(results)

    for r in proc:
        fname = _filename(r)
        det = r.get("detection", {}) or {}
        issues: List[str] = []
        data: Dict = {}

        # --- Hallucination > 50% ---
        hall_ratio = (det.get("hallucination") or {}).get("ratio", 0)
        if hall_ratio > 0.5:
            issues.append(f"hallucination {hall_ratio * 100:.0f}%")
            data["hallucination_pct"] = round(hall_ratio * 100, 1)

        # --- Alignment < 50% ---
        align_score = (det.get("alignment") or {}).get("score", None)
        if align_score is not None and align_score < 50:
            issues.append(f"alignment {align_score:.0f}%")
            data["alignment_pct"] = round(align_score, 1)

        # --- Misclassification vs ground truth ---
        mal_match = (det.get("alignment") or {}).get("malicious_match")
        if mal_match is False:
            got_mal = bool(det.get("is_malicious", False))
            expected_mal = not got_mal
            label = "malicious" if expected_mal else "benign"
            issues.append(f"misclassified (expected {label})")
            data["misclassified"] = True
            data["expected_label"] = label
            # Extra context for the expandable per-finding view in the UI.
            data["got_label"] = "malicious" if got_mal else "benign"
            sb = det.get("score_breakdown") or {}
            data["score_20"] = sb.get("total_20", sb.get("total"))
            if align_score is not None:
                data["alignment_pct"] = round(align_score, 1)
            expl = (det.get("parsed") or {}).get("explanation")
            if expl:
                expl = " ".join(str(expl).split())
                data["explanation"] = expl[:240] + ("…" if len(expl) > 240 else "")

        if issues:
            title = f"{fname}: {', '.join(issues)}"
            parts = [", ".join(issues)]
            if data.get("misclassified"):
                parts.append(
                    f"Expected {data['expected_label']} but classified otherwise."
                )
            recs.append({
                "id": "file-alert",
                "category": "per_file",
                "severity": "warning",
                "title": title,
                "description": ". ".join(parts),
                "affected_files": [fname],
                "data": data,
            })

    return recs
