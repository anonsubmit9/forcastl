"""PDF report renderer for benchmark runs.

Renders the Jinja2 template at ``reporting/templates/pdf_report.html``
against a manifest (+ CSV rows + ground truth) and prints the result to PDF
via headless Chromium (bundled under ``chromium/`` or system Chrome/Chromium).

Public entry: :func:`generate_pdf_report`.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from jinja2 import Environment, FileSystemLoader, select_autoescape

from forcastl import config


_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"   # ships with the package
_CHROMIUM_DIR = Path(config.REPO_ROOT) / "chromium"             # local dev artefact


# ── Tier hints ────────────────────────────────────────────────────────────────
# Map a metric value to "good" / "warn" / "bad" / "neutral" so the template
# can color-tier each tile / derived-metric. Bounds mirror the verdict
# thresholds in ``config.VERDICT_THRESHOLDS`` so the PDF and the verdict
# block agree on what's pass-quality vs fail-quality.

def _tier_higher_is_better(value: Optional[float], pass_bound: float, fail_bound: float) -> str:
    if value is None:
        return "neutral"
    if value >= pass_bound:
        return "good"
    if value < fail_bound:
        return "bad"
    return "warn"


def _tier_lower_is_better(value: Optional[float], pass_bound: float, fail_bound: float) -> str:
    if value is None:
        return "neutral"
    if value <= pass_bound:
        return "good"
    if value > fail_bound:
        return "bad"
    return "warn"


def _alignment_tier(value: Optional[float]) -> str:
    return _tier_higher_is_better(value, 80.0, 50.0)


def _score_20_tier(value: Optional[float]) -> str:
    if value is None:
        return "neutral"
    if value >= 17.0:
        return "good"
    if value < 10.0:
        return "bad"
    return "warn"


def _hallucination_tier(value: Optional[float]) -> str:
    return _tier_lower_is_better(value, 10.0, 40.0)


def _recall_tier(value: Optional[float]) -> str:
    return _tier_higher_is_better(value, 90.0, 60.0)


def _fp_rate_tier(value: Optional[float]) -> str:
    return _tier_lower_is_better(value, 10.0, 50.0)


def _precision_tier(value: Optional[float]) -> str:
    return _tier_higher_is_better(value, 80.0, 50.0)


def _files_error_tier(errors: int, total: int) -> str:
    if total == 0:
        return "neutral"
    rate = errors / total
    if rate <= 0.05:
        return "good"
    if rate >= 0.30:
        return "bad"
    return "warn"


# ── Context builders ──────────────────────────────────────────────────────────

def _format_started_at(iso_str: Optional[str]) -> str:
    if not iso_str:
        return ""
    try:
        dt = datetime.fromisoformat(iso_str)
    except (TypeError, ValueError):
        return iso_str
    return dt.strftime("%B %d, %Y · %H:%M")


def _build_tiles(summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Top-of-page metric tiles. Order matches the spec for the cover page."""
    total = summary.get("total_files") or 0
    processed = summary.get("processed") or 0
    errors = (summary.get("error") or 0) + (summary.get("context_exceeded") or 0)
    avg_score = summary.get("avg_score_20")
    avg_alignment = summary.get("avg_alignment")
    hall = summary.get("avg_hallucination_rate")
    hall_pct = (hall * 100.0) if isinstance(hall, (int, float)) else None
    recall = summary.get("recall_pct")
    fp_rate = summary.get("fp_rate_pct")
    precision = summary.get("precision_pct")

    tiles: List[Dict[str, Any]] = [
        {
            "label": "Files",
            "value": f"{processed}/{total}" if total else "0",
            "tier": "good" if processed and processed == total else "warn",
        },
        {
            "label": "Errors",
            "value": str(errors),
            "tier": _files_error_tier(errors, total),
        },
        {
            "label": "Avg score",
            "value": f"{avg_score:.1f}/20" if isinstance(avg_score, (int, float)) else "—",
            "tier": _score_20_tier(avg_score if isinstance(avg_score, (int, float)) else None),
        },
        {
            "label": "Alignment",
            "value": f"{avg_alignment:.0f}%" if isinstance(avg_alignment, (int, float)) else "—",
            "tier": _alignment_tier(avg_alignment if isinstance(avg_alignment, (int, float)) else None),
        },
        {
            "label": "Hallucination",
            "value": f"{hall_pct:.0f}%" if hall_pct is not None else "—",
            "tier": _hallucination_tier(hall_pct),
        },
        {
            "label": "Recall",
            "value": f"{recall:.0f}%" if isinstance(recall, (int, float)) else "—",
            "tier": _recall_tier(recall if isinstance(recall, (int, float)) else None),
        },
        {
            "label": "FP rate",
            "value": f"{fp_rate:.0f}%" if isinstance(fp_rate, (int, float)) else "n/a",
            "tier": _fp_rate_tier(fp_rate if isinstance(fp_rate, (int, float)) else None),
        },
        {
            "label": "Precision",
            "value": f"{precision:.0f}%" if isinstance(precision, (int, float)) else "—",
            "tier": _precision_tier(precision if isinstance(precision, (int, float)) else None),
        },
    ]
    return tiles


def _build_summary_sentence(summary: Dict[str, Any], model: str) -> str:
    total = summary.get("total_files") or 0
    processed = summary.get("processed") or 0
    avg_score = summary.get("avg_score_20")
    score_str = f"{avg_score:.1f}/20" if isinstance(avg_score, (int, float)) else "—"
    verdict = (summary.get("verdict") or {}).get("tier")
    verdict_str = f" Verdict: {verdict.upper()}." if verdict else ""
    return (
        f"{model} processed {processed} of {total} files with an average score of "
        f"{score_str}.{verdict_str}"
    )


def _build_confusion(summary: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Confusion-matrix block, or None when not derivable.

    A run with `total_malicious_in_scope == 0` has no usable confusion data —
    return None so the template hides the section entirely rather than show
    all-zeros.
    """
    if not summary.get("total_malicious_in_scope"):
        return None
    recall = summary.get("recall_pct")
    fp_rate = summary.get("fp_rate_pct")
    precision = summary.get("precision_pct")
    return {
        "tp": summary.get("true_positives") or 0,
        "fp": summary.get("false_positives") or 0,
        "tn": summary.get("true_negatives") or 0,
        "fn": summary.get("false_negatives") or 0,
        "recall_pct": recall if isinstance(recall, (int, float)) else 0.0,
        "fp_rate_pct": fp_rate if isinstance(fp_rate, (int, float)) else 0.0,
        "precision_pct": precision if isinstance(precision, (int, float)) else 0.0,
        "recall_tier": _recall_tier(recall),
        "fp_rate_tier": _fp_rate_tier(fp_rate),
        "precision_tier": _precision_tier(precision),
    }


def _build_findings(recommendations: List[Dict[str, Any]], limit: int = 8) -> Tuple[List[Dict[str, Any]], int]:
    """Pick the top-priority recommendations for the findings block.

    Mirrors the web UI: the run-level verdict rec is dropped (it's shown as the
    badge), and the limit is high enough that the failed-files card surfaces
    alongside per-file misclassifications.
    """
    if not recommendations:
        return [], 0
    severity_order = {"critical": 0, "warning": 1, "info": 2}
    items = [r for r in recommendations if r.get("category") != "verdict"]
    sortable = sorted(
        items,
        key=lambda r: severity_order.get(r.get("severity", "info"), 9),
    )
    findings = []
    for r in sortable[:limit]:
        findings.append({
            "severity": r.get("severity", "info"),
            "title": r.get("title", ""),
            "description": r.get("description", ""),
            "affected": r.get("affected_files") or [],
        })
    hidden = max(0, len(sortable) - limit)
    return findings, hidden


def _build_per_file(csv_rows: List[Dict[str, str]], ground_truth: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    gt = ground_truth or {}
    for row in csv_rows:
        # `read_detection_csv` yields the on-disk headers ("Filename", "Malicious",
        # "Alignment %", "Total (20)", ...). The lowercase/underscore keys are kept
        # as fallbacks for older callers/fixtures.
        filename = (row.get("Filename") or row.get("file_name")
                    or row.get("filename") or row.get("file_path") or "")
        filename = Path(filename).name if filename else ""
        gt_entry = gt.get(filename, {}) if filename else {}
        # Ground truth is keyed by .evtx even for CSV inputs. Mirror the
        # .csv->.evtx fallback used by reporting/run_summary.py so the per-file
        # Expected/match column agrees with the verdict KPIs on the same report.
        if not gt_entry and filename.lower().endswith(".csv"):
            gt_entry = gt.get(filename[:-4] + ".evtx", {})
        expected = gt_entry.get("malicious")
        status = (row.get("Status") or row.get("status") or "").strip().lower()
        verdict = (row.get("Malicious") or row.get("malicious")
                   or row.get("verdict") or "").upper()

        if status and status != "processed":
            # errored / context_exceeded rows have no scoreable verdict
            is_match: Optional[bool] = None
        elif expected and verdict in ("YES", "NO"):
            is_match = (verdict == expected)
        else:
            is_match = None

        def _to_float(v: Any) -> Optional[float]:
            if v in (None, "", "—"):
                return None
            try:
                s = str(v).rstrip("%").strip()
                return float(s) if s else None
            except (TypeError, ValueError):
                return None

        align = _to_float(row.get("Alignment %") or row.get("alignment_score") or row.get("alignment"))
        hall = _to_float(row.get("Hallucination %") or row.get("hallucination_rate") or row.get("hallucination"))
        score_20 = _to_float(row.get("Total (20)") or row.get("score_20") or row.get("score"))
        grade = (row.get("Grade") or row.get("grade") or "").strip().upper() or None

        out.append({
            "filename": filename,
            "expected": expected,
            "verdict": verdict or "—",
            "grade": grade,
            "align_pct": int(round(align)) if align is not None else None,
            "hall_pct": int(round(hall)) if hall is not None else None,
            "score_20": int(round(score_20)) if score_20 is not None else None,
            "is_match": is_match,
        })
    return out


def _build_run_config(manifest: Dict[str, Any]) -> List[Tuple[str, str]]:
    # Detection manifests store run config at the TOP LEVEL (see
    # csv_output.write_run_manifest), not under a "config" sub-dict. Read
    # top-level first, then fall back to a legacy "config" block and legacy
    # key names so older manifests still render.
    cfg = manifest.get("config") or {}

    def pick(*keys: str) -> Any:
        for k in keys:
            v = manifest.get(k)
            if v not in (None, "", "null"):
                return v
            v = cfg.get(k)
            if v not in (None, "", "null"):
                return v
        return None

    candidates: List[Tuple[str, Any]] = [
        ("Mode",              pick("mode")),
        ("Sample size",       pick("sample_size")),
        ("Input format",      pick("input_format")),
        ("CSV dir",           pick("csv_dir")),
        ("Context window",    pick("context_window")),  # only present in legacy manifests
        ("Max output tokens", pick("max_output_tokens", "max_tokens")),
        ("Timeout (s)",       pick("timeout_s", "timeout")),
        ("Delay (s)",         pick("delay_s", "delay")),
        ("Difficulty filter", pick("difficulty_filter", "difficulty")),
        ("Test set filter",   pick("test_set_filter", "test_set")),
        ("Temperature",       pick("temperature")),
    ]
    out: List[Tuple[str, str]] = []
    for k, v in candidates:
        if v in (None, "", "null"):
            continue
        out.append((k, str(v)))
    return out


def _build_kpi_cards(summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The web UI's 3 primary KPI cards: Detection rate / FP rate / Hallucination,
    with one-decimal values, sub-labels, and tier colours."""
    recall = summary.get("recall_pct")
    fp = summary.get("fp_rate_pct")
    hall = summary.get("avg_hallucination_rate")
    hall_pct = (hall * 100.0) if isinstance(hall, (int, float)) else None
    has_benign = summary.get("has_benign_samples")
    tp = summary.get("true_positives")
    tn = summary.get("true_negatives")
    fpc = summary.get("false_positives")
    total_mal = summary.get("total_malicious_in_scope")
    total_benign = (fpc + tn) if isinstance(fpc, int) and isinstance(tn, int) else None
    hall_fab = summary.get("total_hallucinated_fields")
    hall_claim = summary.get("total_claimed_fields")

    return [
        {
            "label": "Detection rate",
            "value": f"{recall:.1f}%" if isinstance(recall, (int, float)) else "—",
            "sub": f"{tp}/{total_mal} attacks caught" if (tp is not None and total_mal) else "",
            "tier": _recall_tier(recall if isinstance(recall, (int, float)) else None),
        },
        {
            "label": "False-positive rate" if has_benign else "FP (no benign data)",
            "value": (f"{fp:.1f}%" if isinstance(fp, (int, float)) else ("—" if has_benign else "n/a")),
            "sub": f"{fpc}/{total_benign} benign mislabeled" if (fpc is not None and total_benign) else "",
            "tier": _fp_rate_tier(fp if isinstance(fp, (int, float)) else None) if has_benign else "neutral",
        },
        {
            "label": "Hallucination",
            "value": f"{hall_pct:.1f}%" if hall_pct is not None else "—",
            "sub": f"{hall_fab}/{hall_claim} fields fabricated" if (hall_fab is not None and hall_claim) else "",
            "tier": _hallucination_tier(hall_pct),
        },
    ]


def _fmt_duration(started: Optional[str], finished: Optional[str]) -> Optional[str]:
    from datetime import datetime
    if not started or not finished:
        return None
    try:
        s = datetime.fromisoformat(started)
        f = datetime.fromisoformat(finished)
    except ValueError:
        return None
    secs = max(0, int((f - s).total_seconds()))
    h, rem = divmod(secs, 3600)
    m, sec = divmod(rem, 60)
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {sec}s"
    return f"{sec}s"


def _build_detail_groups(manifest: Dict[str, Any], summary: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """Compact key/value groups mirroring the web UI's Technical / More details."""
    def rows(*pairs):
        return [{"k": k, "v": str(v)} for k, v in pairs if v not in (None, "", "null")]

    technical = [
        {"label": "Run", "rows": rows(
            ("Model", manifest.get("model")),
            ("Run ID", manifest.get("run_id")),
            ("Server", manifest.get("server")),
            ("Started", _format_started_at(manifest.get("started_at"))),
            ("Duration", _fmt_duration(manifest.get("started_at"), manifest.get("finished_at"))),
        )},
        {"label": "Scope", "rows": rows(
            ("Mode", manifest.get("mode")),
            ("Sample size", manifest.get("sample_size")),
            ("Input format", (manifest.get("input_format") or "").upper() or None),
            ("CSV folder", manifest.get("csv_dir")),
            ("Difficulty filter", manifest.get("difficulty_filter")),
            ("Test set filter", manifest.get("test_set_filter")),
        )},
        {"label": "Inference", "rows": rows(
            ("Context window", manifest.get("context_window")),
            ("Max output tokens", manifest.get("max_output_tokens")),
            ("Timeout", f"{manifest['timeout_s']} s" if manifest.get("timeout_s") is not None else None),
            ("Delay", f"{manifest['delay_s']} s" if manifest.get("delay_s") is not None else None),
        )},
    ]

    processed = summary.get("processed") or 0
    total = summary.get("total_files") or processed
    fp = summary.get("false_positives") or 0
    fn = summary.get("false_negatives") or 0
    miscount = fp + fn
    avg_score = summary.get("avg_score_20")
    avg_align = summary.get("avg_alignment")
    errs = summary.get("error") or 0
    ctx = summary.get("context_exceeded") or 0

    more = [
        {"label": "Corpus", "rows": rows(
            ("Total files", total),
            ("Processed", processed),
            ("Context skipped", ctx if ctx else None),
            ("Errors", errs if errs else None),
        )},
        {"label": "Accuracy", "rows": rows(
            ("Correct", f"{processed - miscount} of {total}" if processed else None),
            ("Misclassified", miscount if processed else None),
        )},
        {"label": "Quality", "rows": rows(
            ("Avg score", f"{avg_score:.1f} / 20" if isinstance(avg_score, (int, float)) else None),
            ("Evidence captured", f"{avg_align:.1f}%" if isinstance(avg_align, (int, float)) else None),
        )},
    ]
    # Drop empty groups so the layout stays tight.
    return {
        "technical": [g for g in technical if g["rows"]],
        "more": [g for g in more if g["rows"]],
    }


def _build_context(manifest: Dict[str, Any], csv_rows: List[Dict[str, str]],
                   ground_truth: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    summary = manifest.get("summary") or {}
    model = manifest.get("model") or "—"
    run_id = manifest.get("run_id") or ""
    started_at = _format_started_at(manifest.get("started_at"))
    server = manifest.get("server") or ""

    tiles = _build_tiles(summary)
    kpi_cards = _build_kpi_cards(summary)
    detail_groups = _build_detail_groups(manifest, summary)
    grade_dist = summary.get("grade_dist") or {}
    total_graded = sum(grade_dist.values()) if isinstance(grade_dist, dict) else 0
    confusion = _build_confusion(summary)

    findings, hidden = _build_findings(manifest.get("recommendations") or [])
    per_file = _build_per_file(csv_rows or [], ground_truth)
    run_config = _build_run_config(manifest)
    summary_sentence = _build_summary_sentence(summary, model)
    verdict = summary.get("verdict")

    return {
        "model": model,
        "run_id": run_id,
        "started_at": started_at,
        "server": server,
        "summary_sentence": summary_sentence,
        "verdict": verdict,
        "tiles": tiles,
        "kpi_cards": kpi_cards,
        "technical_groups": detail_groups["technical"],
        "more_groups": detail_groups["more"],
        "grade_dist": grade_dist,
        "total_graded": total_graded,
        "confusion": confusion,
        "findings": findings,
        "hidden_findings_count": hidden,
        "per_file": per_file,
        "run_config": run_config,
    }


# ── Chromium print ────────────────────────────────────────────────────────────

def _is_executable(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def _find_bundled_chromium() -> Optional[Path]:
    """Project-local Chromium (optional download under chromium/)."""
    fixed = [
        _CHROMIUM_DIR / "win64-1596606" / "chrome-win" / "chrome.exe",
        _CHROMIUM_DIR / "chrome.exe",
        _CHROMIUM_DIR / "mac" / "Chromium.app" / "Contents" / "MacOS" / "Chromium",
        _CHROMIUM_DIR / "linux" / "chrome",
    ]
    for c in fixed:
        if _is_executable(c):
            return c
    if not _CHROMIUM_DIR.exists():
        return None
    for pattern in ("chrome.exe", "headless_shell.exe", "chrome", "Chromium", "Google Chrome"):
        for p in _CHROMIUM_DIR.rglob(pattern):
            if _is_executable(p):
                return p
    return None


def _find_system_chromium() -> Optional[Path]:
    """Installed Chrome/Chromium on the host OS."""
    system = platform.system()
    candidates: List[Path] = []

    if system == "Darwin":
        candidates.extend([
            Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            Path("/Applications/Chromium.app/Contents/MacOS/Chromium"),
            Path("/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary"),
        ])
    elif system == "Windows":
        for env in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
            base = os.environ.get(env)
            if not base:
                continue
            candidates.extend([
                Path(base) / "Google" / "Chrome" / "Application" / "chrome.exe",
                Path(base) / "Chromium" / "Application" / "chrome.exe",
            ])
    else:
        for name in (
            "google-chrome-stable",
            "google-chrome",
            "chromium-browser",
            "chromium",
            "chrome",
        ):
            found = shutil.which(name)
            if found:
                candidates.append(Path(found))

    for path in candidates:
        if _is_executable(path):
            return path
    return None


def find_chromium() -> Optional[Path]:
    """Return a Chromium/Chrome binary suitable for headless print-to-pdf."""
    return _find_bundled_chromium() or _find_system_chromium()


def pdf_export_available() -> bool:
    return find_chromium() is not None


def chromium_setup_hint() -> str:
    system = platform.system()
    if system == "Darwin":
        return (
            "Install Google Chrome (https://www.google.com/chrome/) or place a "
            "Chromium.app under chromium/ in the project root."
        )
    if system == "Windows":
        return (
            "Install Google Chrome, or add bundled Chromium under "
            "chromium/win64-*/chrome-win/chrome.exe."
        )
    return (
        "Install google-chrome or chromium (package manager), or add a chrome "
        "binary under chromium/ in the project root."
    )


def _find_chromium() -> Optional[Path]:
    return find_chromium()


def _print_html_to_pdf(html_path: Path, pdf_path: Path) -> None:
    chrome = _find_chromium()
    if chrome is None:
        raise RuntimeError(
            "No Chromium/Chrome binary found for PDF export. "
            + chromium_setup_hint()
        )

    # Chromium resolves `--print-to-pdf=<rel>` against its own cwd, not the
    # caller's. Always pass an absolute path so the file lands where the
    # caller asked for it.
    abs_pdf = pdf_path.resolve()
    cmd = [
        str(chrome),
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--no-pdf-header-footer",
        "--print-to-pdf-no-header",
        "--virtual-time-budget=10000",
        f"--print-to-pdf={abs_pdf}",
        html_path.as_uri(),
    ]
    if platform.system() == "Windows":
        # When launched from an elevated (Administrator) process, Chrome on
        # Windows re-launches itself de-elevated and the process we started
        # exits immediately with rc=0 — before the PDF exists. This switch
        # keeps the print job in the process we wait on. (Observed with
        # Chromium 147: without it the PDF appeared ~8 s after return.)
        cmd.insert(1, "--do-not-de-elevate")
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if proc.returncode != 0 or not pdf_path.exists():
        raise RuntimeError(
            f"Chromium print-to-pdf failed (rc={proc.returncode}). "
            f"stderr: {proc.stderr.strip()[:400]}"
        )


# ── Public API ────────────────────────────────────────────────────────────────

def generate_pdf_report(manifest: Dict[str, Any],
                        csv_rows: List[Dict[str, str]],
                        pdf_path: Path,
                        ground_truth: Optional[Dict[str, Any]] = None) -> Path:
    """Render the run-level PDF from a manifest.

    Args:
        manifest: parsed run_manifest_*.json content.
        csv_rows: per-file rows from ``read_detection_csv`` (may be empty if
            the run didn't produce a CSV).
        pdf_path: destination .pdf file (overwritten if it exists).
        ground_truth: optional `{filename: entry}` map used to label the
            "Expected" column in the per-file appendix table.

    Returns: the resolved ``pdf_path``.
    """
    pdf_path = Path(pdf_path)
    pdf_path.parent.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("pdf_report.html")

    context = _build_context(manifest, csv_rows or [], ground_truth)
    html = template.render(**context)

    workdir = Path(tempfile.mkdtemp(prefix="forcastl_pdf_"))
    try:
        html_path = workdir / "report.html"
        html_path.write_text(html, encoding="utf-8")
        _print_html_to_pdf(html_path, pdf_path)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    return pdf_path
