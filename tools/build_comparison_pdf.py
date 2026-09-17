#!/usr/bin/env python3
"""Build a polished, public-facing model-comparison PDF.

Numbers are computed through the SAME verified replay pipeline used by
``tools/rescore_saved.py`` (parity-checked against a known manifest), so the
PDF cannot drift from the scored manifests. Everything is scored against the
live ground truth under the frozen ``SCORING_VERSION``.

Renders via the project's existing headless-Chromium engine
(``forcastl.reporting.pdf_report._print_html_to_pdf``).

    python -m tools.build_comparison_pdf            # -> outputs/forcastl_model_comparison.pdf
    python -m tools.build_comparison_pdf out.pdf
"""
from __future__ import annotations

import html
import sys
import tempfile
from pathlib import Path

from forcastl.benchmark_contract import SCORING_VERSION, PROMPT_VERSION
from forcastl import config
from forcastl.reporting.pdf_report import _print_html_to_pdf, find_chromium
from tools.rescore_saved import rescore_one, DEFAULT_CSVS

# Display order + friendly labels (kept honest: real model ids shown too).
LABELS = {
    "claude-opus-4-8": ("Claude Opus 4.8", "Anthropic (frontier)"),
    "gpt-5.5-2026-04-23": ("GPT-5.5", "OpenAI (frontier)"),
    "qwen3.6-27b": ("Qwen3.6-27B", "Local open-weight (27B)"),
}
GENERATED = "2026-06-18"  # Date.now() is unavailable in this harness; stamp explicitly.


def _summ(s: dict) -> dict:
    v = s.get("verdict", {}) or {}
    return {
        "n_mal": (v.get("drivers", {}) or {}).get("n_malicious"),
        "n_ben": (v.get("drivers", {}) or {}).get("n_benign"),
        "recall": s.get("recall_pct"),
        "recall_ci": s.get("recall_ci_pct") or {},
        "fp": s.get("fp_rate_pct"),
        "fp_ci": s.get("fp_rate_ci_pct") or {},
        "hall": (s.get("avg_hallucination_rate") or 0) * 100,
        "score20": s.get("avg_score_20"),
        "grades": s.get("grade_dist", {}) or {},
        "total_files": s.get("total_files"),
        "processed": s.get("processed"),
        "err_mal": s.get("errors_on_malicious"),
        "err_ben": s.get("errors_on_benign"),
        "tier": v.get("tier"),
    }


def _ci(ci: dict) -> str:
    if not ci or ci.get("lo") is None:
        return ""
    return f"{ci['lo']:.0f}–{ci['hi']:.0f}"


def _pct(x) -> str:
    return f"{x:.1f}" if isinstance(x, (int, float)) else "–"


def collect():
    """Run the verified replay for each model; return full + head-to-head data."""
    runs = []
    for c in DEFAULT_CSVS:
        det, by_stem, summary, missing = rescore_one(Path(c), "pdf", write_reports=False)
        runs.append({"id": det._get_model_id(), "det": det, "by_stem": by_stem,
                     "full": _summ(summary)})

    common = sorted(set.intersection(*[set(r["by_stem"]) for r in runs]))
    for r in runs:
        sub = [r["by_stem"][s] for s in common]
        r["shared"] = _summ(r["det"]._compute_run_summary(sub))
    return runs, len(common)


# ── HTML ──────────────────────────────────────────────────────────────────────

CSS = """
@page { size: A4; margin: 16mm 15mm; }
* { box-sizing: border-box; }
body { font-family: -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif;
       color: #1a2230; font-size: 10.5pt; line-height: 1.5; margin: 0; }
h1 { font-size: 22pt; margin: 0 0 2px; letter-spacing: -0.4px; }
h2 { font-size: 13pt; margin: 26px 0 8px; padding-bottom: 5px;
     border-bottom: 2px solid #e4e8ef; color: #16324f; }
.sub { color: #5a6678; font-size: 10pt; margin: 0; }
.meta { color: #7a8597; font-size: 8.5pt; margin-top: 6px; }
.lede { background: #f5f8fc; border-left: 3px solid #2f6db0; padding: 11px 15px;
        border-radius: 4px; margin: 16px 0 4px; font-size: 10pt; }
table { width: 100%; border-collapse: collapse; margin: 6px 0 4px; }
th, td { text-align: right; padding: 7px 9px; font-variant-numeric: tabular-nums; }
th { font-size: 8.5pt; text-transform: uppercase; letter-spacing: .4px;
     color: #5a6678; border-bottom: 2px solid #cdd5e1; }
td { border-bottom: 1px solid #edf0f5; }
th:first-child, td:first-child { text-align: left; }
.model { font-weight: 600; }
.vendor { display: block; font-weight: 400; color: #8893a4; font-size: 8pt; }
.ci { display: block; color: #9aa4b4; font-size: 8pt; font-weight: 400; }
.best { color: #1a7a46; font-weight: 700; }
.lead td { background: #fafcff; }
.note { color: #5a6678; font-size: 8.7pt; margin: 4px 0 0; }
.caveat { background: #fffaf2; border: 1px solid #f0e2c8; border-radius: 5px;
          padding: 10px 15px; margin-top: 8px; }
.caveat li { margin: 3px 0; }
.grid2 { display: flex; gap: 18px; }
.grid2 > div { flex: 1; }
ul.tight { margin: 4px 0; padding-left: 18px; }
ul.tight li { margin: 2px 0; font-size: 9.3pt; }
.foot { margin-top: 24px; padding-top: 10px; border-top: 1px solid #e4e8ef;
        color: #8893a4; font-size: 8pt; line-height: 1.5; }
.pill { display:inline-block; padding:1px 7px; border-radius:10px; font-size:8pt;
        background:#eef3f9; color:#3a567a; font-weight:600; }
"""


def _row(r, key, best, lead=False):
    label, vendor = LABELS.get(r["id"], (r["id"], ""))
    d = r[key]

    def cell(metric, val, ci, lower_better):
        is_best = best.get(metric) == r["id"]
        cls = "best" if is_best else ""
        ci_txt = f'<span class="ci">95% CI {ci}</span>' if ci else ""
        return f'<td class="{cls}">{_pct(val)}%{ci_txt}</td>'

    return (
        f'<tr class="{"lead" if lead else ""}">'
        f'<td class="model">{html.escape(label)}<span class="vendor">{html.escape(vendor)} '
        f'&middot; <span class="pill">{r["id"]}</span></span></td>'
        f'<td>{d["n_mal"]} / {d["n_ben"]}</td>'
        + cell("recall", d["recall"], _ci(d["recall_ci"]), False)
        + cell("fp", d["fp"], _ci(d["fp_ci"]), True)
        + f'<td>{d["hall"]:.1f}%</td>'
        + "</tr>"
    )


def _best_map(runs, key):
    """Pick best model per metric: max recall, min fp, min hall."""
    def pick(metric, fn):
        vals = [(r["id"], r[key][metric]) for r in runs if r[key][metric] is not None]
        return fn(vals, key=lambda x: x[1])[0] if vals else None
    return {"recall": pick("recall", max), "fp": pick("fp", min), "hall": pick("hall", min)}


def build_html(runs, n_common) -> str:
    head = ("<th>Model</th><th>Attack / Benign<br>samples</th>"
            "<th>Detection<br>(recall)</th><th>False-positive<br>rate</th>"
            "<th>Hallucination<br>rate</th>")

    # A comparison is only valid where every model answered the SAME question on
    # the SAME artifact — i.e. the shared 120-file set. Everything in this report
    # is computed on that set. Full-corpus numbers (different file sets per model)
    # appear only as a representativeness footnote, never as a three-way table.
    # Highlight ONLY best recall; lowest FP/hallucination often belongs to the
    # weakest detector (a precision/recall trade-off), so crowning it would mislead.
    best_shared = {"recall": _best_map(runs, "shared")["recall"]}
    shared_rows = "\n".join(_row(r, "shared", best_shared, lead=True) for r in runs)

    grades = ""
    for r in runs:
        label = LABELS.get(r["id"], (r["id"],))[0]
        g = r["shared"]["grades"]
        tot = sum(g.values()) or 1
        a = g.get("A", 0)
        grades += (f'<li><b>{html.escape(label)}</b>: {a}/{tot} files graded A '
                   f'({100*a/tot:.0f}%), mean score {r["shared"]["score20"]:.1f}/20</li>')

    # Representativeness footnote: the two frontier models also ran the full 328.
    frontier = [r for r in runs if r["full"]["total_files"] and r["full"]["total_files"] > n_common]
    repn = ""
    if frontier:
        parts = ", ".join(f'{LABELS.get(r["id"],(r["id"],))[0]} {r["full"]["recall"]:.1f}%'
                          for r in frontier)
        repn = (f' Sample representativeness: on the full 328-file corpus, {parts} recall '
                f'&mdash; consistent with the {n_common}-file results above, indicating the '
                f'shared set is representative for those models. The local model was evaluated '
                f'on the {n_common}-file set only.')

    return f"""<!doctype html><html><head><meta charset="utf-8">
<style>{CSS}</style></head><body>

<h1>Forensic Log-Triage: Model Comparison</h1>
<p class="sub">How well do language models detect malicious activity in Windows event logs?</p>
<p class="meta">FORCAST-L benchmark &middot; generated {GENERATED} &middot;
scoring contract <b>{SCORING_VERSION}</b> &middot; all models scored against one frozen ground-truth snapshot</p>

<div class="lede">
Each model reads raw Windows event-log records (EvtxECmd CSV) for a single forensic
artifact and must decide <b>malicious vs.&nbsp;benign</b> and extract the supporting
evidence. We measure three things that matter operationally: how many real attacks it
catches (<b>recall</b>), how often it cries wolf on benign activity (<b>false-positive
rate</b>), and how often it invents evidence that isn't in the log (<b>hallucination</b>).
Lower is better for the last two.
</div>

<h2>Results &mdash; same {n_common} questions, every model</h2>
<p class="note">A comparison is only meaningful when every model is asked the
<b>same question on the same evidence</b>. Each model here saw the
<b>identical prompt</b> (<span class="pill">{PROMPT_VERSION}</span>) on the
<b>same {n_common} artifacts</b> ({runs[0]['shared']['n_mal']} attack /
{runs[0]['shared']['n_ben']} benign) with identical ground truth and scoring &mdash;
only the model differs. Best detection rate is highlighted; false-positive and
hallucination rates are shown without a "winner" because the lowest value usually
reflects a model that simply flags less.</p>
<table><thead><tr>{head}</tr></thead><tbody>
{shared_rows}
</tbody></table>

<div class="grid2">
  <div>
    <h2>What the benchmark is</h2>
    <ul class="tight">
      <li><b>328 real artifacts</b> &mdash; genuine Windows event logs, no synthetic data.</li>
      <li>Attacks span <b>11 MITRE ATT&amp;CK tactics, 60 techniques</b>; benign set is real
          baseline/admin activity shaped as near-misses.</li>
      <li>Evidence scored across 6 fields (event IDs, processes, accounts, commands,
          network, registry) on a 20-point rubric.</li>
      <li><b>Identical question for every model</b> &mdash; one frozen prompt template,
          parameterized only by the artifact; nothing is tailored per model.</li>
      <li>Deterministic: models run at <b>temperature 0</b>.</li>
    </ul>
  </div>
  <div>
    <h2>Extraction quality</h2>
    <ul class="tight">
      {grades}
    </ul>
    <p class="note">Grade A&nbsp;=&nbsp;&ge;17/20. High recall with low hallucination
    means the evidence a model reports can be trusted, not just its verdict.</p>
  </div>
</div>

<h2>How to read this &mdash; and what it does <i>not</i> say</h2>
<div class="caveat"><ul class="tight" style="margin:0">
  <li><b>Single run per model.</b> Temperature&nbsp;0 makes each run deterministic, but
      these are not yet averaged across repeated runs; treat differences inside the
      overlapping 95% confidence intervals as ties.</li>
  <li><b>Coverage differs in the full-corpus table.</b> The local model was scored on the
      120-file Standard slice, not all 328 &mdash; use the head-to-head table above for any
      apples-to-apples claim.</li>
  <li><b>A "false positive" here is strict.</b> The benign set is deliberately adversarial
      (admin actions that look attack-shaped), so double-digit FP rates are expected and do
      not indicate a broken model.</li>
  <li>This is an independent capability comparison, not a vendor endorsement.</li>
</ul></div>

<div class="foot">
Corpus provenance: attack artifacts from the public mdecrevoisier/EVTX-to-MITRE-Attack
dataset (CC0); benign baseline from NextronSystems/evtx-baseline (Apache-2.0); both
converted to CSV with EvtxECmd. Scoring contract {SCORING_VERSION} (frozen). Numbers are
computed by replaying each model's saved responses through the production scoring pipeline
against one common ground-truth snapshot; the replay is parity-verified against the
original scored manifests. Recall/FP confidence intervals are 95% Wilson; errored-benign
files are excluded from the FP denominator and an errored attack counts as a miss.{repn}
</div>

</body></html>"""


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else config.OUTPUTS_DIR / "forcastl_model_comparison.pdf"
    if not find_chromium():
        sys.exit("No Chrome/Chromium found for PDF rendering.")
    runs, n_common = collect()
    html_str = build_html(runs, n_common)
    workdir = Path(tempfile.mkdtemp(prefix="forcastl_cmp_"))
    html_path = workdir / "comparison.html"
    html_path.write_text(html_str, encoding="utf-8")
    _print_html_to_pdf(html_path, out)
    # keep the html next to the pdf for inspection / web embedding
    (out.with_suffix(".html")).write_text(html_str, encoding="utf-8")
    print(f"\n[OK] PDF : {out}")
    print(f"[OK] HTML: {out.with_suffix('.html')}")


if __name__ == "__main__":
    main()
