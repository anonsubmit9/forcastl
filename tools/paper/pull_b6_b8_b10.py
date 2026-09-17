"""B6/B8/B10 data pulls from the recovered June run manifests.

B6: unsupported (hallucinated) structured values / total claimed, per model.
B8: full-corpus FP rates + benign counts.
B10: per-file failure statuses for non-processed cases.
"""
import json
from pathlib import Path

import os
# Repository root: set FORCASTL_ROOT or run from <repo>/tools/paper/
REPO = Path(os.environ.get("FORCASTL_ROOT") or Path(__file__).resolve().parents[2])
OUT = REPO / "outputs"

RUNS = {
    "claude-opus-4-8 (canonical 0612_170300)": "run_manifest_claude-opus-4-8_20260612_170300.json",
    "gpt-5.5 (canonical 0613_123806)": "run_manifest_gpt-5.5-2026-04-23_20260613_123806.json",
    "qwen3.6-27b (canonical 0615_194908)": "run_manifest_qwen3.6-27b_20260615_194908.json",
    "claude-opus-4-8 (rescore_v1)": "run_manifest_claude-opus-4-8_rescore_v1.json",
    "gpt-5.5 (rescore_v1)": "run_manifest_gpt-5.5-2026-04-23_rescore_v1.json",
    "qwen3.6-27b (rescore_v1)": "run_manifest_qwen3.6-27b_rescore_v1.json",
}

for label, fn in RUNS.items():
    p = OUT / fn
    if not p.exists():
        print(f"\n### {label}: MISSING ({fn})")
        continue
    m = json.load(open(p, encoding="utf-8"))
    s = m["summary"]
    files = m.get("files", [])
    print(f"\n### {label}")
    print(f"  scoring_version={m.get('scoring_version')}  mode={m.get('mode')}  "
          f"total={s.get('total_files')}  processed={s.get('processed')}")
    print(f"  B8: mal_in_scope={s.get('total_malicious_in_scope')}  "
          f"ben_in_scope={s.get('total_benign_in_scope')}  "
          f"TP={s.get('true_positives')} TN={s.get('true_negatives')} "
          f"FP={s.get('false_positives')} FN={s.get('false_negatives')}")
    print(f"      recall={s.get('recall_pct'):.2f}%  fp_rate={s.get('fp_rate_pct'):.2f}%  "
          f"fp_ci={s.get('fp_rate_ci_pct')}  avg_align20={s.get('avg_score_20'):.2f}")
    hal, clm = s.get("total_hallucinated_fields"), s.get("total_claimed_fields")
    n_proc = s.get("processed") or 1
    print(f"  B6: hallucinated={hal}  claimed={clm}  "
          f"rate={100*hal/clm:.3f}%  mean_claims_per_processed_case={clm/n_proc:.1f}")
    bad = [f for f in files if f.get("status") != "processed"]
    print(f"  B10: {len(bad)} non-processed file(s):")
    for f in bad:
        print(f"      [{f.get('status')}] {f.get('filename')}")
