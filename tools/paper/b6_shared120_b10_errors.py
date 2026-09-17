"""B6 at shared-120 scope + B10 error-string classification.

Shared set = files present in all three rescore_v1 manifests (paper's
apples-to-apples basis, per tools/paper_tables_shared120.py).
"""
import json
from pathlib import Path

import os
# Repository root: set FORCASTL_ROOT or run from <repo>/tools/paper/
REPO = Path(os.environ.get("FORCASTL_ROOT") or Path(__file__).resolve().parents[2])
OUT = REPO / "outputs"
MODELS = {
    "claude-opus-4-8": "run_manifest_claude-opus-4-8_rescore_v1.json",
    "gpt-5.5-2026-04-23": "run_manifest_gpt-5.5-2026-04-23_rescore_v1.json",
    "qwen3.6-27b": "run_manifest_qwen3.6-27b_rescore_v1.json",
}

manifests = {k: json.load(open(OUT / v, encoding="utf-8")) for k, v in MODELS.items()}
by_model = {k: {f["filename"]: f for f in m["files"]} for k, m in manifests.items()}
shared = set.intersection(*[set(d) for d in by_model.values()])
print(f"shared file set: {len(shared)}")

print("\n== B6 on shared set (processed files only) ==")
for k, d in by_model.items():
    proc = [f for f in (d[s] for s in shared) if f.get("status") == "processed"]
    hal = sum(f.get("hallucinated_fields") or 0 for f in proc)
    clm = sum(f.get("claimed_fields") or 0 for f in proc)
    print(f"{k:<22} processed={len(proc):>3}  unsupported={hal:>3}  claimed={clm:>5}  "
          f"rate={100*hal/clm:.3f}%  mean_claims/case={clm/len(proc):.1f}")

print("\n== B10 error strings (all non-processed, full manifests) ==")
for k, m in manifests.items():
    print(f"\n-- {k}")
    for f in m["files"]:
        if f.get("status") != "processed":
            err = (f.get("error") or "")[:160].replace("\n", " ")
            print(f"  [{f['status']}] {f['filename']}")
            print(f"      err: {err}")
            print(f"      rt={f.get('response_time_s')}")
