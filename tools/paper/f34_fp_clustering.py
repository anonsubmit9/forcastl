"""F34: do false positives cluster on the 46 relabelled (attack-source) benign
cases versus the 63 native-benign (evtx-baseline) controls?

Join: metadata.json (source) x ground_truth_evidence.json (label) x
rescore_v1 manifests (per-file verdicts). Scopes: shared-120 and full corpus.
Clustering test: one-sided Fisher exact (relabelled enriched among FPs),
computed directly from the hypergeometric distribution (no scipy needed).
"""
import json
from math import comb
from pathlib import Path

import os
# Repository root: set FORCASTL_ROOT or run from <repo>/tools/paper/
REPO = Path(os.environ.get("FORCASTL_ROOT") or Path(__file__).resolve().parents[2])
ROOT = REPO
meta = json.load(open(ROOT / "data/metadata.json", encoding="utf-8"))["files"]
gt = json.load(open(ROOT / "data/ground_truth_evidence.json", encoding="utf-8"))
gt_files = gt.get("files", gt)

MODELS = {
    "claude-opus-4-8": "run_manifest_claude-opus-4-8_rescore_v1.json",
    "gpt-5.5-2026-04-23": "run_manifest_gpt-5.5-2026-04-23_rescore_v1.json",
    "qwen3.6-27b": "run_manifest_qwen3.6-27b_rescore_v1.json",
}
manifests = {k: json.load(open(ROOT / "outputs" / v, encoding="utf-8"))
             for k, v in MODELS.items()}
# Manifests store native-benign files with .csv extension; GT/metadata key by
# .evtx. Join on the stem, which is unique across the corpus.
by_model = {k: {Path(f["filename"]).stem: f for f in m["files"]}
            for k, m in manifests.items()}
shared = set.intersection(*[set(d) for d in by_model.values()])
meta = {Path(k).stem: v for k, v in meta.items()}
gt_files = {Path(k).stem: v for k, v in gt_files.items()}


def benign_group(fname):
    """'relabelled' | 'native' | None (not GT-benign)."""
    g = gt_files.get(fname)
    if not g or g.get("malicious") != "NO":
        return None
    src = meta.get(fname, {}).get("source")
    return "relabelled" if src == "folder_structure" else "native"


def fisher_one_sided(k, K, n, N):
    """P(X >= k), X ~ Hypergeom(N pop, K successes, n draws)."""
    return sum(comb(K, i) * comb(N - K, n - i) for i in range(k, min(K, n) + 1)) / comb(N, n)


def analyze(scope_name, fnames):
    groups = {f: benign_group(f) for f in fnames}
    ben = [f for f, g in groups.items() if g]
    n_rel = sum(1 for f in ben if groups[f] == "relabelled")
    n_nat = len(ben) - n_rel
    print(f"\n== {scope_name}: {len(ben)} benign in scope "
          f"({n_rel} relabelled, {n_nat} native) ==")
    for model, files in by_model.items():
        fps = []
        for f in ben:
            r = files.get(f)
            if r and r.get("status") == "processed" and r.get("malicious") is True:
                fps.append(f)
        completed_ben = [f for f in ben
                         if files.get(f, {}).get("status") == "processed"]
        c_rel = sum(1 for f in completed_ben if groups[f] == "relabelled")
        c_nat = len(completed_ben) - c_rel
        fp_rel = sum(1 for f in fps if groups[f] == "relabelled")
        fp_nat = len(fps) - fp_rel
        rate_rel = 100 * fp_rel / c_rel if c_rel else 0
        rate_nat = 100 * fp_nat / c_nat if c_nat else 0
        p = fisher_one_sided(fp_rel, c_rel, len(fps), len(completed_ben)) if fps else 1.0
        print(f"{model:<20} FP={len(fps):>2}  on relabelled: {fp_rel:>2}/{c_rel} "
              f"({rate_rel:.1f}%)   on native: {fp_nat:>2}/{c_nat} ({rate_nat:.1f}%)   "
              f"Fisher p={p:.4f}")
        if scope_name.startswith("shared"):
            for f in fps:
                print(f"      [{groups[f][:3]}] {f}")


analyze("shared-120", shared)
analyze("full corpus (each model's own scope)", set(gt_files))
