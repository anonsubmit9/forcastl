"""F32 round-trip validation + native-benign scoring.

Per-file max alert level from three Hayabusa scans:
  evtx     : native .evtx scan            (265 attack-source cases)   hayabusa_default.jsonl
  flat_ref : JSON dumped from the EVTX    (265)                        hayabusa_flat_ref.jsonl
  flat_csv : JSON rebuilt from EvtxECmd CSV (328 = 265 + 63 native benign) hayabusa_flat_csv.jsonl
Concordance of verdict-at-threshold between paths on the 265 shared cases validates
using flat_csv for the 63 native-benign cases that exist only as CSV.
Then: full-328 baseline = evtx path for the 265, flat_csv path for the 63.
"""
import json
from collections import defaultdict
from math import sqrt
from pathlib import Path

S = Path(__file__).parent / "f32"
import os
# Repository root: set FORCASTL_ROOT or run from <repo>/tools/paper/
REPO = Path(os.environ.get("FORCASTL_ROOT") or Path(__file__).resolve().parents[2])
ROOT = REPO
LEVELS = ["informational", "low", "medium", "high", "critical", "emergency"]; RANK = {l: i for i, l in enumerate(LEVELS)}
ABBR = {"info": "informational", "med": "medium", "crit": "critical", "emer": "emergency"}

gt = json.load(open(ROOT / "data/ground_truth_evidence.json", encoding="utf-8")); gt = gt.get("files", gt)
gt = {Path(k).stem: v for k, v in gt.items()}
meta = json.load(open(ROOT / "data/metadata.json", encoding="utf-8"))["files"]; meta = {Path(k).stem: v for k, v in meta.items()}
evtx = {p.stem for p in (ROOT / "data/evtx").rglob("*.evtx")}

def load(name, exclude_eids=()):
    per = defaultdict(lambda: -1); rules = defaultdict(set)
    for l in open(S / name, encoding="utf-8"):
        r = json.loads(l)
        if int(r["EventID"]) in exclude_eids: continue
        s = Path(r["EvtxFile"]).stem
        lvl = ABBR.get(r["Level"].lower(), r["Level"].lower())
        per[s] = max(per[s], RANK.get(lvl, -1)); rules[s].add((r["RuleTitle"], lvl))
    return per, rules

paths = {"evtx": load("hayabusa_default.jsonl"), "flat_ref": load("hayabusa_flat_ref.jsonl"), "flat_csv": load("hayabusa_flat_csv.jsonl")}
attack = sorted(s for s in gt if s in evtx); native = sorted(s for s in gt if s not in evtx)
print(f"attack-source cases: {len(attack)}   native benign (CSV only): {len(native)}")

print("\n== round-trip concordance on the 265 attack-source cases (verdict at threshold) ==")
for thr in ("medium", "high"):
    t = RANK[thr]
    for a, b in (("evtx", "flat_ref"), ("evtx", "flat_csv"), ("flat_ref", "flat_csv")):
        pa, pb = paths[a][0], paths[b][0]
        agree = sum(1 for s in attack if (pa[s] >= t) == (pb[s] >= t))
        only_a = [s for s in attack if pa[s] >= t and pb[s] < t]; only_b = [s for s in attack if pb[s] >= t and pa[s] < t]
        print(f">= {thr:<7} {a:>8} vs {b:<8}: agree {agree}/{len(attack)} ({100*agree/len(attack):.1f}%)  only-{a}: {len(only_a)}  only-{b}: {len(only_b)}")
        if a == "evtx" and b == "flat_csv":
            for s in only_a[:8]: print("      evtx-only :", s, "|", sorted(x for x, l in paths['evtx'][1][s] if RANK[l] >= t)[:3])
            for s in only_b[:8]: print("      csv-only  :", s, "|", sorted(x for x, l in paths['flat_csv'][1][s] if RANK[l] >= t)[:3])
same_exact = sum(1 for s in attack if paths["evtx"][0][s] == paths["flat_csv"][0][s])
print(f"exact max-level agreement evtx vs flat_csv: {same_exact}/{len(attack)}")

def wilson(k, n, z=1.96):
    if n == 0: return (0, 0)
    p = k/n; d = 1+z*z/n; c = (p+z*z/(2*n))/d; h = z*sqrt(p*(1-p)/n+z*z/(4*n*n))/d
    return (100*(c-h), 100*(c+h))

print("\n== native-benign baselines (63, CSV-only, flat_csv path) ==")
pc, rc = paths["flat_csv"]
for thr in ("informational", "low", "medium", "high"):
    t = RANK[thr]; fp = [s for s in native if pc[s] >= t]
    lo, hi = wilson(len(fp), len(native))
    print(f">= {thr:<13} FP {len(fp):>2}/{len(native)}  FPR {100*len(fp)/len(native):5.1f}%  CI {lo:.1f}-{hi:.1f}")
    if thr in ("medium", "high"):
        for s in fp: print("      ", s, "|", sorted(x for x, l in rc[s] if RANK[l] >= t)[:4])

print("\n== combined 328-case baseline: evtx path for 265, flat_csv path for 63 native benign ==")
comb = {s: (paths["evtx"][0][s] if s in evtx else pc[s]) for s in gt}
mal = [s for s in gt if gt[s]["malicious"] == "YES"]; ben = [s for s in gt if gt[s]["malicious"] == "NO"]
rel = [s for s in ben if meta[s]["source"] == "folder_structure"]; nat = [s for s in ben if meta[s]["source"] != "folder_structure"]
print(f"{'threshold':<16}{'TP':>4}{'FN':>4}{'FP':>4}{'TN':>4}  {'recall':>7} {'[CI]':>12}  {'FPR all':>8} {'[CI]':>12}  {'FPR relab':>10}  {'FPR native':>11}  {'prec':>6}")
for thr in ("low", "medium", "high"):
    t = RANK[thr]
    tp = sum(1 for s in mal if comb[s] >= t); fn = len(mal) - tp
    fp = sum(1 for s in ben if comb[s] >= t); tn = len(ben) - fp
    fpr_r = sum(1 for s in rel if comb[s] >= t); fpr_n = sum(1 for s in nat if comb[s] >= t)
    rl, rh = wilson(tp, len(mal)); fl, fh = wilson(fp, len(ben))
    print(f">= {thr:<13}{tp:>4}{fn:>4}{fp:>4}{tn:>4}  {100*tp/len(mal):6.1f}% [{rl:4.1f}-{rh:4.1f}]  {100*fp/len(ben):7.1f}% [{fl:4.1f}-{fh:4.1f}]  {fpr_r:>3}/{len(rel)} {100*fpr_r/len(rel):5.1f}%  {fpr_n:>3}/{len(nat)} {100*fpr_n/len(nat):5.1f}%  {100*tp/(tp+fp):5.1f}%")

# comparison-set (120) with the combined baseline
def stems(name):
    m = json.load(open(ROOT / "outputs" / name, encoding="utf-8")); return {Path(f["filename"]).stem for f in m["files"]}
shared = stems("run_manifest_claude-opus-4-8_rescore_v1.json") & stems("run_manifest_gpt-5.5-2026-04-23_rescore_v1.json") & stems("run_manifest_qwen3.6-27b_rescore_v1.json")
print(f"\n== 120-case comparison set, combined baseline ({len(shared)} cases) ==")
mal = [s for s in shared if gt[s]["malicious"] == "YES"]; ben = [s for s in shared if gt[s]["malicious"] == "NO"]
rel = [s for s in ben if meta[s]["source"] == "folder_structure"]; nat = [s for s in ben if meta[s]["source"] != "folder_structure"]
print(f"malicious {len(mal)}, benign {len(ben)} (relabelled {len(rel)}, native {len(nat)})")
for thr in ("low", "medium", "high"):
    t = RANK[thr]
    tp = sum(1 for s in mal if comb[s] >= t); fn = len(mal) - tp
    fp = sum(1 for s in ben if comb[s] >= t); tn = len(ben) - fp
    fpr_r = sum(1 for s in rel if comb[s] >= t); fpr_n = sum(1 for s in nat if comb[s] >= t)
    rl, rh = wilson(tp, len(mal)); fl, fh = wilson(fp, len(ben))
    print(f">= {thr:<13}{tp:>4}{fn:>4}{fp:>4}{tn:>4}  {100*tp/len(mal):6.1f}% [{rl:4.1f}-{rh:4.1f}]  {100*fp/len(ben):7.1f}% [{fl:4.1f}-{fh:4.1f}]  {fpr_r:>3}/{len(rel)} {100*fpr_r/len(rel):5.1f}%  {fpr_n:>3}/{len(nat)} {100*fpr_n/len(nat):5.1f}%  {100*tp/(tp+fp):5.1f}%")
json.dump({s: comb[s] for s in gt}, open(S / "sigma_combined_maxlevel.json", "w"), indent=0)
