"""F32: score Hayabusa (Sigma) as a deterministic baseline against FORCAST-L GT.

Per-file verdict = "any detection at or above threshold L" for L in
{informational, low, medium, high, critical}. Scored on:
  (a) all 265 attack-source EVTX cases (219 malicious, 46 relabelled benign)
  (b) the 120-case comparison set restricted to cases with an EVTX (85: 60 mal, 25 relabelled benign)
The 63 native-benign baselines have no EVTX in the checkout (CSV only) -> NOT SCANNED.
"""
import json, sys
from collections import Counter, defaultdict
from math import sqrt
from pathlib import Path

import os
# Repository root: set FORCASTL_ROOT or run from <repo>/tools/paper/
REPO = Path(os.environ.get("FORCASTL_ROOT") or Path(__file__).resolve().parents[2])
ROOT = REPO
JSONL = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "f32/hayabusa_default.jsonl"
LEVELS = ["informational", "low", "medium", "high", "critical", "emergency"]
RANK = {l: i for i, l in enumerate(LEVELS)}

gt = json.load(open(ROOT / "data/ground_truth_evidence.json", encoding="utf-8")); gt = gt.get("files", gt)
meta = json.load(open(ROOT / "data/metadata.json", encoding="utf-8"))["files"]
gt = {Path(k).stem: v for k, v in gt.items()}
meta = {Path(k).stem: v for k, v in meta.items()}
evtx = {p.stem for p in (ROOT / "data/evtx").rglob("*.evtx")}

# comparison set = files in all three June manifests
def stems(name):
    m = json.load(open(ROOT / "outputs" / name, encoding="utf-8"))
    return {Path(f["filename"]).stem for f in m["files"]}
shared = stems("run_manifest_claude-opus-4-8_rescore_v1.json") & stems("run_manifest_gpt-5.5-2026-04-23_rescore_v1.json") & stems("run_manifest_qwen3.6-27b_rescore_v1.json")

# parse detections
per_file = defaultdict(Counter)     # stem -> Counter(level)
rules = defaultdict(set)
n = 0
with open(JSONL, encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        r = json.loads(line); n += 1
        if n == 1:
            print("record keys:", list(r)[:20])
        ev = r.get("EvtxFile") or r.get("evtx_file") or ""
        stem = Path(ev).stem
        lvl = (r.get("Level") or "").lower()
        # hayabusa abbreviates levels in some profiles: info/low/med/high/crit/emer
        lvl = {"info": "informational", "med": "medium", "crit": "critical", "emer": "emergency"}.get(lvl, lvl)
        per_file[stem][lvl] += 1
        rules[stem].add(r.get("RuleTitle"))
print(f"detections parsed: {n}; files with >=1 detection: {len(per_file)}")
print("level vocabulary:", sorted({l for c in per_file.values() for l in c}))

def wilson(k, m, z=1.96):
    if m == 0: return (0.0, 0.0)
    p = k / m; d = 1 + z*z/m; c = (p + z*z/(2*m)) / d; h = z*sqrt(p*(1-p)/m + z*z/(4*m*m)) / d
    return (100*(c-h), 100*(c+h))

def max_level(stem):
    c = per_file.get(stem)
    if not c: return -1
    return max(RANK.get(l, -1) for l in c)

def score(scope_name, cases):
    mal = [s for s in cases if gt[s]["malicious"] == "YES"]
    ben = [s for s in cases if gt[s]["malicious"] == "NO"]
    print(f"\n== {scope_name}: {len(cases)} cases ({len(mal)} malicious, {len(ben)} benign; "
          f"benign by source: {dict(Counter(meta[s]['source'] for s in ben))}) ==")
    print(f"{'threshold':<16}{'TP':>4}{'FN':>4}{'FP':>4}{'TN':>4}   {'recall':>8} {'95% CI':>13}   {'FPR':>7} {'95% CI':>13}   {'prec':>6}")
    for thr in ["informational", "low", "medium", "high", "critical"]:
        t = RANK[thr]
        tp = sum(1 for s in mal if max_level(s) >= t); fn = len(mal) - tp
        fp = sum(1 for s in ben if max_level(s) >= t); tn = len(ben) - fp
        rec = 100*tp/len(mal); fpr = 100*fp/len(ben) if ben else 0
        prec = 100*tp/(tp+fp) if tp+fp else 0
        rlo, rhi = wilson(tp, len(mal)); flo, fhi = wilson(fp, len(ben))
        print(f">= {thr:<13}{tp:>4}{fn:>4}{fp:>4}{tn:>4}   {rec:>7.1f}% {rlo:>5.1f}-{rhi:<5.1f}   {fpr:>6.1f}% {flo:>5.1f}-{fhi:<5.1f}   {prec:>5.1f}%")
    return mal, ben

cases_all = [s for s in gt if s in evtx]
score("all attack-source EVTX cases", cases_all)
cases_cmp = [s for s in shared if s in evtx]
print(f"\n(comparison set has {len(shared)} cases; {len(shared)-len(cases_cmp)} native-benign without EVTX excluded)")
mal_c, ben_c = score("comparison-set cases with EVTX", cases_cmp)

# misses at >= medium, for the write-up
t = RANK["medium"]
missed = [s for s in cases_all if gt[s]["malicious"] == "YES" and max_level(s) < t]
print(f"\nmalicious cases with no detection >= medium: {len(missed)}")
for s in sorted(missed)[:40]:
    print("   ", s, "| max level:", LEVELS[max_level(s)] if max_level(s) >= 0 else "none", "| difficulty:", gt[s].get("difficulty"))
fp_med = [s for s in cases_all if gt[s]["malicious"] == "NO" and max_level(s) >= t]
print(f"\nrelabelled-benign cases with a detection >= medium: {len(fp_med)}")
for s in sorted(fp_med):
    print("   ", s, "|", ", ".join(sorted(rules[s]))[:120])

# overlap with model FPs on the comparison set (from rescore manifests)
def model_fps(name):
    m = json.load(open(ROOT / "outputs" / name, encoding="utf-8"))
    return {Path(f["filename"]).stem for f in m["files"] if f["status"] == "processed" and f["malicious"] is True and gt.get(Path(f["filename"]).stem, {}).get("malicious") == "NO"}
for label, name in [("Claude", "run_manifest_claude-opus-4-8_rescore_v1.json"), ("GPT", "run_manifest_gpt-5.5-2026-04-23_rescore_v1.json"), ("Qwen27B", "run_manifest_qwen3.6-27b_rescore_v1.json")]:
    fps = model_fps(name) & set(cases_cmp)
    both = fps & set(fp_med)
    print(f"{label}: comparison-set FPs on relabelled cases = {len(fps)}; also Sigma>=medium FP = {len(both)}")
