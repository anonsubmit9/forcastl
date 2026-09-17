"""F32: LLM deployments vs Hayabusa on IDENTICAL case slices.
Slices: (a) 265 attack-source EVTX cases; (b) the 85 comparison-set cases with EVTX.
Sigma variants: default; excluding pure log-clear events (EID 1102/104), which are a
dataset-construction artifact (logs cleared before each capture)."""
import json
from collections import defaultdict
from math import sqrt
from pathlib import Path

import os
# Repository root: set FORCASTL_ROOT or run from <repo>/tools/paper/
REPO = Path(os.environ.get("FORCASTL_ROOT") or Path(__file__).resolve().parents[2])
ROOT = REPO
NEW = REPO / "outputs"
SP = Path(__file__).parent
LEVELS = ["informational", "low", "medium", "high", "critical", "emergency"]; RANK = {l: i for i, l in enumerate(LEVELS)}
ABBR = {"info": "informational", "med": "medium", "crit": "critical", "emer": "emergency"}

gt = json.load(open(ROOT / "data/ground_truth_evidence.json", encoding="utf-8")); gt = gt.get("files", gt)
gt = {Path(k).stem: v for k, v in gt.items()}
evtx = {p.stem for p in (ROOT / "data/evtx").rglob("*.evtx")}

MODELS = {
    "Claude Opus 4.8": ROOT / "outputs/run_manifest_claude-opus-4-8_rescore_v1.json",
    "GPT-5.5": ROOT / "outputs/run_manifest_gpt-5.5-2026-04-23_rescore_v1.json",
    "Qwen3.6-27B": ROOT / "outputs/run_manifest_qwen3.6-27b_rescore_v1.json",
    "Qwen3.8-Flash-Next": NEW / "run_manifest_Qwen3.8-Flash-Next-MLX-Serve-4bit_20260901_123829.json",
    "Qwen3.6-35B-A3B": NEW / "run_manifest_Qwen3.6-35B-A3B-UD-Q4_K_M.gguf_20260901_144311.json",
}
verd = {}
for m, p in MODELS.items():
    d = json.load(open(p, encoding="utf-8"))
    verd[m] = {Path(f["filename"]).stem: f for f in d["files"]}
shared = set(verd["Claude Opus 4.8"]) & set(verd["GPT-5.5"]) & set(verd["Qwen3.6-27B"])

def load_sigma(exclude_eids=()):
    per = defaultdict(lambda: -1)
    for l in open(SP / "f32/hayabusa_default.jsonl", encoding="utf-8"):
        r = json.loads(l)
        if int(r["EventID"]) in exclude_eids: continue
        lvl = ABBR.get(r["Level"].lower(), r["Level"].lower())
        s = Path(r["EvtxFile"]).stem
        per[s] = max(per[s], RANK.get(lvl, -1))
    return per
sig = {"Sigma (default)": load_sigma(), "Sigma (excl. EID 1102/104)": load_sigma((1102, 104))}

def wilson(k, n, z=1.96):
    if n == 0: return (0, 0)
    p = k/n; d = 1+z*z/n; c = (p+z*z/(2*n))/d; h = z*sqrt(p*(1-p)/n+z*z/(4*n*n))/d
    return (100*(c-h), 100*(c+h))

def fmt(tp, fn, fp, tn, fail_m, fail_b):
    nm = tp+fn+fail_m; nb_done = fp+tn
    rec = 100*tp/nm; rl, rh = wilson(tp, nm)          # failure-aware: failed malicious = miss
    fpr = 100*fp/nb_done if nb_done else 0; fl, fh = wilson(fp, nb_done)
    prec = 100*tp/(tp+fp) if tp+fp else 0
    return f"{tp:>4}{fn:>4}{fp:>4}{tn:>4}{fail_m+fail_b:>5}   {rec:>6.1f}% [{rl:4.1f}-{rh:4.1f}]  {fpr:>6.1f}% [{fl:4.1f}-{fh:4.1f}]  {prec:>5.1f}%"

def table(name, cases):
    mal = [s for s in cases if gt[s]["malicious"] == "YES"]; ben = [s for s in cases if gt[s]["malicious"] == "NO"]
    print(f"\n== {name}: {len(cases)} cases ({len(mal)} malicious, {len(ben)} relabelled benign) ==")
    print(f"{'system':<40}{'TP':>4}{'FN':>4}{'FP':>4}{'TN':>4}{'fail':>5}   {'recall':>7} {'[95% CI]':>12} {'FPR':>8} {'[95% CI]':>12} {'prec':>7}")
    for m, d in verd.items():
        if not all(s in d for s in cases):
            cov = sum(1 for s in cases if s in d)
            if cov == 0: continue
            print(f"{m:<40} (covers {cov}/{len(cases)} cases; skipped)"); continue
        tp = sum(1 for s in mal if d[s]["status"] == "processed" and d[s]["malicious"] is True)
        fm = sum(1 for s in mal if d[s]["status"] != "processed"); fn = len(mal) - tp - fm
        fp = sum(1 for s in ben if d[s]["status"] == "processed" and d[s]["malicious"] is True)
        fb = sum(1 for s in ben if d[s]["status"] != "processed"); tn = len(ben) - fp - fb
        print(f"{m:<40}" + fmt(tp, fn, fp, tn, fm, fb))
    for sname, per in sig.items():
        for thr in ("medium", "high"):
            t = RANK[thr]
            tp = sum(1 for s in mal if per[s] >= t); fn = len(mal) - tp
            fp = sum(1 for s in ben if per[s] >= t); tn = len(ben) - fp
            print(f"{sname + ' >= ' + thr:<40}" + fmt(tp, fn, fp, tn, 0, 0))

table("all attack-source EVTX cases", sorted(s for s in gt if s in evtx))
table("comparison-set cases with EVTX", sorted(s for s in shared if s in evtx))
