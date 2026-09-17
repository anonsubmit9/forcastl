"""F38: scoring-weight sensitivity ablation.

Re-weights the four frozen sub-scores (Extraction/6, Interpretation/6,
NoHallucination/4, Reasoning/4) from the saved per-case CSVs under alternative
weightings and reports mean score per model + model ordering. No model calls.

Scope: the shared 120-case comparison set; per-model completed cases (as the
paper's mean alignment) and, as a robustness check, the intersection of cases
every model completed. Rank stability via case bootstrap (2000 resamples).
"""
import csv, io, random
from pathlib import Path

import os
# Repository root: set FORCASTL_ROOT or run from <repo>/tools/paper/
REPO = Path(os.environ.get("FORCASTL_ROOT") or Path(__file__).resolve().parents[2])
JUNE = REPO / "outputs"
NEW = REPO / "outputs"
RUNS = {
    "Claude Opus 4.8":   JUNE / "detection_results_claude-opus-4-8_rescore_v1.csv",
    "GPT-5.5":           JUNE / "detection_results_gpt-5.5-2026-04-23_rescore_v1.csv",
    "Qwen3.6-27B":       JUNE / "detection_results_qwen3.6-27b_rescore_v1.csv",
    "Qwen3.8-Flash-Next": NEW / "detection_results_Qwen3.8-Flash-Next-MLX-Serve-4bit_20260901_123829.csv",
    "Qwen3.6-35B-A3B":   NEW / "detection_results_Qwen3.6-35B-A3B-UD-Q4_K_M.gguf_20260901_144311.csv",
}
DIMS = [("Extraction (6)", 6), ("Interpretation (6)", 6), ("NoHallucination (4)", 4), ("Reasoning (4)", 4)]
# name -> weights (E, I, H, R), summing to 1
WEIGHTS = {
    "frozen 30/30/20/20":      (0.30, 0.30, 0.20, 0.20),
    "40/40/10/10":             (0.40, 0.40, 0.10, 0.10),
    "equal 25/25/25/25":       (0.25, 0.25, 0.25, 0.25),
    "drop reasoning 37.5/37.5/25/0": (0.375, 0.375, 0.25, 0.0),
    "hallucination-heavy 20/20/40/20": (0.20, 0.20, 0.40, 0.20),
    "decision-heavy 20/40/20/20":     (0.20, 0.40, 0.20, 0.20),
}

def load(p):
    raw = p.read_text(encoding="utf-8").splitlines()
    rows = list(csv.DictReader(io.StringIO("\n".join(l for l in raw if not l.startswith("#")))))
    out = {}
    for r in rows:
        if r["Status"] != "processed":
            continue
        out[Path(r["Filename"]).stem] = (
            tuple(float(r[c]) / m for c, m in DIMS), float(r["Total (20)"]))
    return out

data = {m: load(p) for m, p in RUNS.items()}
# shared-120 = files present (any status) in all three June runs
def files_any(p):
    raw = p.read_text(encoding="utf-8").splitlines()
    return {Path(r["Filename"]).stem for r in csv.DictReader(io.StringIO("\n".join(l for l in raw if not l.startswith("#"))))}
shared = set.intersection(*[files_any(RUNS[m]) for m in ("Claude Opus 4.8", "GPT-5.5", "Qwen3.6-27B")])
print(f"shared comparison set: {len(shared)} cases")
for m in data:
    data[m] = {f: v for f, v in data[m].items() if f in shared}
    print(f"  {m:<20} completed {len(data[m]):>3}")

# sanity: frozen weights reproduce Total (20)
w0 = WEIGHTS["frozen 30/30/20/20"]
maxdev = max(abs(20 * sum(a * b for a, b in zip(v[0], w0)) - v[1])
             for d in data.values() for v in d.values())
print(f"frozen-weight reconstruction max |dev| from saved Total(20): {maxdev:.4f}")

def score(dims, w):
    return 20 * sum(a * b for a, b in zip(dims, w))

def table(scope_name, subset):
    print(f"\n== {scope_name} ==")
    hdr = f"{'weighting':<34}" + "".join(f"{m:>20}" for m in data) + "   ordering (best->worst)"
    print(hdr)
    for wn, w in WEIGHTS.items():
        means = {}
        for m, d in data.items():
            cases = [v for f, v in d.items() if subset is None or f in subset]
            means[m] = sum(score(v[0], w) for v in cases) / len(cases)
        order = " > ".join(m for m, _ in sorted(means.items(), key=lambda x: -x[1]))
        print(f"{wn:<34}" + "".join(f"{means[m]:>20.2f}" for m in data) + f"   {order}")

table("per-model completed cases (paper convention)", None)
common = set.intersection(*[set(d) for d in data.values()])
print(f"\ncommon completed-by-all-five set: {len(common)} cases")
table(f"common completed set (n={len(common)})", common)
june = ("Claude Opus 4.8", "GPT-5.5", "Qwen3.6-27B")
common3 = set.intersection(*[set(data[m]) for m in june])
print(f"\ncommon completed-by-all-three-June-models set: {len(common3)} cases")

# per-dimension means (frozen scale) to explain any movement
print("\n== per-dimension mean (out of max) on per-model completed cases ==")
print(f"{'model':<20}" + "".join(f"{c:>22}" for c, _ in DIMS))
for m, d in data.items():
    vals = list(d.values())
    print(f"{m:<20}" + "".join(f"{sum(v[0][i] for v in vals)/len(vals)*DIMS[i][1]:>18.2f}/{DIMS[i][1]}" for i in range(4)))

# bootstrap rank stability on the three June models, common3 set, per weighting
random.seed(20260902)
B = 2000
print(f"\n== bootstrap ({B} case resamples of the {len(common3)}-case common June set): "
      f"P(top model) per weighting ==")
cl = sorted(common3)
pt = {m: sum(score(data[m][f][0], w0) for f in cl) / len(cl) for m in june}
frozen_order = tuple(sorted(pt, key=lambda x: -pt[x]))
print("frozen-weight point order on this set:", " > ".join(frozen_order),
      {m: round(v, 2) for m, v in pt.items()})
for wn, w in WEIGHTS.items():
    wins = {m: 0 for m in june}
    same = 0
    pair = {"Claude>Qwen27B": 0, "Qwen27B>GPT": 0, "Claude>GPT": 0}
    for _ in range(B):
        samp = [cl[random.randrange(len(cl))] for _ in cl]
        means = {m: sum(score(data[m][f][0], w) for f in samp) / len(samp) for m in june}
        order = tuple(sorted(means, key=lambda x: -means[x]))
        wins[order[0]] += 1
        same += order == frozen_order
        pair["Claude>Qwen27B"] += means["Claude Opus 4.8"] > means["Qwen3.6-27B"]
        pair["Qwen27B>GPT"] += means["Qwen3.6-27B"] > means["GPT-5.5"]
        pair["Claude>GPT"] += means["Claude Opus 4.8"] > means["GPT-5.5"]
    print(f"{wn:<34} P(top): " + " ".join(f"{m.split()[0]}={wins[m]/B:.2f}" for m in june)
          + f" | P(full frozen order)={same/B:.2f} | "
          + " ".join(f"P({k})={v/B:.2f}" for k, v in pair.items()))
