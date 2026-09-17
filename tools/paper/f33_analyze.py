"""F33: original vs perturbed run, same model, same 120 cases.
Paired per-case comparison: verdict flips, recall/FPR/alignment/unsupported deltas
with paired case-bootstrap 95% CIs, relabelled/native split, and the list of flips."""
import csv, io, json, random, sys
from math import sqrt
from pathlib import Path
from collections import Counter

ORIG = Path(sys.argv[1]); PERT = Path(sys.argv[2])
import os
# Repository root: set FORCASTL_ROOT or run from <repo>/tools/paper/
REPO = Path(os.environ.get("FORCASTL_ROOT") or Path(__file__).resolve().parents[2])
ROOT = REPO
gt = json.load(open(ROOT / "data/ground_truth_evidence.json", encoding="utf-8")); gt = gt.get("files", gt); gt = {Path(k).stem: v for k, v in gt.items()}
meta = json.load(open(ROOT / "data/metadata.json", encoding="utf-8"))["files"]; meta = {Path(k).stem: v for k, v in meta.items()}

def load(p):
    raw = p.read_text(encoding="utf-8").splitlines()
    return {Path(r["Filename"]).stem: r for r in csv.DictReader(io.StringIO("\n".join(l for l in raw if not l.startswith("#"))))}
A, B = load(ORIG), load(PERT)
assert set(A) == set(B), (len(A), len(B), set(A) ^ set(B))
cases = sorted(A)
print(f"paired cases: {len(cases)}  (model: {A[cases[0]]['Model']})")

def v(r):  # True/False/None
    return None if r["Status"] != "processed" else (r["Malicious"].strip().upper() == "YES")
def f(r, c):
    try: return float(r[c])
    except: return None

def metrics(R, subset):
    mal = [s for s in subset if gt[s]["malicious"] == "YES"]; ben = [s for s in subset if gt[s]["malicious"] == "NO"]
    tp = sum(1 for s in mal if v(R[s]) is True); fail = sum(1 for s in subset if v(R[s]) is None)
    done_b = [s for s in ben if v(R[s]) is not None]; fp = sum(1 for s in done_b if v(R[s]) is True)
    proc = [s for s in subset if v(R[s]) is not None]
    align = sum(f(R[s], "Total (20)") for s in proc) / len(proc)
    hal = sum(f(R[s], "Hallucination %") for s in proc) / len(proc)
    return dict(recall=100*tp/len(mal), fpr=100*fp/len(done_b) if done_b else 0, align=align, hal=hal, fail=fail, tp=tp, fp=fp, nb=len(done_b))

def wilson(k, n, z=1.96):
    p = k/n; d = 1+z*z/n; c = (p+z*z/(2*n))/d; h = z*sqrt(p*(1-p)/n+z*z/(4*n*n))/d
    return 100*(c-h), 100*(c+h)

ma, mb = metrics(A, cases), metrics(B, cases)
print(f"\n{'metric':<22}{'original':>12}{'perturbed':>12}{'delta':>10}")
for k in ("recall", "fpr", "align", "hal", "fail"):
    print(f"{k:<22}{ma[k]:>12.2f}{mb[k]:>12.2f}{mb[k]-ma[k]:>+10.2f}")
mal = [s for s in cases if gt[s]["malicious"] == "YES"]; ben = [s for s in cases if gt[s]["malicious"] == "NO"]
print(f"recall CI  orig {wilson(ma['tp'], len(mal))}  pert {wilson(mb['tp'], len(mal))}")
print(f"FPR CI     orig {wilson(ma['fp'], ma['nb'])}  pert {wilson(mb['fp'], mb['nb'])}")

# paired bootstrap on deltas
random.seed(20260902); Bn = 2000; deltas = {k: [] for k in ("recall", "fpr", "align", "hal")}
for _ in range(Bn):
    samp = [cases[random.randrange(len(cases))] for _ in cases]
    xa, xb = metrics(A, samp), metrics(B, samp)
    for k in deltas: deltas[k].append(xb[k] - xa[k])
print("\npaired bootstrap 95% CI of delta (perturbed - original):")
for k, d in deltas.items():
    d.sort(); print(f"  {k:<8} [{d[int(0.025*Bn)]:+.2f}, {d[int(0.975*Bn)]:+.2f}]")

# verdict flips
flips = [(s, v(A[s]), v(B[s])) for s in cases if v(A[s]) != v(B[s])]
print(f"\nverdict/status changes: {len(flips)} of {len(cases)}")
kinds = Counter()
for s, a, b in flips:
    lab = gt[s]["malicious"]; src = meta[s]["source"]
    kind = f"{'mal' if lab=='YES' else 'ben'}/{src}: {a} -> {b}"
    kinds[kind] += 1
    print(f"   [{lab} {src:<16}] {s[:60]:<60} {a} -> {b}")
print("by kind:", dict(kinds))
same = sum(1 for s in cases if v(A[s]) == v(B[s]))
print(f"verdict agreement: {same}/{len(cases)} ({100*same/len(cases):.1f}%)")

# per-case score movement
proc_both = [s for s in cases if v(A[s]) is not None and v(B[s]) is not None]
d20 = [f(B[s], "Total (20)") - f(A[s], "Total (20)") for s in proc_both]
print(f"\nTotal(20) per-case delta on {len(proc_both)} cases completed in both: mean {sum(d20)/len(d20):+.2f}, "
      f"|delta|>=2 on {sum(1 for x in d20 if abs(x)>=2)} cases, max +{max(d20):.1f} / {min(d20):.1f}")
for c in ("Extraction (6)", "Interpretation (6)", "NoHallucination (4)", "Reasoning (4)"):
    da = sum(f(A[s], c) for s in proc_both)/len(proc_both); db = sum(f(B[s], c) for s in proc_both)/len(proc_both)
    print(f"  {c:<20} {da:.2f} -> {db:.2f} ({db-da:+.2f})")

# split
rel = [s for s in ben if meta[s]["source"] == "folder_structure"]; nat = [s for s in ben if meta[s]["source"] != "folder_structure"]
for name, sub in (("relabelled benign", rel), ("native benign", nat)):
    fa = sum(1 for s in sub if v(A[s]) is True); fb = sum(1 for s in sub if v(B[s]) is True)
    print(f"FP on {name}: {fa}/{len(sub)} -> {fb}/{len(sub)}")
# failures
fa = [s for s in cases if v(A[s]) is None]; fb = [s for s in cases if v(B[s]) is None]
print(f"failures: orig {len(fa)}  pert {len(fb)}  same set: {set(fa)==set(fb)}  only-orig {sorted(set(fa)-set(fb))}  only-pert {sorted(set(fb)-set(fa))}")
