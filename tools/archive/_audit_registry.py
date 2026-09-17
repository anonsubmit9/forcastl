import json
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
gt = json.loads((PROJECT_ROOT / "ground_truth_evidence.json").read_text(encoding="utf-8"))

hits = []
for fname, e in gt.get("files", {}).items():
    for x in (e.get("evidence") or {}).get("registry", []) or []:
        s = str(x).strip()
        if s and not (s.upper().startswith("HK") or "\\" in s):
            hits.append((fname, s))

print(f"{len(hits)} registry values that don't look like a path.")
print("Top 30 unique values:")
c = Counter(v for _, v in hits)
for v, n in c.most_common(30):
    print(f"  ({n}x) {v}")

print()
print("Sample files containing these:")
seen_files = []
for fname, val in hits:
    if fname not in seen_files:
        seen_files.append(fname)
        if len(seen_files) <= 8:
            print(f"  {fname}")
            print(f"    -> {val}")
