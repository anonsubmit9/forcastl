"""Verify corpus label/source split and label_review coverage.

Cross-references data/metadata.json (source) with data/ground_truth_evidence.json
(malicious label, label_review audit records).
"""
import json
from collections import Counter

import os
from pathlib import Path
# Repository root: set FORCASTL_ROOT or run from <repo>/tools/paper/
REPO = Path(os.environ.get("FORCASTL_ROOT") or Path(__file__).resolve().parents[2])
ROOT = str(REPO)
meta = json.load(open(ROOT + r"\data\metadata.json", encoding="utf-8"))["files"]
gt = json.load(open(ROOT + r"\data\ground_truth_evidence.json", encoding="utf-8"))
gt_files = gt.get("files", gt)

print("metadata entries:", len(meta), "| GT entries:", len(gt_files))
print("label counts:", Counter(v.get("malicious") for v in gt_files.values()))

rows = []
for name, g in gt_files.items():
    src = meta.get(name, {}).get("source", "MISSING-IN-METADATA")
    rows.append((name, src, g.get("malicious"), bool(g.get("label_review"))))

benign = [r for r in rows if r[2] == "NO"]
print("\nbenign by source:", Counter(r[1] for r in benign))

relabelled = [r for r in benign if r[1] == "folder_structure"]
with_review = [r for r in relabelled if r[3]]
without_review = [r for r in relabelled if not r[3]]
print("benign folder_structure (relabelled):", len(relabelled))
print("  with label_review:", len(with_review))
print("  WITHOUT label_review:", len(without_review))
for r in without_review:
    print("   -", r[0])

# any label_review on non-benign or non-folder_structure entries?
lr_all = [(n, meta.get(n, {}).get("source"), g.get("malicious"))
          for n, g in gt_files.items() if g.get("label_review")]
print("\ntotal label_review records:", len(lr_all))
print("label_review by (source, label):", Counter((s, m) for _, s, m in lr_all))
