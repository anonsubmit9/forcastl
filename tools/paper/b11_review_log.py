"""B11: quantify the expert-led GT review from the release's own audit files.

Sources (recovered June checkout):
  data/gt_review_state.json   per-file {reviewed, reviewed_at}
  data/gt_edit_log.jsonl      one row per applied evidence edit (GUI)
  data/ground_truth_evidence.json  label_review records (relabels)
  data/metadata.json          source (folder_structure | evtx-baseline)
"""
import json
from collections import Counter
from pathlib import Path

import os
# Repository root: set FORCASTL_ROOT or run from <repo>/tools/paper/
REPO = Path(os.environ.get("FORCASTL_ROOT") or Path(__file__).resolve().parents[2])
ROOT = REPO
rs = json.load(open(ROOT / "data/gt_review_state.json", encoding="utf-8"))
log = [json.loads(l) for l in open(ROOT / "data/gt_edit_log.jsonl", encoding="utf-8") if l.strip()]
gt = json.load(open(ROOT / "data/ground_truth_evidence.json", encoding="utf-8"))
gt = gt.get("files", gt)
meta = json.load(open(ROOT / "data/metadata.json", encoding="utf-8"))["files"]

reviewed = {k: v for k, v in rs.items() if v.get("reviewed")}
ra = sorted(v["reviewed_at"] for v in reviewed.values())
print(f"GT cases: {len(gt)}   marked reviewed: {len(reviewed)}   "
      f"missing: {sorted(set(gt) - set(reviewed))}")
print(f"reviewed_at: {ra[0]} .. {ra[-1]}   per day: {dict(Counter(x[:10] for x in ra))}")

ok = [r for r in log if r["result"] == "ok"]
print(f"\nedit log rows: {len(log)}  applied: {len(ok)}  "
      f"sources: {dict(Counter(r['source'] for r in log))}")
print(f"ops: {dict(Counter(r['op'] for r in ok))}")
print("field x op:", {f: dict(Counter(r["op"] for r in ok if r["field"] == f))
                      for f in sorted({r["field"] for r in ok})})
per = Counter(r["file"] for r in ok)
print(f"files with >=1 evidence edit: {len(per)} of {len(gt)} "
      f"({100*len(per)/len(gt):.1f}%)")
print(f"  by label: malicious={sum(1 for f in per if gt[f]['malicious']=='YES')} "
      f"benign={sum(1 for f in per if gt[f]['malicious']=='NO')}")
print(f"  by source: {dict(Counter(meta[f]['source'] for f in per))}")
dist = sorted(Counter(per.values()).items())
print(f"  edits/file: median={sorted(per.values())[len(per)//2]}  "
      f"dist={dist}")
print(f"  heaviest: {per.most_common(3)}")
ts = sorted(r["ts"] for r in ok)
print(f"edit time range: {ts[0]} .. {ts[-1]}")

lr = {k: v["label_review"] for k, v in gt.items() if v.get("label_review")}
print(f"\nlabel_review records: {len(lr)}  "
      f"reclassified: {dict(Counter(v['reclassified'] for v in lr.values()))}  "
      f"dates: {sorted({v['date'] for v in lr.values()})}")
relab = [k for k, v in gt.items() if v["malicious"] == "NO"
         and meta[k]["source"] == "folder_structure"]
print(f"folder_structure benign (relabelled): {len(relab)}  "
      f"without label_review: {[k for k in relab if k not in lr]}")

# union of any recorded human touch (evidence edit or relabel)
touched = set(per) | set(lr)
print(f"\ncases with a recorded evidence edit or relabel: {len(touched)} "
      f"({100*len(touched)/len(gt):.1f}%); reviewed with no change: {len(gt)-len(touched)}")
