"""E31: bound the Qwen server's effective input limit from the run record.
The 6 immediate HTTP 400 rejections (0.2-1.3 s) vs the largest artifact the
server accepted. Sizes measured on the CSV artifact the prompt embeds.
Token estimate: tiktoken cl100k if available, else chars/4 (stated heuristic)."""
import csv, io
from pathlib import Path

import os
# Repository root: set FORCASTL_ROOT or run from <repo>/tools/paper/
REPO = Path(os.environ.get("FORCASTL_ROOT") or Path(__file__).resolve().parents[2])
ROOT = REPO
CSVDIR = ROOT / "data/csv"
raw = open(ROOT / "outputs/detection_results_qwen3.6-27b_20260615_194908.csv", encoding="utf-8").read().splitlines()
rows = list(csv.DictReader(io.StringIO("\n".join(l for l in raw if not l.startswith("#")))))
try:
    import tiktoken
    enc = tiktoken.get_encoding("cl100k_base")
    tok = lambda s: len(enc.encode(s, disallowed_special=()))
    method = "tiktoken cl100k_base (proxy tokenizer, not Qwen's)"
except Exception:
    tok = lambda s: len(s) // 4
    method = "chars/4 heuristic"
print("token method:", method)

INDEX = {p.stem: p for p in CSVDIR.rglob("*.csv")}  # corpus is nested by tactic/technique


def artifact(fn):
    p = INDEX.get(Path(fn).stem)
    return p.read_text(encoding="utf-8", errors="replace") if p else None

out = []
for r in rows:
    a = artifact(r["Filename"])
    if a is None:
        print("MISSING artifact for", r["Filename"]); continue
    kind = ("http400" if "HTTP 400" in r["LLM Response"] else
            "timeout" if "timed out" in r["LLM Response"] else "processed")
    out.append((kind, tok(a), len(a), r["Filename"], r["Response Time (s)"]))

for kind in ("http400", "timeout", "processed"):
    xs = sorted(x for x in out if x[0] == kind)
    print(f"\n{kind}: n={len(xs)}  tokens min={xs[0][1]:,} max={xs[-1][1]:,}")
    for k, t, b, fn, rt in (xs if kind != "processed" else xs[-5:]):
        print(f"   {t:>8,} tok {b:>9,} B  {rt:>7}s  {fn[:60]}")
