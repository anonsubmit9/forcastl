"""Convert EvtxECmd CSV cases to evtx_dump-style JSONL for Hayabusa -J.

One JSONL per case (so EvtxFile attribution survives), written under f32/json/.
Structure per event:
  {"Event": {"System": {...}, "EventData": {name: value, ...}}}
System fields come from the CSV columns; EventData is rebuilt from the Payload
column (EvtxECmd JSON: {"EventData":{"Data":[{"@Name":..,"#text":..},...]}}).
UserData payloads are passed through under "UserData".
Validation: run the same conversion on the 265 attack cases that also have EVTX
and compare per-file max alert level with the EVTX scan (f32_roundtrip.py).
"""
import csv, json, sys
from pathlib import Path

import os
# Repository root: set FORCASTL_ROOT or run from <repo>/tools/paper/
REPO = Path(os.environ.get("FORCASTL_ROOT") or Path(__file__).resolve().parents[2])
ROOT = REPO
OUT = Path(__file__).parent / "f32/json"
OUT.mkdir(parents=True, exist_ok=True)
csv.field_size_limit(1 << 30)

def iso(ts):  # "2022-04-07 16:54:08.7928366" -> "2022-04-07T16:54:08.7928366Z" (EvtxECmd emits UTC)
    return ts.replace(" ", "T") + ("Z" if not ts.endswith("Z") else "")

def to_int(x):
    try: return int(x)
    except Exception: return x

def event_data(payload):
    try:
        p = json.loads(payload)
    except Exception:
        return {"EventData": {"Data": payload}}
    out = {}
    if "EventData" in p and isinstance(p["EventData"], dict):
        ed = {}
        data = p["EventData"].get("Data")
        if isinstance(data, list):
            for i, d in enumerate(data):
                if isinstance(d, dict):
                    ed[d.get("@Name") or f"Data{i}"] = d.get("#text", "")
                else:
                    ed[f"Data{i}"] = d
        elif isinstance(data, dict):
            ed[data.get("@Name", "Data")] = data.get("#text", "")
        elif data is not None:
            ed["Data"] = data
        for k, v in p["EventData"].items():
            if k != "Data": ed[k] = v
        out["EventData"] = ed
    if "UserData" in p:
        out["UserData"] = p["UserData"]
    if not out:
        out["EventData"] = p
    return out

def convert(csv_path, dst):
    n = 0
    with open(csv_path, encoding="utf-8-sig", newline="") as fh, open(dst, "w", encoding="utf-8") as w:
        for r in csv.DictReader(fh):
            sysd = {
                "Provider": {"#attributes": {"Name": r.get("Provider", "")}},
                "EventID": to_int(r.get("EventId", "")),
                "Level": r.get("Level", ""),
                "Keywords": r.get("Keywords", ""),
                "TimeCreated": {"#attributes": {"SystemTime": iso(r.get("TimeCreated", ""))}},
                "EventRecordID": to_int(r.get("EventRecordId", "")),
                "Execution": {"#attributes": {"ProcessID": to_int(r.get("ProcessId", "")), "ThreadID": to_int(r.get("ThreadId", ""))}},
                "Channel": r.get("Channel", ""),
                "Computer": r.get("Computer", ""),
                "Security": {"#attributes": {"UserID": r.get("UserId", "")}} if r.get("UserId") else None,
            }
            ev = {"Event": {"System": sysd, **event_data(r.get("Payload", ""))}}
            w.write(json.dumps(ev, ensure_ascii=False) + "\n"); n += 1
    return n

if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    gt = json.load(open(ROOT / "data/ground_truth_evidence.json", encoding="utf-8")); gt = gt.get("files", gt)
    idx = {p.stem: p for p in (ROOT / "data/csv").rglob("*.csv")}
    evtx = {p.stem for p in (ROOT / "data/evtx").rglob("*.evtx")}
    stems = [Path(k).stem for k in gt]
    if which == "benign-only":
        stems = [s for s in stems if s not in evtx]
    tot = 0
    for s in stems:
        tot += convert(idx[s], OUT / (s + ".jsonl"))
    print(f"converted {len(stems)} cases, {tot} events -> {OUT}")
