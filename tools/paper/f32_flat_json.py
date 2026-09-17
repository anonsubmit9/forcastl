"""Produce FLAT (OTRF/Mordor-style) JSONL for Hayabusa -J, per the format the
implementing PR (#881) tested against: top-level "@timestamp", "EventID",
"Channel", "Computer"/"Hostname", "SourceName", "RecordNumber", with EventData
fields flattened to top level.

Two sources, same layout, so the CSV path can be validated against EVTX:
  f32/flat_csv/<stem>.jsonl   from the EvtxECmd CSV (all 328 cases)
  f32/flat_ref/<stem>.jsonl   from the EVTX via the evtx library (265 cases)
"""
import csv, json, os, sys
from pathlib import Path

S = Path(__file__).parent
# Repository root: set FORCASTL_ROOT or run from <repo>/tools/paper/
REPO = Path(os.environ.get("FORCASTL_ROOT") or Path(__file__).resolve().parents[2])
ROOT = REPO
sys.path.insert(0, str(S / "pylib"))
csv.field_size_limit(1 << 30)

def flat_from_csv_row(r):
    rec = {
        "@timestamp": r.get("TimeCreated", "").replace(" ", "T") + "Z",
        "EventID": int(r["EventId"]) if r.get("EventId", "").isdigit() else r.get("EventId"),
        "Channel": r.get("Channel", ""),
        "Computer": r.get("Computer", ""),
        "Hostname": r.get("Computer", ""),
        "SourceName": r.get("Provider", ""),
        "ProviderName": r.get("Provider", ""),
        "RecordNumber": int(r["EventRecordId"]) if r.get("EventRecordId", "").isdigit() else r.get("EventRecordId"),
        "Keywords": r.get("Keywords", ""),
        "ProcessID": r.get("ProcessId", ""),
        "ThreadID": r.get("ThreadId", ""),
        "UserID": r.get("UserId", ""),
    }
    try:
        p = json.loads(r.get("Payload", "") or "{}")
    except Exception:
        p = {}
    ed = p.get("EventData") if isinstance(p, dict) else None
    if isinstance(ed, dict):
        data = ed.get("Data")
        if isinstance(data, list):
            for i, d in enumerate(data):
                if isinstance(d, dict):
                    rec[d.get("@Name") or f"Data{i}"] = d.get("#text", "")
        elif isinstance(data, dict):
            rec[data.get("@Name", "Data")] = data.get("#text", "")
        for k, v in ed.items():
            if k != "Data" and k not in rec:
                rec[k] = v if not isinstance(v, (dict, list)) else json.dumps(v)
    ud = p.get("UserData") if isinstance(p, dict) else None
    if isinstance(ud, dict):
        # flatten one level of UserData/<Container>/<fields>
        for k, v in ud.items():
            if isinstance(v, dict):
                for kk, vv in v.items():
                    if not kk.startswith("@") and kk not in rec:
                        rec[kk] = vv if not isinstance(vv, (dict, list)) else json.dumps(vv)
            elif k not in rec:
                rec[k] = v
    return rec

def flat_from_evtx_record(o):
    e = o["Event"]; s = e["System"]
    rec = {
        "@timestamp": s["TimeCreated"]["#attributes"]["SystemTime"],
        "EventID": s["EventID"] if not isinstance(s["EventID"], dict) else s["EventID"].get("#text"),
        "Channel": s.get("Channel", ""),
        "Computer": s.get("Computer", ""),
        "Hostname": s.get("Computer", ""),
        "SourceName": s.get("Provider", {}).get("#attributes", {}).get("Name", ""),
        "ProviderName": s.get("Provider", {}).get("#attributes", {}).get("Name", ""),
        "RecordNumber": s.get("EventRecordID"),
        "Keywords": s.get("Keywords", ""),
    }
    ex = s.get("Execution") or {}
    rec["ProcessID"] = (ex.get("#attributes") or {}).get("ProcessID", "")
    rec["ThreadID"] = (ex.get("#attributes") or {}).get("ThreadID", "")
    ed = e.get("EventData") or {}
    if isinstance(ed, dict):
        for k, v in ed.items():
            if k not in rec:
                rec[k] = v if not isinstance(v, (dict, list)) else json.dumps(v)
    ud = e.get("UserData") or {}
    if isinstance(ud, dict):
        for k, v in ud.items():
            if isinstance(v, dict):
                for kk, vv in v.items():
                    if not kk.startswith("#") and kk not in rec:
                        rec[kk] = vv if not isinstance(vv, (dict, list)) else json.dumps(vv)
    return rec

if __name__ == "__main__":
    gt = json.load(open(ROOT / "data/ground_truth_evidence.json", encoding="utf-8")); gt = gt.get("files", gt)
    stems = {Path(k).stem for k in gt}
    out_csv = S / "f32/flat_csv"; out_ref = S / "f32/flat_ref"
    out_csv.mkdir(parents=True, exist_ok=True); out_ref.mkdir(parents=True, exist_ok=True)
    idx = {p.stem: p for p in (ROOT / "data/csv").rglob("*.csv")}
    n = 0
    for s in stems:
        with open(idx[s], encoding="utf-8-sig", newline="") as fh, open(out_csv / (s + ".jsonl"), "w", encoding="utf-8") as w:
            for r in csv.DictReader(fh):
                w.write(json.dumps(flat_from_csv_row(r), ensure_ascii=False) + "\n"); n += 1
    print("csv ->", len(stems), "files,", n, "events")
    import evtx
    n = m = 0
    for p in (ROOT / "data/evtx").rglob("*.evtx"):
        if p.stem not in stems: continue
        with open(out_ref / (p.stem + ".jsonl"), "w", encoding="utf-8") as w:
            for r in evtx.PyEvtxParser(str(p)).records_json():
                w.write(json.dumps(flat_from_evtx_record(json.loads(r["data"])), ensure_ascii=False) + "\n"); n += 1
        m += 1
    print("evtx ->", m, "files,", n, "events")
    print(open(out_csv / "ID4688-Scheduled task creation.jsonl", encoding="utf-8").read()[:500])
