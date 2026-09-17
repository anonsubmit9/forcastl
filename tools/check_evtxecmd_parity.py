#!/usr/bin/env python3
"""Confirm a freshly-converted EvtxECmd CSV matches the corpus's CSV contract.

Phase 0 of the corpus reset: before importing baseline benign logs, verify the
EvtxECmd version/settings on the Windows box produce CSVs the tool reads exactly
like the existing corpus — same 27-column header, Payload as EventData/UserData
JSON, parseable by the project parser, and per-Event-ID Payload field-sets that
match real corpus events (no schema drift).

    python -m tools.check_evtxecmd_parity <converted.csv | dir-of-csvs>

Exit 0 = parity OK; exit 1 = drift found (details printed).
"""
from __future__ import annotations

import argparse
import collections
import csv as _csv
import json
import sys
from pathlib import Path

from forcastl.core.parser import EVTXParser
from forcastl.core.csv_evidence import DEFAULT_CSV_DIR

EXPECTED_COLS = [
    "RecordNumber", "EventRecordId", "TimeCreated", "EventId", "Level", "Provider",
    "Channel", "ProcessId", "ThreadId", "Computer", "ChunkNumber", "UserId",
    "MapDescription", "UserName", "RemoteHost", "PayloadData1", "PayloadData2",
    "PayloadData3", "PayloadData4", "PayloadData5", "PayloadData6", "ExecutableInfo",
    "HiddenRecord", "SourceFile", "Keywords", "ExtraDataOffset", "Payload",
]


def _payload_keyset(payload: str):
    """The Payload's Data field-set signature, mirroring the corpus convention."""
    try:
        d = json.loads(payload)
    except Exception:  # noqa: BLE001
        return None
    ed = d.get("EventData")
    if isinstance(ed, dict):
        data = ed.get("Data")
        if isinstance(data, list):
            return ("list", tuple(it.get("@Name") for it in data if isinstance(it, dict)))
        if isinstance(data, dict):
            return ("dict", data.get("@Name"))
        if isinstance(data, str):
            return ("rawstr",)
    if "UserData" in d:
        return ("userdata",)
    return ("other",)


def _real_reference():
    """Field-set signatures seen in the REAL (folder_structure) corpus, per (EID, Provider)."""
    import json as _json
    md = _json.loads((Path("data/metadata.json")).read_text(encoding="utf-8"))["files"]
    real_stems = {k[:-5] for k, v in md.items()
                  if str(v.get("source", "")).lower() == "folder_structure"}
    ref = collections.defaultdict(set)
    for p in Path(DEFAULT_CSV_DIR).rglob("*.csv"):
        if p.stem not in real_stems:
            continue
        for r in _csv.DictReader(p.read_text(encoding="utf-8-sig", errors="replace").splitlines()):
            sig = _payload_keyset(r.get("Payload", "") or "")
            if sig:
                ref[(r.get("EventId"), r.get("Provider"))].add(sig)
    return ref


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Check EvtxECmd CSV parity with the corpus.")
    ap.add_argument("path", help="Converted CSV file or directory.")
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])
    root = Path(args.path)
    paths = [root] if root.is_file() else sorted(root.rglob("*.csv"))
    if not paths:
        print(f"no CSVs at {root}", file=sys.stderr)
        return 2

    ref = _real_reference()
    parser = EVTXParser()
    problems = 0
    for p in paths:
        raw = p.read_text(encoding="utf-8-sig", errors="replace").splitlines()
        rows = list(_csv.DictReader(raw))
        cols = list(rows[0].keys()) if rows else []
        miss_cols = [c for c in EXPECTED_COLS if c not in cols]
        extra_cols = [c for c in cols if c not in EXPECTED_COLS]
        bad_json = sum(1 for r in rows if (r.get("Payload") or "").strip()
                       and _payload_keyset(r["Payload"]) is None)
        events = parser.parse_csv_file(str(p))
        with_payload = sum(1 for r in rows if (r.get("Payload") or "").strip())
        drift = []
        for r in rows:
            k = (r.get("EventId"), r.get("Provider"))
            sig = _payload_keyset(r.get("Payload", "") or "")
            if sig and k in ref and sig not in ref[k]:
                drift.append((k, sig))

        ok = not miss_cols and not bad_json and len(events) == with_payload and not drift
        flag = "OK " if ok else "!! "
        print(f"{flag}{p.name}: rows={len(rows)} parsed={len(events)}/{with_payload}"
              f" json_bad={bad_json} cols_missing={miss_cols or '-'}"
              f" cols_extra={extra_cols or '-'}")
        if drift:
            problems += 1
            seen = collections.Counter(str(d) for d in drift)
            for d, n in seen.most_common(5):
                print(f"     schema drift x{n}: {d}")
        elif not ok:
            problems += 1

    print("\nPARITY OK — conversions match the corpus contract" if not problems
          else f"\nPARITY ISSUES on {problems} file(s) — fix EvtxECmd version/settings before importing")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
