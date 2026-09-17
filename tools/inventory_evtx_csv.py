#!/usr/bin/env python3
"""Inventory a folder of EvtxECmd CSVs — Phase 0 of the corpus reset.

After converting evtx-baseline `.evtx` to CSV with EvtxECmd, run this against the
output to see what benign coverage we got: the Event-ID / Provider / Channel
distribution, and specifically which of the *wanted* near-miss benign event types
(the benign near-misses of the attack techniques) are present and
in what volume. This drives the Phase-0 gate (can we curate >=60 quality benign?).

    python -m tools.inventory_evtx_csv <dir-of-csvs | one.csv> [--min 1]
"""
from __future__ import annotations

import argparse
import collections
import csv as _csv
import sys
from pathlib import Path

# Wanted benign Event IDs — benign near-misses of the attack techniques (derived
# from the real attack corpus's top Event IDs + the ambiguous singles the models
# over-flag). Value = short note.
WANTED = {
    "1":     "Sysmon ProcessCreate — process-execution near-misses",
    "4688":  "Security ProcessCreate — admin command lines",
    "4624":  "Logon — service/admin/remote logons",
    "4625":  "Failed logon — vs brute-force",
    "4720":  "User account created — vs malicious account creation",
    "4738":  "User account changed — vs account manipulation",
    "4728":  "Member added to global group — vs privilege escalation",
    "4732":  "Member added to local group — vs privilege escalation",
    "4672":  "Special privileges assigned — vs privileged abuse",
    "4964":  "Special-group logon — vs flagged privileged logon",
    "4662":  "DS object access — vs DCSync/DCShadow",
    "4661":  "SAM/handle access — vs credential access",
    "4656":  "Object handle requested — vs sensitive access",
    "5136":  "DS object modified (GPO) — vs GPO modification",
    "5140":  "Network share accessed — vs lateral SMB",
    "5145":  "Network share file access — vs lateral SMB",
    "7045":  "Service installed — vs malicious service",
    "4698":  "Scheduled task created — vs persistence",
    "800":   "PowerShell pipeline — vs malicious PowerShell",
    "4103":  "PowerShell module logging — vs malicious PowerShell",
    "4104":  "PowerShell script-block — vs malicious PowerShell",
    "11":    "Sysmon FileCreate — vs file drops",
    "33205": "SQL Server audit — vs malicious SQL role/login",
    "1102":  "Security log cleared — vs anti-forensics (rare benign)",
}


def _iter_csvs(root: Path):
    if root.is_file():
        yield root
    else:
        yield from sorted(root.rglob("*.csv"))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Inventory EvtxECmd CSVs for benign coverage.")
    ap.add_argument("path", help="A converted CSV file or a directory of them.")
    ap.add_argument("--min", type=int, default=1, help="Only list wanted EIDs with >= this many events.")
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])

    root = Path(args.path)
    if not root.exists():
        print(f"no such path: {root}", file=sys.stderr)
        return 2

    by_eid = collections.Counter()
    by_eid_prov = collections.Counter()
    by_channel = collections.Counter()
    files = 0
    for p in _iter_csvs(root):
        try:
            rows = list(_csv.DictReader(p.read_text(encoding="utf-8-sig", errors="replace").splitlines()))
        except Exception:  # noqa: BLE001
            continue
        if not rows or "EventId" not in rows[0]:
            continue
        files += 1
        for r in rows:
            eid = (r.get("EventId") or "").strip()
            prov = (r.get("Provider") or "").strip()
            by_eid[eid] += 1
            by_eid_prov[(eid, prov)] += 1
            by_channel[(r.get("Channel") or "").strip()] += 1

    total = sum(by_eid.values())
    print(f"CSV files: {files}   total events: {total:,}")
    print(f"distinct Event IDs: {len(by_eid)}   channels: {len(by_channel)}\n")

    print("=== WANTED benign Event IDs present (near-misses of the attack techniques) ===")
    hits = 0
    for eid, note in WANTED.items():
        c = by_eid.get(eid, 0)
        if c >= args.min:
            hits += 1
            provs = ", ".join(f"{p or '?'}({n})" for (e, p), n in by_eid_prov.most_common() if e == eid)
            print(f"   EID {eid:<6} x{c:<6} {note}")
            print(f"        providers: {provs[:140]}")
    print(f"\n   -> {hits}/{len(WANTED)} wanted event types present")

    missing = [e for e in WANTED if by_eid.get(e, 0) < args.min]
    if missing:
        print(f"   not present (or below --min): {', '.join(missing)}")

    print("\n=== top 25 Event IDs overall (for reference) ===")
    for eid, c in by_eid.most_common(25):
        print(f"   EID {eid:<6} x{c}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
