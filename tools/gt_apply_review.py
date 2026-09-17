#!/usr/bin/env python3
"""Apply reviewer-authored GT evidence corrections, validated against the artifact.

Companion to ``tools.gt_review_packets``. The reviewer (a model or human) opens
each packet in ``outputs/gt_review/`` and adds a top-level ``"corrected"`` block
holding the complete, correct 6-field forensic inventory for that file:

    { ...packet..., "corrected": {
        "event_ids": [...], "processes": [...], "accounts": [...],
        "commands": [...], "network": [...], "registry": [...] } }

This tool reads those packets and, for each, VALIDATES that every corrected value
is actually present in the artifact the model saw (event_ids exact against the
event set; other fields via the same artifact-presence check the hallucination
scorer uses) — so a review can ADD real evidence but cannot introduce a
fabrication. Validated entries' 6 BASE fields are rewritten in place, preserving
labels, narrative, difficulty/test_set, and attack_* sidecars (same contract as
sync_ground_truth_evidence._apply_evidence).

Dry-run by default (reports planned changes + any rejected values); --apply writes.
Always re-run `python -m tools.validate_ground_truth -v` afterward.

    python -m tools.gt_apply_review                       # dry-run over outputs/gt_review
    python -m tools.gt_apply_review --apply
    python -m tools.gt_apply_review --packets <dir> --gt <path> --apply
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from forcastl import config
from forcastl.core.parser import EVTXParser
from forcastl.core.csv_evidence import (
    DEFAULT_CSV_DIR, build_csv_index, resolve_csv, sort_text, sort_event_ids,
)
from forcastl.core.hallucination import (
    EVIDENCE_FIELDS, present_in_artefact, _normalize_artefact,
)

_EVTX = EVTXParser()


def _artifact_views(fname: str, csv_index: Dict[str, str]) -> Optional[Tuple[str, Set[str]]]:
    """Return (normalized artefact text, set of event-id strings) or None."""
    csv_path = resolve_csv(fname, csv_index)
    if not csv_path or not Path(csv_path).is_file():
        return None
    events = _EVTX.parse_csv_file(csv_path)
    artefact_norm = _normalize_artefact(_EVTX.format_for_llm_pure_raw_xml(events))
    ids: Set[str] = set()
    for e in events:
        sysblk = (e.get("Event", {}) or {}).get("System", {}) or {}
        eid = sysblk.get("EventID")
        if isinstance(eid, dict):
            eid = eid.get("#text")
        if eid is not None:
            ids.add(str(eid).strip())
    return artefact_norm, ids


def validate_corrected(corrected: Dict[str, List[str]], artefact_norm: str,
                       event_ids: Set[str],
                       current_base: Optional[Dict[str, List[str]]] = None,
                       ) -> Tuple[Dict[str, Set[str]], List[str]]:
    """Return (accepted per field, rejected 'field: value' that aren't in the artifact).

    A value is accepted if it is present in the artifact (event_ids: in the
    event set), OR it is already in the entry's current base field — existing
    extractor-derived evidence is grandfathered so a review can ADD without the
    artifact-presence floor (which has a 4-char minimum) ever DROPPING a real,
    pre-existing value like a short SQL principal.
    """
    base = {f: {str(x).strip().lower() for x in (current_base or {}).get(f, [])}
            for f in EVIDENCE_FIELDS}
    accepted: Dict[str, Set[str]] = {f: set() for f in EVIDENCE_FIELDS}
    rejected: List[str] = []
    for f in EVIDENCE_FIELDS:
        for raw in corrected.get(f, []) or []:
            v = str(raw).strip()
            if not v:
                continue
            grandfathered = v.lower() in base[f]
            ok = grandfathered or (
                (v in event_ids) if f == "event_ids" else present_in_artefact(v, artefact_norm))
            if ok:
                accepted[f].add(v)
            else:
                rejected.append(f"{f}: {v}")
    return accepted, rejected


def _apply_base(entry: Dict, accepted: Dict[str, Set[str]]) -> None:
    """Rewrite only the 6 base fields in place; preserve every other key."""
    ev = entry.setdefault("evidence", {})
    ev["event_ids"] = sort_event_ids(accepted["event_ids"])
    for f in ("processes", "accounts", "commands", "network", "registry"):
        ev[f] = sort_text(accepted[f])


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Apply validated GT review corrections.")
    ap.add_argument("--packets", default=None, help="Packets dir (default: outputs/gt_review).")
    ap.add_argument("--gt", default=None, help="Ground-truth path (default: config.GROUND_TRUTH_FILE).")
    ap.add_argument("--csv-dir", default=str(DEFAULT_CSV_DIR), help="Source CSV corpus root.")
    ap.add_argument("--apply", action="store_true", help="Write changes (default: dry-run).")
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])

    config.require_data_dir()
    gt_path = Path(args.gt) if args.gt else Path(config.GROUND_TRUTH_FILE)
    gt_doc = json.loads(gt_path.read_text(encoding="utf-8"))
    files = gt_doc["files"]
    csv_index = build_csv_index(args.csv_dir)

    packets_dir = Path(args.packets) if args.packets else (config.OUTPUTS_DIR / "gt_review")
    packets = [p for p in sorted(packets_dir.glob("*.json")) if p.name != "_index.json"]

    changed, skipped, total_rejected = 0, 0, 0
    for p in packets:
        d = json.loads(p.read_text(encoding="utf-8"))
        corrected = d.get("corrected")
        if not corrected:
            skipped += 1
            continue
        key = d.get("gt_key")
        entry = files.get(key)
        if entry is None:
            print(f"[WARN] {p.name}: gt_key {key!r} not in GT; skipped")
            skipped += 1
            continue
        views = _artifact_views(d["file"], csv_index)
        if views is None:
            print(f"[WARN] {p.name}: no source CSV for {d['file']}; skipped")
            skipped += 1
            continue
        artefact_norm, event_ids = views
        current_base = {f: (entry.get("evidence", {}) or {}).get(f) or [] for f in EVIDENCE_FIELDS}
        accepted, rejected = validate_corrected(corrected, artefact_norm, event_ids, current_base)
        if rejected:
            total_rejected += len(rejected)
            print(f"[REJECT] {d['file']}: {len(rejected)} value(s) NOT in artifact (not written):")
            for r in rejected[:10]:
                print(f"           {r}")
        before = {f: list((entry.get('evidence', {}) or {}).get(f) or []) for f in EVIDENCE_FIELDS}
        after = {f: sort_event_ids(accepted[f]) if f == "event_ids" else sort_text(accepted[f])
                 for f in EVIDENCE_FIELDS}
        if before != after:
            changed += 1
            if args.apply:
                _apply_base(entry, accepted)

    if args.apply and changed:
        gt_doc.setdefault("_metadata", {})["evidence_source"] = "csv+review"
        gt_path.write_text(json.dumps(gt_doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print("\n" + "=" * 70)
    print(f"packets with corrections: {len(packets) - skipped} | entries changed: {changed}")
    print(f"rejected values (absent from artifact): {total_rejected}")
    if args.apply:
        print(f"WROTE {gt_path}. Now run: python -m tools.validate_ground_truth -v")
    else:
        print("Dry-run. Re-run with --apply to write. Then validate_ground_truth.")
    return 1 if total_rejected else 0


if __name__ == "__main__":
    raise SystemExit(main())
