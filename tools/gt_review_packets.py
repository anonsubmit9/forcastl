#!/usr/bin/env python3
"""Build per-file ground-truth review packets, using a model run as the oracle.

For the GT "expected" correction pass (see internal/plans): a strong model's run
flags where GT and the artifact disagree. For every processed file in a detection
run CSV, this computes:

  * the artifact XML the model actually saw (reconstructed from the source CSV),
  * the current GT "expected" (the base evidence fields the live scorer compares against),
  * the model's detected evidence (re-parsed from its response),
  * the delta the reviewer must adjudicate:
      - under_population: model reported an item NOT in expected that IS in the
        artifact  -> GT should ADD it (this is the reported symptom; it can occur
        even at 100% alignment),
      - gt_missed_by_model: expected item the model did NOT report  -> adjudicate
        (genuine model miss vs a wrong/over-specified GT item).

A file is a TRIAGE CANDIDATE if it has any artifact-present under-population OR
Alignment % < 100. Packets for candidates are written to outputs/gt_review/.

Matching reuses the scorer's own logic (`hallucination.item_in_actual`,
`present_in_artefact`) so the delta reflects what scoring actually credits.

    python -m tools.gt_review_packets --run outputs/detection_results_<model>_<ts>.csv
    python -m tools.gt_review_packets --run <csv> --all      # packet for every file, not just candidates
"""
from __future__ import annotations

import argparse
import csv as _csv
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

from forcastl import config
from forcastl.core.parser import EVTXParser
from forcastl.core.response_parser import parse_structured_response
from forcastl.core.csv_evidence import DEFAULT_CSV_DIR, build_csv_index, resolve_csv
from forcastl.core.hallucination import (
    EVIDENCE_FIELDS, item_in_actual, present_in_artefact, _normalize_artefact,
)

_EVTX = EVTXParser()


def _read_run_rows(run_csv: Path) -> List[Dict[str, str]]:
    lines = run_csv.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    start = next((i for i, l in enumerate(lines) if l.startswith("Model,Filename")), None)
    if start is None:
        raise ValueError(f"{run_csv}: no 'Model,Filename' header row found")
    return list(_csv.DictReader(lines[start:]))


def _gt_entry(gt: Dict, fname: str) -> Optional[Dict]:
    e = gt.get(fname)
    if e is None and fname.lower().endswith(".csv"):
        e = gt.get(fname[:-4] + ".evtx")
    return e


def _scored_expected(ev: Dict) -> Dict[str, List[str]]:
    """The expected the scorer actually compares against.

    The live scorer (`ground_truth_compare._expected`) compares against the
    **base** evidence field — the `attack_*` curated-subset precedence was retired.
    This must use base too, else the triage under-reports: a real read that sits in
    `attack_*` but is missing from base (empty-base attack files) would look matched
    and never surface as under-population (e.g. CrackMapExec / LSASS / SQL files).
    """
    return {f: list(ev.get(f) or []) for f in EVIDENCE_FIELDS}


def _status(row: Dict[str, str]) -> str:
    return (row.get("Status") or "processed").strip().lower()


def _alignment(row: Dict[str, str]) -> Optional[float]:
    raw = (row.get("Alignment %") or "").strip()
    try:
        return float(raw)
    except ValueError:
        return None


def build_packet(row: Dict[str, str], gt: Dict, csv_index: Dict[str, str]) -> Optional[Dict]:
    fname = row.get("Filename")
    if not fname or _status(row) != "processed":
        return None
    entry = _gt_entry(gt, fname)
    if entry is None:
        return None

    csv_path = resolve_csv(fname, csv_index)
    if not csv_path or not Path(csv_path).is_file():
        return None
    events = _EVTX.parse_csv_file(csv_path)
    artefact = _EVTX.format_for_llm_pure_raw_xml(events)
    artefact_norm = _normalize_artefact(artefact)

    ev = entry.get("evidence", {}) or {}
    scored = _scored_expected(ev)
    base = {f: list(ev.get(f) or []) for f in EVIDENCE_FIELDS}

    detected = parse_structured_response(row.get("LLM Response", "") or "", clean=True).get(
        "evidence", {}) or {}
    detected = {f: list(detected.get(f) or []) for f in EVIDENCE_FIELDS}

    # delta: model reported items NOT already credited by expected.
    under_pop: Dict[str, List[Dict]] = {}
    for f in EVIDENCE_FIELDS:
        exp_set = set(scored.get(f, []))
        items = []
        for it in detected.get(f, []):
            if not str(it).strip() or item_in_actual(it, exp_set, f):
                continue
            in_art = (f == "event_ids" and str(it).strip() in exp_set) or (
                f != "event_ids" and present_in_artefact(it, artefact_norm))
            items.append({"value": it, "in_artifact": bool(in_art)})
        if items:
            under_pop[f] = items

    # expected items the model did not report (misalignment cause).
    missed: Dict[str, List[str]] = {}
    for f in EVIDENCE_FIELDS:
        det_set = set(detected.get(f, []))
        miss = [it for it in scored.get(f, []) if it and not item_in_actual(it, det_set, f)]
        if miss:
            missed[f] = miss

    align = _alignment(row)
    has_artifact_underpop = any(
        d["in_artifact"] for items in under_pop.values() for d in items)
    reasons = []
    if has_artifact_underpop:
        reasons.append("under_population")
    if align is not None and align < 100.0:
        reasons.append("misalignment")

    return {
        "file": fname,
        "gt_key": fname[:-4] + ".evtx" if fname.lower().endswith(".csv") else fname,
        "malicious": entry.get("malicious"),
        "alignment_pct": align,
        "triage_reasons": reasons,
        "is_candidate": bool(reasons),
        "artefact_xml": artefact,
        "scored_expected": scored,
        "base_expected": base,
        "model_detected": detected,
        "under_population": under_pop,       # add to GT if in_artifact
        "gt_missed_by_model": missed,        # adjudicate: model miss vs wrong GT
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Build GT review packets from a model run.")
    ap.add_argument("--run", required=True, help="Detection run CSV (the oracle model's run).")
    ap.add_argument("--out", default=None, help="Output dir (default: outputs/gt_review).")
    ap.add_argument("--all", action="store_true",
                    help="Emit a packet for every processed file, not just triage candidates.")
    ap.add_argument("--csv-dir", default=str(DEFAULT_CSV_DIR), help="Source CSV corpus root.")
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])

    config.require_data_dir()
    gt = json.loads(Path(config.GROUND_TRUTH_FILE).read_text(encoding="utf-8"))["files"]
    csv_index = build_csv_index(args.csv_dir)
    rows = _read_run_rows(Path(args.run))

    out_dir = Path(args.out) if args.out else (config.OUTPUTS_DIR / "gt_review")
    out_dir.mkdir(parents=True, exist_ok=True)

    candidates, total, written = [], 0, 0
    for row in rows:
        packet = build_packet(row, gt, csv_index)
        if packet is None:
            continue
        total += 1
        if packet["is_candidate"]:
            candidates.append(packet["file"])
        if packet["is_candidate"] or args.all:
            safe = packet["file"].replace("/", "_").replace("\\", "_")
            (out_dir / f"{safe}.json").write_text(json.dumps(packet, indent=2), encoding="utf-8")
            written += 1

    index = {
        "run": str(Path(args.run).name),
        "processed_files": total,
        "candidates": sorted(candidates),
        "candidate_count": len(candidates),
        "packets_written": written,
    }
    (out_dir / "_index.json").write_text(json.dumps(index, indent=2), encoding="utf-8")

    print(f"processed files: {total}")
    print(f"triage candidates (GT-vs-model disagreement): {len(candidates)}")
    print(f"packets written: {written} → {out_dir}")
    print("Review each packet's `under_population` (add items where in_artifact=true) and "
          "`gt_missed_by_model` (adjudicate), then apply with tools.gt_apply_review.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
