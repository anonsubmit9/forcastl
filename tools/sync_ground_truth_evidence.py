#!/usr/bin/env python3
"""Synchronize ground_truth_evidence.json evidence fields from CSV content.

For every file entry in ground_truth_evidence.json this script reparses the
corresponding artefact and rewrites the six core evidence sets
  evidence.event_ids / processes / accounts / commands / network / registry
from the actual parsed events. Curated subfields (attack_processes,
attack_accounts, attack_commands, ...) and every non-evidence key are preserved.

Evidence is read straight from each EvtxECmd CSV's structured Payload JSON (no
XML round-trip), via the shared CSV reader (core/csv_evidence) — the SAME
extraction the validator and audits use, resolved by (lowercased) stem from
--csv-dir. This grounds the ground truth in the exact bytes the benchmark scores.

Regenerate the canonical ground truth from the CSV corpus:

  python sync_ground_truth_evidence.py            # -> ground_truth_evidence.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Set

from forcastl import config
from forcastl.core.csv_evidence import (
    DEFAULT_CSV_DIR,
    build_csv_index,
    evidence_from_csv,
    resolve_csv,
    sort_event_ids,
    sort_text,
)


FIELDS = ("event_ids", "processes", "accounts", "commands", "network", "registry")


def _apply_evidence(entry: Dict, evidence: Dict[str, Set[str]]) -> None:
    """Rewrite only the six core fields in place; preserve all other subkeys."""
    ev = entry.setdefault("evidence", {})
    ev["event_ids"] = sort_event_ids(evidence["event_ids"])
    ev["processes"] = sort_text(evidence["processes"])
    ev["accounts"] = sort_text(evidence["accounts"])
    ev["commands"] = sort_text(evidence["commands"])
    ev["network"] = sort_text(evidence["network"])
    ev["registry"] = sort_text(evidence["registry"])


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Rebuild ground_truth evidence fields from parsed CSV content."
    )
    ap.add_argument(
        "--csv-dir",
        default=str(DEFAULT_CSV_DIR),
        help="CSV corpus root (default: test_data/csv).",
    )
    ap.add_argument(
        "--ground-truth",
        default=str(config.GROUND_TRUTH_FILE),
        help="Path to ground_truth_evidence.json (input).",
    )
    ap.add_argument(
        "--output",
        default=None,
        help="Output path. Defaults to overwrite --ground-truth.",
    )
    ap.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print per-file progress.",
    )
    args = ap.parse_args()

    gt_path = Path(args.ground_truth)
    out_path = Path(args.output) if args.output else gt_path

    with gt_path.open("r", encoding="utf-8") as f:
        gt = json.load(f)

    gt_files = gt.get("files", {})

    csv_index = build_csv_index(Path(args.csv_dir))
    print(f"Indexed {len(csv_index)} CSV files under {args.csv_dir}")

    updated = 0
    skipped_missing_artefact = 0

    for filename, entry in gt_files.items():
        csv_path = resolve_csv(filename, csv_index)
        if not csv_path:
            skipped_missing_artefact += 1
            if args.verbose:
                print(f"[SKIP] {filename}: no CSV for stem")
            continue
        evidence = evidence_from_csv(csv_path)

        _apply_evidence(entry, evidence)
        updated += 1
        if args.verbose:
            print(f"[OK] {filename}: updated evidence from csv")

    # Self-document which artefact source produced this file's evidence.
    gt.setdefault("_metadata", {})["evidence_source"] = "csv"

    with out_path.open("w", encoding="utf-8") as f:
        json.dump(gt, f, indent=2, ensure_ascii=False)

    print(
        f"Source csv | updated {updated} | "
        f"skipped missing artefact: {skipped_missing_artefact} | "
        f"output: {out_path}"
    )


if __name__ == "__main__":
    main()
