#!/usr/bin/env python3
"""Quarantine unusable CSV artefacts so benchmark runs skip them.

The tool operates on the EvtxECmd CSV corpus only; the binary EVTX is upstream
provenance and is never parsed. Metadata entries are keyed by their `.evtx`
``full_path`` (a logical key) — the corresponding CSV is resolved by lowercased
stem via :func:`core.csv_evidence.resolve_csv`. A CSV that parses to 0 events is
"unusable" and gets moved to the CSV quarantine tree with its metadata entry
marked excluded.
"""

from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime
from pathlib import Path

from forcastl import config
from forcastl.core.csv_evidence import DEFAULT_CSV_DIR, build_csv_index, resolve_csv
from forcastl.core.parser import EVTXParser


def _move_preserve_tree(src: Path, src_root: Path, dst_root: Path) -> Path:
    rel = src.relative_to(src_root)
    dst = dst_root / rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dst))
    return dst


def main():
    parser = argparse.ArgumentParser(description="Move unusable CSV samples to quarantine and exclude them.")
    parser.add_argument("--apply", action="store_true", help="Apply file moves and metadata updates.")
    args = parser.parse_args()

    metadata_path = config.METADATA_FILE
    csv_root = Path(DEFAULT_CSV_DIR)
    csv_quarantine = config.DATA_DIR / "csv_quarantine"

    with open(metadata_path, "r", encoding="utf-8") as f:
        metadata = json.load(f)
    files = metadata.get("files", {})

    csv_index = build_csv_index(csv_root)
    parser_obj = EVTXParser(verbose=False)
    unusable = []
    for name, info in files.items():
        if info.get("excluded"):
            continue
        # Metadata `full_path` is the logical .evtx key; resolve the CSV by stem.
        # The binary EVTX is never parsed.
        csv_path = resolve_csv(info.get("full_path", "") or name, index=csv_index)
        if csv_path is None or not Path(csv_path).exists():
            continue
        events = parser_obj.parse_csv_file(csv_path)
        if len(events) == 0:
            unusable.append((name, info, Path(csv_path)))

    print(f"Found {len(unusable)} unusable CSV files (0 parsed events).")
    for name, _, csv_path in unusable:
        print(f" - {name} | {csv_path}")

    if not args.apply:
        print("\nDry run only. Re-run with --apply to move files and update metadata.")
        return

    now = datetime.now().isoformat(timespec="seconds")
    moved_count = 0
    for name, info, csv_path in unusable:
        # Move the unusable CSV to the quarantine tree (binary EVTX is left in
        # place as provenance and is never touched).
        _move_preserve_tree(csv_path, csv_root, csv_quarantine)

        # Mark excluded in metadata as before.
        info["excluded"] = True
        info["exclusion_reason"] = "unusable_csv_zero_events"
        info["excluded_at"] = now
        moved_count += 1

    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"\nMoved and excluded {moved_count} files.")
    print(f"CSV quarantine:  {csv_quarantine}")


if __name__ == "__main__":
    main()
