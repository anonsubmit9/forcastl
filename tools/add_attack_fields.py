"""One-off: add `attack_processes` / `attack_accounts` / `attack_commands` sidecar
fields to ground_truth_evidence.json, then rebuild `processes` / `accounts` /
`commands` as full inventories from the source CSV corpus.

Semantics after this script runs:
  - evidence.processes / accounts / commands  = full inventory of what the source
    file actually contains (regenerated via core.csv_evidence.evidence_from_events,
    the same noise-filtered aggregation the GT pipeline uses, so GT and the
    hallucination-check stay fully self-consistent).
  - evidence.attack_processes / attack_accounts / attack_commands = curated subset
    that is part of the malicious activity. For benign files (`malicious: NO`),
    these fields are empty lists.

event_ids / network / registry are left untouched (not in scope for this pass).

Usage:
    python scripts/add_attack_fields.py
"""
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))   # import forcastl from a clone w/o install

from forcastl import config
from forcastl.core.csv_evidence import (
    build_csv_index,
    evidence_from_events,
    read_csv_events,
    resolve_csv,
    sort_text,
)


def seed_attack_fields(entry: dict, events: list) -> dict:
    """Seed the `attack_*` sidecars and rebuild the full inventory for ONE entry.

    Shared by this script's corpus-wide pass and ``add_sample.py``'s single-file
    add, so both produce byte-identical evidence semantics:

      - ``attack_processes`` / ``attack_accounts`` / ``attack_commands`` — captured
        ONLY if not already present, so re-runs never clobber a curated subset.
        For malicious entries they snapshot the current curated lists; for benign
        (``malicious != "YES"``) they are empty lists.
      - ``processes`` / ``accounts`` / ``commands`` — rebuilt as the full,
        noise-filtered inventory from the parsed CSV ``events`` (the same
        aggregation the GT pipeline uses), so GT stays self-consistent with the
        hallucination check.

    ``event_ids`` / ``network`` / ``registry`` are left untouched. Mutates and
    returns ``entry``.
    """
    evidence = entry.setdefault("evidence", {})
    is_malicious = entry.get("malicious") == "YES"
    if "attack_processes" not in evidence:
        if is_malicious:
            evidence["attack_processes"] = list(evidence.get("processes", []))
            evidence["attack_accounts"] = list(evidence.get("accounts", []))
            evidence["attack_commands"] = list(evidence.get("commands", []))
        else:
            evidence["attack_processes"] = []
            evidence["attack_accounts"] = []
            evidence["attack_commands"] = []

    inv = evidence_from_events(events)
    # Same case-insensitive order as sync_ground_truth_evidence, so the corpus
    # keeps ONE order and re-running this pass on a synced corpus is a no-op.
    evidence["processes"] = sort_text(inv["processes"])
    evidence["accounts"] = sort_text(inv["accounts"])
    evidence["commands"] = sort_text(inv["commands"])
    return entry


def main():
    gt_path = config.GROUND_TRUTH_FILE

    gt = json.loads(gt_path.read_text(encoding="utf-8"))

    # Build the CSV stem index ONCE before the per-entry loop. The CSV corpus is
    # the source of truth for ground truth; nothing here parses binary EVTX.
    csv_index = build_csv_index()

    stats = {
        "total": 0,
        "regenerated_csv": 0,
        "skipped_no_csv": 0,
        "skipped_parse_error": 0,
        "benign": 0,
    }

    for fname, entry in gt["files"].items():
        stats["total"] += 1
        if entry.get("malicious") != "YES":
            stats["benign"] += 1

        # Resolve the GT entry to its CSV by lowercased stem. The entry name is
        # keyed by `.evtx`, but resolve_csv matches the stem against the CSV
        # corpus (the same resolution the runtime uses to score CSV runs), so
        # ID33205-….evtx -> ID33205-….csv. Metadata full_path (which points at
        # test_data/evtx/...) is no longer consulted for path resolution.
        csv_path = resolve_csv(fname, csv_index)
        if not csv_path:
            stats["skipped_no_csv"] += 1
            print(f"[skip:no-csv] {fname}")
            continue

        try:
            events = read_csv_events(csv_path)
        except Exception as exc:
            stats["skipped_parse_error"] += 1
            print(f"[skip:parse-error] {fname}: {exc!r}")
            continue

        if not events:
            stats["skipped_parse_error"] += 1
            print(f"[skip:no-events] {fname}")
            continue

        # Snapshot attack_* (once) and rebuild the noise-filtered inventory — the
        # same per-entry logic add_sample.py uses, so single-file adds match.
        seed_attack_fields(entry, events)
        stats["regenerated_csv"] += 1

    # Preserve the on-disk field order so downstream JSON diffs are reviewable:
    # ensure_ascii=False keeps unicode as-is, indent=2 matches existing style.
    gt_path.write_text(
        json.dumps(gt, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print()
    print("=" * 60)
    for key, val in stats.items():
        print(f"  {key:30s}: {val}")
    print("=" * 60)


if __name__ == "__main__":
    main()
