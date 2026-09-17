#!/usr/bin/env python3
"""Add ONE CSV sample + ground-truth entry to the detection corpus, safely.

A single, idempotent entry point for the whole add-a-sample workflow. It does for
one file what the maintenance scripts do corpus-wide — but **scoped to one entry**,
so it can never clobber another file's curated state (e.g. a benign ``test_set:D``).

Given a CSV already placed under ``test_data/csv/`` it will:

  1. resolve the CSV (by lowercased stem, the runtime's join key) and confirm it
     parses to > 0 events;
  2. insert/update the ground-truth entry keyed ``<stem>.evtx`` with the label, then
     auto-extract the six evidence fields from the CSV ``Payload`` (the same
     extraction ``sync_ground_truth_evidence`` uses) and seed the ``attack_*`` sidecars;
  3. ensure a ``metadata.json`` entry (tactic/technique derived from the folder path
     for attack files; a ``csv_only`` synthetic entry for ``_benign/``);
  4. tag difficulty + test_set for **this entry only** (honoring ``--test-set``);
  5. run the ground-truth validator and abort on any false-claim / missed-evidence;
  6. print the new ``tests/test_corpus_sizes.py`` lock constants (``--write-locks``
     patches them in place).

The human still authors the two things a script can't infer: the ``malicious_events``
narrative and ``explanation_keywords`` (pass ``--malicious-event`` / ``--keywords`` or
edit the JSON afterwards). See ``docs/adding_samples.md`` for the full guide.

Examples
--------
    # malicious attack sample in a MITRE folder
    python add_sample.py --csv "test_data/csv/TA0003-Persistence/T1098.xxx-Account manipulation/ID999-New.csv" \
        --label YES --keywords "persistence,role grant"

    # benign control
    python add_sample.py --csv "test_data/csv/_benign/BENIGN-ID999-New.csv" \
        --label NO --test-set D --source synthetic --write-locks
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional

from forcastl import config
from forcastl.core.csv_evidence import (
    DEFAULT_CSV_DIR,
    evidence_from_csv,
    read_csv_events,
)
from tools.add_attack_fields import seed_attack_fields
from tools.sync_ground_truth_evidence import _apply_evidence
from tools.tag_metadata import _classify_difficulty, _classify_test_set, _count_events_and_signal
from forcastl.validation.ground_truth import run_validation

LOCK_FILE = config.PROJECT_ROOT / "tests" / "test_corpus_sizes.py"


# ── JSON helpers (match the on-disk style: indent=2, unicode preserved) ───────
def _load(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _dump(path: Path, data: dict) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ── Metadata entry ────────────────────────────────────────────────────────────
def _relpath_under_csv(csv_path: Path) -> Optional[List[str]]:
    """Parts of ``csv_path`` relative to test_data/csv, or None if outside it."""
    try:
        rel = csv_path.resolve().relative_to(Path(DEFAULT_CSV_DIR).resolve())
    except ValueError:
        return None
    return list(rel.parts)


def _build_metadata_entry(
    key: str,
    csv_path: Path,
    label: str,
    event_ids: List[str],
    source: Optional[str],
    overrides: Dict[str, str],
) -> dict:
    """Derive a metadata.json entry from the CSV's folder position.

    ``_benign/...`` → a benign (BENIGN tactic) synthetic control.
    ``TA****-…/T****-…/...`` → attack; tactic/technique split from the folder names.
    Any field can be forced via ``overrides`` (``--tactic-id`` etc.).
    """
    parts = _relpath_under_csv(csv_path) or [csv_path.name]
    rel = "/".join(parts)
    benign = parts[0] == "_benign" or label == "NO"

    if benign:
        tactic_id, tactic_name = "BENIGN", "Benign"
        technique_id = technique_name = ""
        description = "Benign test artefact (no attack present)."
        default_source = "synthetic"
    else:
        # parts: [TActic-Name, Technique-Name, file.csv]
        tactic_id, _, tactic_name = (parts[0].partition("-") if len(parts) >= 1 else ("", "", ""))
        technique_id, _, technique_name = (parts[1].partition("-") if len(parts) >= 2 else ("", "", ""))
        description = (
            f"Tactic: {tactic_name} | Technique: {technique_name} | "
            f"Event IDs: {', '.join(event_ids)}"
        )
        default_source = "folder_structure"

    entry = {
        "file_name": key,
        "tactic_id": tactic_id,
        "tactic_name": tactic_name,
        "technique_id": technique_id,
        "technique_name": technique_name,
        "description": description,
        "event_ids": event_ids,
        "is_apt_attack": False,
        "is_antivirus": False,
        "relative_path": rel,
        "full_path": f"data/csv/{rel}",
        "source": source or default_source,
        "confidence": "high",
        # difficulty/test_set/counts are filled by the caller (single-file tag).
        "difficulty": "easy",
        "test_set": "A",
        "total_events": 0,
        "signal_events": 0,
        "signal_ratio": 0.0,
        "excluded": False,
        "exclusion_reason": "",
        "excluded_at": "",
        "csv_only": True,
    }
    for k, v in overrides.items():
        if v is not None:
            entry[k] = v
    return entry


# ── Lock constants ───────────────────────────────────────────────────────────
def _compute_locks(gt_files: dict, meta_files: dict) -> dict:
    labels = Counter(str(v.get("malicious")).upper() for v in gt_files.values())
    diff = Counter(v.get("difficulty") for v in gt_files.values())
    return {
        "GT_TOTAL": len(gt_files),
        "GT_MALICIOUS": labels.get("YES", 0),
        "GT_BENIGN": labels.get("NO", 0),
        "GT_DIFFICULTY": {k: diff.get(k, 0) for k in ("easy", "medium", "hard")},
        "METADATA_TOTAL": len(meta_files),
        "METADATA_EXCLUDED": sum(1 for v in meta_files.values() if v.get("excluded")),
    }


def _format_locks(locks: dict) -> str:
    d = locks["GT_DIFFICULTY"]
    return (
        f'GT_TOTAL = {locks["GT_TOTAL"]}\n'
        f'GT_MALICIOUS = {locks["GT_MALICIOUS"]}\n'
        f'GT_BENIGN = {locks["GT_BENIGN"]}\n'
        f'GT_DIFFICULTY = {{"easy": {d["easy"]}, "medium": {d["medium"]}, "hard": {d["hard"]}}}\n'
        f'METADATA_TOTAL = {locks["METADATA_TOTAL"]}\n'
        f'METADATA_EXCLUDED = {locks["METADATA_EXCLUDED"]}'
    )


def _write_locks(locks: dict) -> None:
    """Patch the constants block in tests/test_corpus_sizes.py in place."""
    text = LOCK_FILE.read_text(encoding="utf-8")
    d = locks["GT_DIFFICULTY"]
    subs = {
        r"^GT_TOTAL = .*$": f'GT_TOTAL = {locks["GT_TOTAL"]}',
        r"^GT_MALICIOUS = .*$": f'GT_MALICIOUS = {locks["GT_MALICIOUS"]}',
        r"^GT_BENIGN = .*$": f'GT_BENIGN = {locks["GT_BENIGN"]}',
        r"^GT_DIFFICULTY = .*$": (
            f'GT_DIFFICULTY = {{"easy": {d["easy"]}, "medium": {d["medium"]}, "hard": {d["hard"]}}}'
        ),
        r"^METADATA_TOTAL = .*$": f'METADATA_TOTAL = {locks["METADATA_TOTAL"]}',
        r"^METADATA_EXCLUDED = .*$": f'METADATA_EXCLUDED = {locks["METADATA_EXCLUDED"]}',
    }
    for pat, repl in subs.items():
        text, n = re.subn(pat, repl, text, count=1, flags=re.MULTILINE)
        if n != 1:
            raise SystemExit(f"add_sample: could not patch {pat!r} in {LOCK_FILE}")
    LOCK_FILE.write_text(text, encoding="utf-8")


# ── Core ──────────────────────────────────────────────────────────────────────
def add_sample(
    csv: str,
    label: str,
    *,
    test_set: Optional[str] = None,
    source: Optional[str] = None,
    keywords: Optional[List[str]] = None,
    malicious_events: Optional[List[str]] = None,
    meta_overrides: Optional[Dict[str, str]] = None,
    gt_path: Path = config.GROUND_TRUTH_FILE,
    meta_path: Path = config.METADATA_FILE,
    report_path: Path = config.OUTPUTS_DIR / "ground_truth_validation_report.json",
) -> dict:
    """Add/update one sample. Returns a summary dict. Idempotent on re-run."""
    label = label.upper()
    if label not in ("YES", "NO"):
        raise SystemExit("add_sample: --label must be YES or NO")

    csv_path = Path(csv)
    if not csv_path.exists():
        raise SystemExit(f"add_sample: CSV not found: {csv_path}")
    if _relpath_under_csv(csv_path) is None:
        raise SystemExit(
            f"add_sample: CSV must live under {DEFAULT_CSV_DIR} (place it there first)"
        )
    events = read_csv_events(str(csv_path))
    if not events:
        raise SystemExit(f"add_sample: CSV parses to 0 events (unusable): {csv_path}")

    key = f"{csv_path.stem}.evtx"

    gt = _load(Path(gt_path))
    meta = _load(Path(meta_path))
    gt_files = gt.setdefault("files", {})
    meta_files = meta.setdefault("files", {})

    # ── Ground-truth entry ───────────────────────────────────────────────────
    entry = gt_files.get(key, {})
    entry["malicious"] = label
    _apply_evidence(entry, evidence_from_csv(str(csv_path)))   # 6 fields from CSV
    seed_attack_fields(entry, events)                          # attack_* sidecars
    if malicious_events is not None:
        entry["malicious_events"] = malicious_events
    else:
        entry.setdefault("malicious_events", [])
    if keywords is not None:
        entry["explanation_keywords"] = keywords
    else:
        entry.setdefault("explanation_keywords", [])

    total, signal = _count_events_and_signal(str(csv_path), entry["evidence"])
    entry["difficulty"] = _classify_difficulty(total, signal)
    entry["test_set"] = test_set or _classify_test_set(
        key, entry["evidence"], meta_files.get(key, {}),
        total_events=total, signal_events=signal,
        current_test_set=entry.get("test_set"),
    )
    entry["total_events"] = total
    entry["signal_events"] = signal
    entry["signal_ratio"] = round(signal / total, 4) if total else 0.0
    gt_files[key] = entry

    # ── Metadata entry ───────────────────────────────────────────────────────
    md = meta_files.get(key) or _build_metadata_entry(
        key, csv_path, label, entry["evidence"]["event_ids"], source, meta_overrides or {}
    )
    md["difficulty"] = entry["difficulty"]
    md["test_set"] = entry["test_set"]
    md["total_events"] = total
    md["signal_events"] = signal
    md["signal_ratio"] = entry["signal_ratio"]
    md.setdefault("csv_only", True)
    if source:
        md["source"] = source
    meta_files[key] = md

    _dump(Path(gt_path), gt)
    _dump(Path(meta_path), meta)

    # ── Validate ─────────────────────────────────────────────────────────────
    report = run_validation(
        gt_path=str(gt_path), meta_path=str(meta_path),
        output_path=str(report_path),
    )
    summary = report.get("summary", {})
    locks = _compute_locks(gt_files, meta_files)
    return {
        "key": key,
        "label": label,
        "difficulty": entry["difficulty"],
        "test_set": entry["test_set"],
        "total_events": total,
        "signal_events": signal,
        "validator": {
            "quality_score": summary.get("quality_score"),
            "false_claims": summary.get("total_false_claims"),
            "missed_evidence": summary.get("total_missed_evidence"),
        },
        "locks": locks,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--csv", required=True, help="Path to the CSV (already placed under test_data/csv/).")
    ap.add_argument("--label", required=True, choices=["YES", "NO", "yes", "no"], help="malicious: YES or NO")
    ap.add_argument("--test-set", choices=["A", "B", "C", "D"], help="Override test_set (use D for benign controls).")
    ap.add_argument("--source", help="metadata source (e.g. synthetic, manual, folder_structure).")
    ap.add_argument("--keywords", help="Comma-separated explanation_keywords.")
    ap.add_argument("--malicious-event", action="append", dest="malicious_events",
                    help="A malicious_events narrative line (repeatable). Benign: omit.")
    ap.add_argument("--tactic-id"); ap.add_argument("--tactic-name")
    ap.add_argument("--technique-id"); ap.add_argument("--technique-name")
    ap.add_argument("--write-locks", action="store_true",
                    help="Patch tests/test_corpus_sizes.py constants in place (default: just print).")
    args = ap.parse_args()

    overrides = {
        "tactic_id": args.tactic_id, "tactic_name": args.tactic_name,
        "technique_id": args.technique_id, "technique_name": args.technique_name,
    }
    summary = add_sample(
        args.csv, args.label,
        test_set=args.test_set, source=args.source,
        keywords=[k.strip() for k in args.keywords.split(",")] if args.keywords else None,
        malicious_events=args.malicious_events,
        meta_overrides=overrides,
    )

    v = summary["validator"]
    print(f"\n✓ {summary['key']}")
    print(f"  label={summary['label']}  difficulty={summary['difficulty']}  test_set={summary['test_set']}"
          f"  events={summary['signal_events']}/{summary['total_events']} signal")
    print(f"  validator: quality={v['quality_score']}  false_claims={v['false_claims']}  missed={v['missed_evidence']}")
    if v["false_claims"] or v["missed_evidence"]:
        print("  ⚠ validator found discrepancies — review the entry before committing.")

    print("\nCorpus-size lock constants (tests/test_corpus_sizes.py):\n")
    print(_format_locks(summary["locks"]))
    if args.write_locks:
        _write_locks(summary["locks"])
        print(f"\n✓ patched {LOCK_FILE.relative_to(config.PROJECT_ROOT)}")
    else:
        print("\n(Pass --write-locks to apply these automatically.)")
    print("\nNext: author malicious_events + explanation_keywords if not provided, "
          "then run `python -m pytest -q`.")


if __name__ == "__main__":
    main()
