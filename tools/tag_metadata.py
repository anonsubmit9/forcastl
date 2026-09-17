#!/usr/bin/env python3
"""
Tag Metadata — adds `difficulty` and `test_set` fields to
ground_truth_evidence.json and metadata.json.

Re-runnable. By DEFAULT it preserves existing `difficulty`/`test_set` (they are
curated benchmark properties — APT difficulty and benign `test_set:D` controls are
hand-assigned, not pure signal-ratio output) and only derives them for entries that
lack them; factual stats (total/signal/ratio) always refresh. Pass `--recompute` to
re-derive every label from the heuristic (overwrites curation — see known_issues).

Difficulty logic (signal-to-noise ratio):
  Reads each file's CSV (the source of truth for ground truth) and checks
  every event for overlap with the ground truth evidence (processes,
  accounts, commands, network, registry — not just Event IDs, since all
  events in a file typically share the same Event ID).

  An event counts as "signal" if it contains at least one specific
  evidence item from the ground truth (a matching process name, account,
  command substring, IP address, or registry key).

  easy   — signal_ratio >= 0.5 OR total_events <= 10
  hard   — signal_ratio < 0.15 AND total_events > 20
  medium — everything else

Test set logic:
  B (Obfuscated) — commands/filename contain obfuscation indicators
  C (Noise-heavy) — low signal-to-noise ratio (signal < 30% AND > 15 events)
  A (Known Pattern) — everything else
"""

import json
from pathlib import Path

from tqdm import tqdm

from forcastl import config
from forcastl.core.csv_evidence import build_csv_index, read_csv_events, resolve_csv
from forcastl.validation.ground_truth import extract_evidence_from_event

# ---------------------------------------------------------------------------
# Obfuscation detection (for test-set tagging)
# ---------------------------------------------------------------------------

OBFUSCATION_TERMS = [
    'base64', 'encoded', 'obfuscat', 'invoke-expression', 'iex',
    'env:', '$env:', 'frombase64', '-enc', '-encodedcommand',
    'get-c`ommand', 'bypass', 'hidden', '-w hidden', '-nop',
    'downloadstring', 'invoke-webrequest', 'wmimplant', 'empire',
    'cobaltstrike', 'cobalt strike', 'meterpreter',
]

OBFUSCATION_FILENAME_TERMS = [
    'wmimplant', 'obfuscat', 'encoded', 'empire', 'cobaltstrike',
    'meterpreter', 'bypass',
]


def _count_evidence_fields(evidence: dict) -> int:
    """Count non-empty evidence fields."""
    return sum(1 for v in evidence.values() if v)


def _has_obfuscation(filename: str, evidence: dict) -> bool:
    fn_lower = filename.lower()
    for term in OBFUSCATION_FILENAME_TERMS:
        if term in fn_lower:
            return True

    commands = evidence.get('commands', [])
    for cmd in commands:
        cmd_lower = cmd.lower()
        for term in OBFUSCATION_TERMS:
            if term in cmd_lower:
                return True
    return False


def _classify_test_set(filename: str, evidence: dict, metadata_entry: dict,
                       total_events: int = 0, signal_events: int = 0,
                       current_test_set: str | None = None) -> str:
    # D — Benign control. There is no derivation path TO 'D' (benign samples are
    # curated, not signal-classified), so a pre-assigned 'D' is authoritative and
    # MUST be preserved — otherwise a re-run silently rewrites every benign's
    # test_set to A/B/C, breaking the "D = benign" convention and `--test-set D`.
    if current_test_set == 'D':
        return 'D'

    # B — Obfuscated
    if _has_obfuscation(filename, evidence):
        return 'B'

    # C — Noise-heavy: low signal-to-noise ratio
    if total_events > 15:
        ratio = signal_events / total_events
        if ratio < 0.3:
            return 'C'

    # A — Known Pattern
    return 'A'


# ---------------------------------------------------------------------------
# Signal-to-noise: check if an event matches specific ground truth evidence
# ---------------------------------------------------------------------------

def _build_match_sets(gt_evidence: dict) -> dict:
    """Pre-compute lowered match sets from ground truth evidence."""
    return {
        'processes': {Path(p.replace('\\', '/')).name.lower()
                      for p in gt_evidence.get('processes', []) if p},
        'accounts': {a.lower() for a in gt_evidence.get('accounts', []) if a},
        'commands': {c.lower() for c in gt_evidence.get('commands', []) if c},
        'network': {n.lower() for n in gt_evidence.get('network', []) if n},
        'registry': {r.lower().replace('\\', '/') for r in gt_evidence.get('registry', []) if r},
    }


def _event_has_signal(event_evidence: dict, match_sets: dict) -> bool:
    """Return True if this event contains at least one ground-truth evidence item.

    Checks processes, accounts, commands, network, registry — NOT event_ids
    (since every event in a file typically shares the same Event ID).
    """
    # Processes — filename match
    for proc in event_evidence.get('processes', set()):
        proc_name = Path(proc.replace('\\', '/')).name.lower()
        if proc_name in match_sets['processes']:
            return True

    # Accounts — exact lower match
    for acct in event_evidence.get('accounts', set()):
        if acct.lower() in match_sets['accounts']:
            return True

    # Commands — substring match
    for cmd in event_evidence.get('commands', set()):
        cmd_lower = cmd.lower()
        for gt_cmd in match_sets['commands']:
            if gt_cmd in cmd_lower or cmd_lower in gt_cmd:
                return True

    # Network — exact match
    for net in event_evidence.get('network', set()):
        if net.lower() in match_sets['network']:
            return True

    # Registry — substring match
    for reg in event_evidence.get('registry', set()):
        reg_norm = reg.lower().replace('\\', '/')
        for gt_reg in match_sets['registry']:
            if gt_reg in reg_norm or reg_norm in gt_reg:
                return True

    return False


def _count_events_and_signal(csv_path: str,
                             gt_evidence: dict) -> tuple:
    """Read a file's CSV and return (total_events, signal_events).

    signal_events = events containing at least one specific ground-truth
    evidence item (process, account, command, network, registry).
    """
    match_sets = _build_match_sets(gt_evidence)

    # If there's no specific evidence beyond event_ids, every event is
    # effectively signal (nothing to distinguish benign from malicious).
    has_specific_evidence = any(match_sets[k] for k in match_sets)

    try:
        events = read_csv_events(csv_path)
    except Exception:
        return 0, 0

    total = len(events)

    if not has_specific_evidence:
        # Can't distinguish — all events are equal
        return total, total

    signal = 0
    for event in events:
        ev = extract_evidence_from_event(event)
        if _event_has_signal(ev, match_sets):
            signal += 1

    return total, signal


def _classify_difficulty(total_events: int, signal_events: int) -> str:
    """Classify difficulty based on signal-to-noise ratio.

    easy   — signal_ratio >= 0.5 OR total_events <= 10
             (most events are relevant, or so few events there's little noise)
    hard   — signal_ratio < 0.15 AND total_events > 20
             (malicious activity buried in lots of benign noise)
    medium — everything else
    """
    if total_events <= 0:
        return 'easy'

    ratio = signal_events / total_events

    if total_events <= 10 or ratio >= 0.5:
        return 'easy'
    if total_events > 20 and ratio < 0.15:
        return 'hard'
    return 'medium'


def _resolve_curated(existing: str | None, derived: str, recompute: bool) -> str:
    """Keep a curated label, or fall back to the derived one.

    `difficulty`/`test_set` are curated benchmark properties — an existing value is
    authoritative and preserved, unless it is missing (a brand-new entry) or
    `recompute` forces a full heuristic re-derive.
    """
    return derived if (recompute or not existing) else existing


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "--recompute", action="store_true",
        help="Re-derive difficulty/test_set for ALL entries from the signal-ratio "
             "heuristic, overwriting curated labels. Default: PRESERVE existing "
             "difficulty/test_set (they are curated benchmark properties) and only "
             "derive them for entries that lack them. Factual stats "
             "(total/signal/ratio) are always refreshed.",
    )
    args = ap.parse_args()

    gt_path = config.GROUND_TRUTH_FILE
    meta_path = config.METADATA_FILE

    with open(gt_path, 'r', encoding='utf-8') as f:
        gt_data = json.load(f)

    with open(meta_path, 'r', encoding='utf-8') as f:
        meta_data = json.load(f)

    gt_files = gt_data.get('files', {})
    meta_files = meta_data.get('files', {})

    # CSV is the source of truth; resolve each entry to its CSV by lowercased
    # stem (built once for the loop below).
    csv_index = build_csv_index()

    # --- Pass 1: read CSV files to get event counts ---
    print("Reading CSV files to compute signal-to-noise ratios...")
    event_stats = {}  # filename -> (total, signal, ratio)

    filenames = list(gt_files.keys())
    for filename in tqdm(filenames, desc="Scanning CSV files"):
        gt_entry = gt_files[filename]
        evidence = gt_entry.get('evidence', {})

        # Resolve the entry to its CSV by lowercased stem
        csv_path = resolve_csv(filename, index=csv_index)

        if csv_path:
            total, signal = _count_events_and_signal(csv_path, evidence)
        else:
            total, signal = 0, 0

        ratio = signal / total if total > 0 else 0.0
        event_stats[filename] = (total, signal, ratio)

    # --- Pass 2: tag ground truth entries ---
    diff_counts = {'easy': 0, 'medium': 0, 'hard': 0}
    set_counts = {'A': 0, 'B': 0, 'C': 0, 'D': 0}

    for filename, entry in gt_files.items():
        evidence = entry.get('evidence', {})
        total, signal, ratio = event_stats.get(filename, (0, 0, 0.0))

        # Factual stats always refresh; difficulty/test_set are CURATED labels —
        # preserve them unless --recompute (a pure signal-ratio re-derive would
        # erase the hand-curated APT difficulty and the test_set:D benign controls).
        entry['total_events'] = total
        entry['signal_events'] = signal
        entry['signal_ratio'] = round(ratio, 4)

        difficulty = _resolve_curated(
            entry.get('difficulty'), _classify_difficulty(total, signal), args.recompute)
        entry['difficulty'] = difficulty
        diff_counts[difficulty] += 1

        meta_entry = meta_files.get(filename, {})
        test_set = _resolve_curated(
            entry.get('test_set'),
            _classify_test_set(filename, evidence, meta_entry,
                               total_events=total, signal_events=signal,
                               current_test_set=entry.get('test_set')),
            args.recompute)
        entry['test_set'] = test_set
        set_counts[test_set] += 1

    # --- Pass 3: tag metadata entries ---
    meta_diff_counts = {'easy': 0, 'medium': 0, 'hard': 0}
    meta_set_counts = {'A': 0, 'B': 0, 'C': 0, 'D': 0}

    for filename, entry in meta_files.items():
        gt_entry = gt_files.get(filename)
        if gt_entry:
            entry['difficulty'] = gt_entry['difficulty']
            entry['test_set'] = gt_entry['test_set']
            entry['total_events'] = gt_entry['total_events']
            entry['signal_events'] = gt_entry['signal_events']
            entry['signal_ratio'] = gt_entry['signal_ratio']
        else:
            # No ground truth — no CSV stats available, default to easy/A
            entry['difficulty'] = 'easy'
            entry['test_set'] = 'A'
            entry['total_events'] = 0
            entry['signal_events'] = 0
            entry['signal_ratio'] = 0.0

        meta_diff_counts[entry['difficulty']] += 1
        meta_set_counts[entry['test_set']] += 1

    # --- Write back ---
    with open(gt_path, 'w', encoding='utf-8') as f:
        json.dump(gt_data, f, indent=2, ensure_ascii=False)

    with open(meta_path, 'w', encoding='utf-8') as f:
        json.dump(meta_data, f, indent=2, ensure_ascii=False)

    # --- Report ---
    print()
    print("Ground Truth Evidence tagging complete:")
    print(f"  Difficulty  — easy: {diff_counts['easy']}, medium: {diff_counts['medium']}, hard: {diff_counts['hard']}")
    print(f"  Test Set    — A: {set_counts['A']}, B: {set_counts['B']}, C: {set_counts['C']}, D: {set_counts['D']}")
    print()
    print("Metadata tagging complete:")
    print(f"  Difficulty  — easy: {meta_diff_counts['easy']}, medium: {meta_diff_counts['medium']}, hard: {meta_diff_counts['hard']}")
    print(f"  Test Set    — A: {meta_set_counts['A']}, B: {meta_set_counts['B']}, C: {meta_set_counts['C']}, D: {meta_set_counts['D']}")

    # Show examples for each difficulty level
    print()
    print("Sample files by difficulty:")
    for d in ['easy', 'medium', 'hard']:
        count = 0
        for fn, entry in gt_files.items():
            if entry['difficulty'] == d:
                total = entry['total_events']
                signal = entry['signal_events']
                ratio = entry['signal_ratio']
                print(f"  [{d:6s}] {fn[:60]:60s}  {signal:>4d}/{total:>4d} events ({ratio:.0%} signal)")
                count += 1
                if count >= 3:
                    break
        if count == 0:
            print(f"  [{d:6s}] (none)")


if __name__ == '__main__':
    main()
