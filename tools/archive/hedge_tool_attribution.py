"""Targeted narrative-discipline pass on high-risk attribution clusters.

Editorial rule:
  If a tool name, tool subcommand, or example invocation is not a literal
  event substring, the narrative must explicitly mark it as inferential,
  illustrative, or analyst shorthand.

Strategy:
  1. Walk every malicious GT entry whose filename matches a high-risk cluster
     (TA0006 Credential Access, TA0008 Lateral Movement, plus entries citing
     Rubeus / Impacket / Mimikatz / PowerView / Kerbrute).
  2. Build the cross-event substring corpus from the source CSV.
  3. For each `malicious_events` string, find tool-DSL fingerprints (e.g.
     `module::command`, `secretsdump.py ...`, `Rubeus kerberoast ...`,
     `Get-DomainGroup ...`).
  4. If the matched fingerprint is NOT a substring of the event corpus AND
     the same narrative bullet doesn't already carry an inferential label,
     append one — choosing wording that preserves analytical content rather
     than sterilizing it.

The script writes proposed changes to a JSON diff file first; user runs
`--apply` to commit.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from forcastl.core.csv_evidence import build_csv_index, resolve_csv, read_csv_events  # noqa: E402


# ── Cluster matchers (filename-based) ─────────────────────────────────────────
HIGH_RISK_PATTERNS = [
    re.compile(r"(?i)mimikatz", re.I),
    re.compile(r"(?i)dcsync|dcshadow", re.I),
    re.compile(r"(?i)lsass", re.I),
    re.compile(r"(?i)dpapi", re.I),
    re.compile(r"(?i)secret(s)?dump|impacket", re.I),
    re.compile(r"(?i)kerberoast|kerbrute|asrep", re.I),
    re.compile(r"(?i)psexec|smbexec|wmiexec|atexec|dcomexec", re.I),
    re.compile(r"(?i)admin\$|admin share|net use|ntds|sam dump", re.I),
    re.compile(r"(?i)rubeus|powerview|sharphound|bloodhound", re.I),
    re.compile(r"(?i)crackmap|cme|tchopper|lsassy|rottenpotato", re.I),
]


# ── Tool-DSL fingerprints ─────────────────────────────────────────────────────
# Backticked Mimikatz / Rubeus / Impacket subcommand syntax.
RE_MIMIKATZ_DSL   = re.compile(r"`([a-z]+::[a-zA-Z][a-zA-Z0-9_/ ]*)`")
# Specific .py/.exe invocations with a flag-bearing argument:
#   `secretsdump.py admmig:<hash>@10.23.42.38`
#   `Rubeus.exe asreproast /domain:offsec.lan`
RE_TOOL_INVOCATION = re.compile(
    r"`([A-Za-z][A-Za-z0-9_-]+\.(?:py|exe|ps1)\s+[^`]+)`"
)
# Tool-family + verb pattern: `Rubeus brute`, `Kerbrute userenum`, etc.
RE_TOOL_VERB = re.compile(
    r"`((?:Rubeus|Kerbrute|Mimikatz|Impacket|CrackMap(?:Exec)?|cme|Hydra|"
    r"BloodHound|SharpHound|PowerView|secretsdump|GetUserSPNs|lsassy|DonPapi)"
    r"(?:\s+[A-Za-z][A-Za-z0-9_/.-]*){1,3})`",
    re.I,
)
# Get-Domain* / Get-AD* PowerView/AD-module commands with arg lists
RE_PS_RECON = re.compile(
    r"`((?:Get|Set|Invoke|New|Add)-(?:Domain|AD|Net|Forest|GP|WMI)[A-Za-z]+"
    r"(?:\s+-[A-Za-z]+\s+[^`]+)?)`"
)


HEDGE_SUFFIXES = {
    "mimikatz_dsl":     " (Mimikatz subcommand syntax — analyst shorthand for the technique; not literally logged).",
    "tool_invocation":  " (illustrative invocation — the literal command line is not in the events).",
    "tool_verb":        " (tool-family attribution — inferential from the event fingerprint).",
    "ps_recon":         " (cmdlet attribution — inferential; the cmdlet name itself is not always logged).",
}

# Words that already signal the surrounding sentence is hedged. If any of
# these appear within ~120 chars of the matched DSL, skip — already labeled.
HEDGE_WORDS = re.compile(
    r"(?i)inferential|illustrative|analyst[\s-]?shorthand|attribution|"
    r"\bnot in (the )?events?\b|\bnot literally\b|\bnot logged\b|"
    r"\bcompatible with\b|\bconsistent with\b|\bcharacteristic of\b|"
    r"\bcanonical\b.*\bsignature\b|"
    r"\bany DRSUAPI client\b|\bImpacket .* or .* tool\b"
)


def is_high_risk(filename: str) -> bool:
    return any(p.search(filename) for p in HIGH_RISK_PATTERNS)


def build_event_corpus(events) -> Set[str]:
    corpus: Set[str] = set()
    def walk(o):
        if isinstance(o, dict):
            for v in o.values(): walk(v)
        elif isinstance(o, list):
            for v in o: walk(v)
        elif isinstance(o, str) and o:
            # Whitespace-normalize so command-line double-spacing doesn't
            # cause false positives on the substring check.
            corpus.add(" ".join(o.split()).lower())
    for ev in events:
        walk(ev.get("Event") or {})
    return corpus


def in_corpus(claim: str, corpus: Set[str]) -> bool:
    cl = " ".join(claim.split()).lower()
    return any(cl in s for s in corpus)


def already_hedged(narrative: str, match_start: int, match_end: int) -> bool:
    """Look ~120 chars before/after the matched DSL for hedging language."""
    window = narrative[max(0, match_start - 120):min(len(narrative), match_end + 120)]
    return bool(HEDGE_WORDS.search(window))


def propose_hedges(narrative: str, corpus: Set[str]) -> List[Tuple[str, str, str]]:
    """Return list of (kind, matched_dsl, suggested_appended_hedge).

    The script doesn't rewrite the narrative inline — it proposes a
    hedge-phrase that should be appended to the bullet containing the DSL.
    The apply step does the actual append.
    """
    proposals = []
    for kind, regex in (
        ("mimikatz_dsl", RE_MIMIKATZ_DSL),
        ("tool_invocation", RE_TOOL_INVOCATION),
        ("tool_verb", RE_TOOL_VERB),
        ("ps_recon", RE_PS_RECON),
    ):
        for m in regex.finditer(narrative):
            dsl = m.group(1)
            if in_corpus(dsl, corpus):
                continue  # actually in the events; not a hedge candidate
            if already_hedged(narrative, m.start(), m.end()):
                continue
            proposals.append((kind, dsl, HEDGE_SUFFIXES[kind]))
    return proposals


def main():
    apply = "--apply" in sys.argv
    gt_path = PROJECT_ROOT / "ground_truth_evidence.json"
    gt = json.loads(gt_path.read_text(encoding="utf-8"))

    csv_index = build_csv_index()
    diffs: Dict[str, List[Dict]] = {}
    files_touched = 0
    bullets_touched = 0

    for fname, entry in gt["files"].items():
        if entry.get("malicious") != "YES":
            continue
        if not is_high_risk(fname):
            continue

        csv_path = resolve_csv(fname, csv_index)
        if not csv_path:
            continue
        try:
            events = read_csv_events(csv_path)
        except Exception:
            continue
        if not events:
            continue
        corpus = build_event_corpus(events)

        bullets = entry.get("malicious_events") or []
        new_bullets = list(bullets)
        per_file = []
        for i, b in enumerate(bullets):
            proposals = propose_hedges(b, corpus)
            if not proposals:
                continue
            # Pick the most-specific hedge in the bullet — if any DSL hit,
            # take the first one's hedge suffix and append once. Don't stack
            # multiple suffixes; one inferential label per bullet is enough
            # to communicate the discipline.
            kind, dsl, suffix = proposals[0]
            if not new_bullets[i].rstrip().endswith(suffix.strip()):
                new_bullets[i] = new_bullets[i].rstrip()
                if not new_bullets[i].endswith("."):
                    new_bullets[i] += "."
                new_bullets[i] += suffix
                per_file.append({
                    "bullet_index": i,
                    "matched_dsl": dsl,
                    "kind": kind,
                    "suffix": suffix,
                })
                bullets_touched += 1

        if per_file:
            diffs[fname] = per_file
            files_touched += 1
            if apply:
                entry["malicious_events"] = new_bullets

    print(f"\nFiles in scope (high-risk clusters): tallying...")
    print(f"Files with proposed hedges: {files_touched}")
    print(f"Bullets to be hedged: {bullets_touched}")
    print()

    diff_path = PROJECT_ROOT / "outputs" / "_hedge_proposals.json"
    diff_path.parent.mkdir(parents=True, exist_ok=True)
    diff_path.write_text(json.dumps(diffs, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Proposed hedges written to {diff_path}")

    if apply:
        gt_path.write_text(json.dumps(gt, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\n[APPLIED] {files_touched} entries updated in {gt_path}")
    else:
        print("\n(Dry-run — no changes written. Re-run with --apply to commit.)")


if __name__ == "__main__":
    main()
