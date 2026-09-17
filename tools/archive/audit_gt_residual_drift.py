"""Round-2 ground-truth audit: stratified residual-drift estimate.

For each sampled malicious entry:
  1. Read the source CSV (the source of truth for ground truth) and build a
     single lowercase corpus of every string in every event field (mirrors
     `_build_cross_field_corpus`).
  2. Extract NAMED ENTITIES from the GT entry's `malicious_events` narrative
     and `attack_processes / attack_accounts / attack_commands` sidecars:
       - Backticked strings (`literal claim`) — these are the highest-risk
         "I copied this from the events" assertions.
       - Tool/binary names: anything ending in .exe, .dll, .sys.
       - IP addresses (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}).
       - Account-style tokens: <domain>\\<user>, *$ machine accounts.
       - MITRE sub-technique IDs: T\\d{4}(\\.\\d{3})?
  3. Flag any extracted entity that isn't a substring of the corpus.

The MITRE technique IDs are reported separately — they're attribution rather
than literal evidence, so they're expected to NOT be in events. Tool names
and command/IP/account claims that aren't in events ARE the drift.

Output: a markdown table of per-file findings + an aggregate drift rate.
Stratified sampling targets the high-risk attribution clusters Codex
identified: credential access, DCSync/DCShadow, lateral movement, registry
persistence, WMI.
"""
from __future__ import annotations

import json
import random
import re
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from forcastl.core.csv_evidence import build_csv_index, read_csv_events, resolve_csv  # noqa: E402

random.seed(20260506)


# ── Stratification: pick high-risk-tactic file groups ────────────────────────
STRATA = {
    "credential_access": [
        re.compile(r"(?i)mimikatz", re.I),
        re.compile(r"(?i)lsass", re.I),
        re.compile(r"(?i)dcsync|dcshadow", re.I),
        re.compile(r"(?i)secret(s)?dump|impacket", re.I),
        re.compile(r"(?i)kerberoast", re.I),
        re.compile(r"(?i)dpapi|dump", re.I),
        re.compile(r"(?i)credential", re.I),
        re.compile(r"(?i)ntds|ifm|ntdsutil|diskshadow|vssadmin", re.I),
    ],
    "lateral_movement": [
        re.compile(r"(?i)psexec|smbexec|wmiexec|atexec|dcomexec", re.I),
        re.compile(r"(?i)rdp|tscon", re.I),
        re.compile(r"(?i)admin\$|admin share|net use|network share", re.I),
    ],
    "registry_persistence": [
        re.compile(r"(?i)stickey|sticky|sethc|ifeo|debugger", re.I),
        re.compile(r"(?i)admin.*sd.*holder|adminsd", re.I),
        re.compile(r"(?i)service.*reg|reg.*permission|damp", re.I),
    ],
    "wmi": [
        re.compile(r"(?i)wmi(?!_)|wmic|wbem", re.I),
        re.compile(r"(?i)wmimplant|powerlurk", re.I),
    ],
    "spn_kerberos": [
        re.compile(r"(?i)spn", re.I),
        re.compile(r"(?i)kerberos|tgt|tgs|kerbrute|kerberoast", re.I),
    ],
}


# ── Entity extraction patterns ───────────────────────────────────────────────
RE_BACKTICK = re.compile(r"`([^`]{3,})`")
RE_BINARY = re.compile(r"\b([A-Za-z0-9_\-./\\]+\.(?:exe|dll|sys|bat|cmd|ps1|vbs|msi))\b", re.I)
RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_DOMAIN_USER = re.compile(r"\b([A-Za-z][A-Za-z0-9_-]+)\\\\([A-Za-z][A-Za-z0-9._-]*\$?)\b")
RE_MACHINE_ACCT = re.compile(r"\b([A-Z][A-Z0-9_-]{2,})\$\b")
RE_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

BINARY_ALLOWLIST = {"windows.exe", "system32.exe", "system.exe"}

# Filters for the backticked-claim list — false-positive categories that
# don't represent residual drift and shouldn't be reported as such:
#   - Cross-references to OTHER GT files (`.evtx` substring)
#   - Microsoft API / COM / cmdlet names (these describe technique
#     semantics; Windows logs the EFFECT, never the literal API call)
#   - Generic template strings with placeholders (`<...>`, `__<...>__`)
#   - Long narrative fragments that happen to fall between backticks
#     because of CommandLine quoting (>120 chars is almost certainly a
#     full command-line citation, not a single claim — those are scored
#     by the in_corpus check directly, not flagged as "drift" until the
#     check actually fails)

RE_API_NAMESHAPE = re.compile(r"^[A-Z][A-Za-z0-9]+(?:::[A-Za-z0-9]+)*$")
RE_DOTTED_API = re.compile(r"^[A-Za-z][A-Za-z0-9]+(?:\.[A-Za-z][A-Za-z0-9]+){1,4}$")
RE_HAS_PLACEHOLDER = re.compile(r"<[^>]+>|\.{3}|__[^_]+__")
RE_KERBEROS_STATUS = re.compile(r"^0x[0-9a-fA-F]{1,4}$")  # like 0x18, 0x19


def is_attribution_claim(claim: str) -> bool:
    """True when the backticked text is tool/api attribution rather than
    a literal-evidence assertion. These belong in the narrative as labeled
    inferential statements, not as event-derived claims."""
    cl = claim.strip()
    if cl.endswith(".evtx"):           # companion file reference
        return True
    if RE_HAS_PLACEHOLDER.search(cl):  # `<session-id>`, `__<unix-timestamp>__`
        return True
    if RE_KERBEROS_STATUS.match(cl):   # status codes referenced as semantic labels
        return True
    if cl.startswith("Get-") or cl.startswith("Set-") or cl.startswith("New-") \
       or cl.startswith("Add-") or cl.startswith("Register-") or cl.startswith("Invoke-"):
        return True  # PowerShell cmdlet name (technique label, not a claim)
    # Mimikatz/Rubeus/Kerbrute DSL — `module::command` shape. Always
    # attribution; Windows doesn't log this syntax, attackers run it
    # locally and only the EFFECT shows up in events.
    if "::" in cl and len(cl.split()) <= 2:
        return True
    if RE_API_NAMESHAPE.match(cl):     # CamelCase API method
        return True
    if RE_DOTTED_API.match(cl):        # `Document.ActiveView.ExecuteShellCommand`
        return True
    # Tool family/mode names — backticked tool-name + verb shape used
    # for attribution: `Kerbrute brute`, `Kerbrute userenum`, `Rubeus brute`, etc.
    if re.match(r"^(Kerbrute|Rubeus|Mimikatz|Impacket|CrackMap|cme|Hydra)\s+\w+", cl, re.I):
        return True
    # Long narrative fragments slipped between backticks — almost certainly
    # not a single literal claim. Fall through to corpus check; if it's
    # >180 chars and contains common prose connectors, treat as narrative.
    if len(cl) > 180 and any(w in cl for w in (" the ", " is ", " that ", " which ")):
        return True
    return False


def is_likely_attribution_binary(claim: str) -> bool:
    """Some `*.exe` extractions in the narrative are tool-family naming
    rather than claimed event content (e.g., `setspn.exe` mentioned as the
    LOLBin name, not as a literal event field). If the binary base-name is
    a Microsoft signed CLI, we don't flag it as drift; a real "fabricated
    binary" claim looks like a random `xyz.dll` or `attacker_tool.exe`."""
    base = claim.lower().rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    return False  # leave to corpus check — no allowlist; we want signal here


def build_event_corpus(events: list) -> Set[str]:
    """Flatten every string value from every event into one lowercase,
    whitespace-normalized set. Whitespace-normalization is critical:
    Windows logs `CommandLine` fields with double spaces between verb and
    args (`wmic  shadowcopy`, `REG  ADD`, `setspn  -T`) so single-space
    narrative quotes were failing exact-substring against double-space
    event content."""
    corpus: Set[str] = set()
    for ev in events:
        evdata = (ev.get("Event") or {}).get("EventData") or {}
        sysdata = (ev.get("Event") or {}).get("System") or {}
        for block in (evdata, sysdata):
            _walk(block, corpus)
        raw = ev.get("_raw_xml")
        if isinstance(raw, str):
            corpus.add(" ".join(raw.split()).lower())
    return corpus


def _walk(obj, out: Set[str]) -> None:
    if isinstance(obj, dict):
        for v in obj.values():
            _walk(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _walk(v, out)
    elif isinstance(obj, str) and obj:
        out.add(" ".join(obj.split()).lower())


def in_corpus(claim: str, corpus: Set[str]) -> bool:
    """Substring match (case-insensitive, whitespace-normalized both sides)."""
    cl = " ".join(claim.split()).lower()
    if not cl or len(cl) < 4:
        return True
    return any(cl in s for s in corpus)


RE_NARRATIVE_HEDGE = re.compile(
    r"(?i)inferential|illustrative|analyst[\s-]?shorthand|attribution|"
    r"\bnot in (the )?events?\b|\bnot literally\b|\bnot logged\b|"
    r"\bcompatible with\b|\bcharacteristic of\b|"
    r"\bany DRSUAPI client\b|"
    r"Mimikatz subcommand syntax|tool-family attribution|"
    r"\bcmdlet attribution\b|\billustrative invocation\b"
)


def collect_claims(entry: Dict) -> Dict[str, List[str]]:
    """Pull entity-style claims out of `malicious_events` + `attack_*` sidecars.

    Bullets that contain narrative hedging language anywhere in them have
    their backticked claims excluded — the editorial pass appended explicit
    inferential labels to such bullets, and re-flagging them would defeat
    the purpose of the labeling discipline.
    """
    bullets = entry.get("malicious_events") or []
    backticked: List[str] = []
    for b in bullets:
        if RE_NARRATIVE_HEDGE.search(b):
            continue  # bullet is hedged; attribution claims here are labeled
        for m in RE_BACKTICK.finditer(b):
            backticked.append(m.group(1))

    text_blob = " ".join(bullets)
    ev = entry.get("evidence") or {}
    sidecar_blob = " ".join([
        " ".join(ev.get("attack_processes") or []),
        " ".join(ev.get("attack_accounts") or []),
        " ".join(ev.get("attack_commands") or []),
    ])
    full = text_blob + " " + sidecar_blob

    claims = {
        "backticked": backticked,
        "binaries":   [m.group(1) for m in RE_BINARY.finditer(full)
                       if m.group(1).lower() not in BINARY_ALLOWLIST],
        "ips":        list(RE_IP.findall(full)),
        "domain_users": [f"{m.group(1)}\\{m.group(2)}" for m in RE_DOMAIN_USER.finditer(full)],
        "machine_accts": list(RE_MACHINE_ACCT.findall(full)),
        "techniques": list(RE_TECHNIQUE.findall(full)),
    }
    return {k: sorted(set(v)) for k, v in claims.items()}


def evaluate_entry(filename: str, entry: Dict, csv_index: Dict[str, str],
                   meta: Dict) -> Dict:
    """Produce a per-file finding record.

    The CSV corpus is the source of truth for ground truth — resolve the
    metadata artefact to its CSV (by lowercased stem) and read its events
    directly; the binary EVTX is never parsed here.
    """
    meta_entry = meta["files"].get(filename, {})
    full_path_rel = meta_entry.get("full_path")
    if not full_path_rel:
        return {"filename": filename, "status": "skipped:no-path"}

    # `full_path` points at test_data/evtx/... for attack files; resolve_csv
    # matches by lowercased stem, so this yields the corresponding CSV.
    csv_path = resolve_csv(full_path_rel, index=csv_index) \
        or resolve_csv(filename, index=csv_index)
    if not csv_path:
        return {"filename": filename, "status": "skipped:missing-csv"}

    try:
        events = read_csv_events(csv_path)
    except Exception as exc:
        return {"filename": filename, "status": f"skipped:parse-error:{exc!r}"}

    if not events:
        return {"filename": filename, "status": "skipped:no-events"}

    corpus = build_event_corpus(events)
    claims = collect_claims(entry)

    unsupported: Dict[str, List[str]] = {}
    attribution_only: Dict[str, List[str]] = {}
    for kind, items in claims.items():
        if kind == "techniques":
            continue
        bad: List[str] = []
        attribution: List[str] = []
        for c in items:
            if in_corpus(c, corpus):
                continue
            if kind == "backticked" and is_attribution_claim(c):
                attribution.append(c)
                continue
            bad.append(c)
        if bad:
            unsupported[kind] = bad
        if attribution:
            attribution_only[kind] = attribution

    return {
        "filename": filename,
        "status": "checked",
        "techniques_referenced": claims["techniques"],
        "unsupported_claims": unsupported,
        "attribution_only": attribution_only,
        "total_unsupported": sum(len(v) for v in unsupported.values()),
    }


def stratify(gt_files: Dict, meta_files: Dict, n_per_stratum: int = 8) -> List[str]:
    """Pick `n_per_stratum` filenames from each stratum (no overlap)."""
    chosen: List[str] = []
    seen: Set[str] = set()
    candidates_by_stratum: Dict[str, List[str]] = {}

    malicious = [
        f for f, e in gt_files.items()
        if e.get("malicious") == "YES" and f in meta_files
    ]

    for stratum, patterns in STRATA.items():
        candidates = [
            f for f in malicious
            if any(p.search(f) for p in patterns) and f not in seen
        ]
        random.shuffle(candidates)
        pick = candidates[:n_per_stratum]
        candidates_by_stratum[stratum] = pick
        for f in pick:
            seen.add(f)
        chosen.extend(pick)

    return chosen, candidates_by_stratum


def main():
    gt_path = PROJECT_ROOT / "ground_truth_evidence.json"
    meta_path = PROJECT_ROOT / "metadata.json"
    gt = json.loads(gt_path.read_text(encoding="utf-8"))
    meta = json.loads(meta_path.read_text(encoding="utf-8"))

    sample, by_stratum = stratify(gt["files"], meta["files"], n_per_stratum=8)
    print(f"# Stratified sample: {len(sample)} files\n")
    for stratum, files in by_stratum.items():
        print(f"## {stratum} ({len(files)})")
        for f in files:
            print(f"  - {f}")
        print()

    csv_index = build_csv_index()
    findings = []
    for fname in sample:
        result = evaluate_entry(fname, gt["files"][fname], csv_index, meta)
        findings.append(result)

    # Aggregate
    print("\n# Per-file findings\n")
    drift_count = 0
    skipped = 0
    for f in findings:
        if f["status"] != "checked":
            print(f"  [skip] {f['filename']}: {f['status']}")
            skipped += 1
            continue
        if f["total_unsupported"] == 0:
            print(f"  [CLEAN] {f['filename']}")
        else:
            drift_count += 1
            print(f"\n  [DRIFT] {f['filename']}")
            for kind, items in f["unsupported_claims"].items():
                print(f"    {kind}:")
                for it in items:
                    print(f"      - {it!r}")

    checked = len([f for f in findings if f["status"] == "checked"])
    print()
    print("# Summary")
    print(f"  Sampled: {len(sample)}")
    print(f"  Checked: {checked}")
    print(f"  Skipped: {skipped}")
    print(f"  Files with at least one unsupported claim: {drift_count}")
    if checked:
        print(f"  Drift rate (files with drift / files checked): "
              f"{100.0 * drift_count / checked:.1f}%")


if __name__ == "__main__":
    main()
