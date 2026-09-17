"""One-off audit: scan ground_truth_evidence.json for category mismatches.

Flags evidence values that look like they're in the wrong field — e.g. error
descriptions in the `accounts` list, multi-sentence text in `processes`, etc.
Run with: `python scripts/audit_ground_truth.py`
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
gt_path = PROJECT_ROOT / "ground_truth_evidence.json"
gt = json.loads(gt_path.read_text(encoding="utf-8"))
files = gt.get("files", {})

ip_re = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$|^[0-9a-fA-F:]+$|^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")
hostname_re = re.compile(r"^[A-Za-z0-9._-]+$")
event_id_re = re.compile(r"^\d{1,5}$")

issues = []
for fname, entry in files.items():
    ev = entry.get("evidence") or {}
    eids = ev.get("event_ids") or []
    accts = ev.get("accounts") or []
    procs = ev.get("processes") or []
    nets = ev.get("network") or []
    regs = ev.get("registry") or []

    # 1. Event IDs must be numeric
    for x in eids:
        if not event_id_re.match(str(x).strip()):
            issues.append(("event_id_not_numeric", fname, repr(x)))

    # 2. Accounts that look like sentences / error messages / IPs
    for x in accts:
        s = str(x).strip()
        if len(s) > 80:
            issues.append(("account_too_long", fname, s[:60] + "..."))
        elif re.search(
            r"\bfailed\b|\berror\b|\breason\b|password|attempt|client",
            s,
            re.IGNORECASE,
        ):
            issues.append(("account_contains_error_words", fname, s[:80]))
        elif s.count(" ") > 3:
            issues.append(("account_too_many_spaces", fname, s[:80]))
        elif ip_re.match(s):
            issues.append(("account_looks_like_ip", fname, s))

    # 3. Network entries that don't look like IP/host
    for x in nets:
        s = str(x).strip()
        if not s:
            continue
        if not (ip_re.match(s) or hostname_re.match(s)):
            issues.append(("network_not_ip_or_host", fname, s[:80]))

    # 4. Processes — should be executables/names. Flag long sentences.
    for x in procs:
        s = str(x).strip()
        if len(s) > 100:
            issues.append(("process_too_long", fname, s[:60] + "..."))
        elif s.count(" ") > 4 and not s.lower().endswith(
            (".exe", ".dll", ".ps1", ".bat", ".cmd")
        ):
            issues.append(("process_looks_like_sentence", fname, s[:80]))

    # 5. Registry — should start with HK or contain backslash
    for x in regs:
        s = str(x).strip()
        if s and not (s.upper().startswith("HK") or "\\" in s):
            issues.append(("registry_doesnt_look_like_path", fname, s[:80]))


by_cat = Counter(c for c, _, _ in issues)
print(f"Total flagged items: {len(issues)} across "
      f"{len({f for _, f, _ in issues})} files\n")
print("By category:")
for cat, n in by_cat.most_common():
    print(f"  {n:3d}  {cat}")

# Print all flags grouped by category so the user can do a manual pass.
print("\n" + "=" * 78)
for cat, _ in by_cat.most_common():
    print(f"\n## {cat}")
    for c, fname, val in issues:
        if c == cat:
            print(f"  - {fname}")
            print(f"      {val}")
