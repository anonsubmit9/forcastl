"""Hand-verify the residual drift hits from audit_gt_residual_drift.py.

For 10 of the flagged claims, dump the actual relevant fields from the
source events so I can categorize each as:

  REAL_DRIFT       — claim asserts something the events don't contain
  ATTRIBUTION      — claim is tool DSL / inferential; narrative should
                     have labeled it as such (real defect, but milder)
  FALSE_POSITIVE   — audit script over-matched (formatting / quoting /
                     trailing-component issues); claim is actually
                     in the events

Output is a manual-review aid, not a verdict.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from forcastl.core.csv_evidence import build_csv_index, read_csv_events, resolve_csv  # noqa: E402

# 10 representative hits from the audit, picked across categories.
HITS = [
    ("ID4656-4663-4658 Mimikatz sekurlsa password dump.evtx", "sekurlsa::logonpasswords"),
    ("ID4724-5145-password reset with setNTLM (Mimikatz).evtx", "lsadump::setntlm"),
    ("ID4662-Sensitve DPAPI attributes accessed.evtx", "dpapi::masterkey /backupkey"),
    ("ID4688-Diskshadow abuse.evtx", "diskshadow.exe /s shadow.txt"),
    ("ID4688-Delete VSS backup (WMI).evtx", "wmic shadowcopy delete /nointeractive"),
    ("ID4688-Clear event log attempt (wmi).evtx", "wmic nteventlog where filename=\"security\" cl"),
    ("ID7045-4697-SMBexec service registration.evtx", "%COMSPEC% /Q /c echo cd ^> \\\\127.0.0.1\\C$\\__output 2^>^&1"),
    ("ID4688-List all Service Principal Names (SPN).evtx", "setspn -T offsec -Q */*"),
    ("ID4688,4697,5140-5145 PSexec remote execution + admin share.evtx", "cmd.exe -u demo\\admmig -p Admin1235 -accepteula"),
    ("ID4688-Stickey command reg update + execution.evtx", "REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe /t REG_SZ /v Debugger /d C:\\windows\\system32\\cmd.exe /f"),
]


def collect_strings(events):
    """Yield every string value from every event."""
    out = []
    def walk(o):
        if isinstance(o, dict):
            for v in o.values(): walk(v)
        elif isinstance(o, list):
            for v in o: walk(v)
        elif isinstance(o, str):
            out.append(o)
    for ev in events:
        walk(ev.get("Event") or {})
    return out


def main():
    csv_index = build_csv_index()

    for fname, claim in HITS:
        csv_path = resolve_csv(fname, csv_index)
        if not csv_path:
            print(f"\n## {fname}\n  CLAIM: {claim!r}\n  [skip: no CSV for this entry]")
            continue
        try:
            events = read_csv_events(csv_path)
        except Exception as e:
            print(f"\n## {fname}\n  CLAIM: {claim!r}\n  [parse error: {e!r}]")
            continue

        strings = collect_strings(events)
        cl_low = claim.lower()
        # Exact substring
        exact_hits = [s for s in strings if cl_low in s.lower()]
        # Token-overlap heuristic — for command-line claims, see if a
        # significant chunk (≥40 chars) of the claim is in any string.
        partial_hits = []
        if not exact_hits and len(claim) > 40:
            cleaned = " ".join(claim.split()).lower()
            for window in range(min(80, len(cleaned)), 30, -10):
                for start in range(0, len(cleaned) - window, 10):
                    chunk = cleaned[start:start+window]
                    for s in strings:
                        if chunk in " ".join(s.split()).lower():
                            partial_hits.append((chunk, s[:200]))
                            break
                    if partial_hits:
                        break
                if partial_hits:
                    break

        print(f"\n## {fname}")
        print(f"  CLAIM: {claim!r}")
        if exact_hits:
            print("  ==> EXACT MATCH found in events. (audit false positive)")
            print(f"     example: {exact_hits[0][:200]!r}")
        elif partial_hits:
            print(f"  ==> PARTIAL MATCH: chunk {partial_hits[0][0]!r}")
            print(f"     in event field: {partial_hits[0][1]!r}")
        else:
            print("  ==> NO MATCH in any event field.")
            # Sample 3 most-relevant strings to show what events DO contain
            relevant = [s for s in strings if any(
                tok in s.lower() for tok in claim.lower().split()[:3] if len(tok) > 3
            )][:3]
            for r in relevant:
                print(f"     events do contain: {r[:200]!r}")


if __name__ == "__main__":
    main()
