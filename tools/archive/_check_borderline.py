import json, sys
sys.path.insert(0, '.')
from forcastl.core.csv_evidence import build_csv_index, resolve_csv, read_csv_events

borderline = [
    ("ID4698-4699-Fast created & deleted task by ATexec (susp. arg.).evtx",
     "cmd.exe /C whoami > %windir%\\Temp\\bouWFQYO.tmp 2>&1"),
    ("ID4688-Task Manager access indicator for potential LSASS dump.evtx",
     "Taskmgr.exe /4"),
    ("ID5145-remote shell execution via SMB admin share.evtx",
     "psexec.exe \\\\target -accepteula -s powershell.exe"),
    ("ID4688,4697,5140-5145 PSexec remote execution + admin share.evtx",
     "cmd.exe -u demo\\admmig -p Admin1235 -accepteula"),
]
m = json.load(open("metadata.json", encoding="utf-8"))
csv_index = build_csv_index()
for fname, claim in borderline:
    full = m["files"].get(fname, {}).get("full_path")
    csv_path = resolve_csv(full or fname, csv_index)
    if not csv_path:
        print(f"{fname}: CSV not found")
        continue
    try:
        events = read_csv_events(csv_path)
    except Exception as e:
        print(f"{fname}: parse error {e}")
        continue
    cl = " ".join(claim.split()).lower()
    found = False

    def walk(o):
        global found
        if isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
        elif isinstance(o, str) and o:
            if cl in " ".join(o.split()).lower():
                found = True

    for ev in events:
        found = False
        walk(ev.get("Event") or {})
        if found:
            break
    tag = "IN events" if found else "NOT in events"
    print(f"{fname}: {tag}: {claim[:80]!r}")
