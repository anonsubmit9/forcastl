"""Read-only helper: dump structured fields from the CSV corpus (the source of
truth for ground truth) so the AI reviewer can compare against ground truth
without re-typing parser logic each time.

Usage: python scripts/_inspect_evtx.py <path-or-name>

The argument may be a full path (e.g. test_data/evtx/...) or a GT/metadata key
like 'ID33205-….evtx'; it is resolved to the matching CSV by lowercased stem.

Prints a compact summary:
  - EventID counts
  - Per-event: ID, key EventData fields (CommandLine, NewProcessName, ImagePath,
    SubjectUserName, TargetUserName, IpAddress, ObjectName, ObjectDN, etc.)
"""
import json
import sys
from collections import Counter, OrderedDict
from pathlib import Path

# Windows console: force utf-8 so AD/Kerberos data with extended chars doesn't crash.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from forcastl.core.csv_evidence import read_csv_events, resolve_csv


# Fields most relevant for evidence extraction. We always print these when present.
INTERESTING = [
    # Process / command
    "NewProcessName", "ParentProcessName", "Image", "ImagePath", "CommandLine",
    "ProcessName", "ScriptBlockText", "Application",
    # Service install/start (Tchopper-style covert channels too)
    "ServiceName", "ServiceFileName", "ServiceType", "StartType",
    # Identity
    "SubjectUserName", "SubjectDomainName", "SubjectUserSid",
    "TargetUserName", "TargetDomainName", "TargetSid",
    "SamAccountName", "AccountName",
    # Network
    "IpAddress", "SourceAddress", "DestAddress", "Workstation",
    "SourceNetworkAddress", "RemoteAddr",
    # File / share
    "ShareName", "ShareLocalPath", "ObjectName", "FileName", "TargetFilename",
    # Registry
    "ObjectType", "ObjectClass", "RegistryKey", "TargetObject",
    # AD-specific
    "ObjectDN", "AttributeLDAPDisplayName", "AttributeValue", "AttributeSyntaxOID",
    "OperationType", "DSName", "DSType", "OpCorrelationID",
    # Generic
    "Properties", "AccessList", "AccessMask", "PrivilegeList",
    "LogonType", "AuthenticationPackageName", "PackageName",
    "Status", "FailureReason", "TicketEncryptionType", "TicketOptions",
]


def _flatten_data(ed):
    out = OrderedDict()
    if not isinstance(ed, dict):
        return out
    data = ed.get("Data") or []
    if isinstance(data, dict):
        data = [data]
    for d in data:
        if not isinstance(d, dict):
            continue
        name = d.get("@Name") or "(unnamed)"
        text = d.get("#text", "")
        out[name] = text
    return out


def main():
    if len(sys.argv) != 2:
        print("usage: _inspect_evtx.py <path-or-name>")
        sys.exit(2)
    name = sys.argv[1]
    csv_path = resolve_csv(name)
    if csv_path is None:
        print(f"# no CSV found for: {name}")
        sys.exit(1)
    events = read_csv_events(csv_path)
    print(f"# csv: {csv_path}")
    print(f"# events: {len(events)}")

    id_counts = Counter()
    raw_per_id = {}
    for ev in events:
        sys_block = ev.get("Event", {}).get("System", {}) or {}
        eid_obj = sys_block.get("EventID")
        eid = eid_obj.get("#text") if isinstance(eid_obj, dict) else eid_obj
        id_counts[str(eid)] += 1
        ed = _flatten_data(ev.get("Event", {}).get("EventData", {}))
        # provider + computer + (first instance) record raw fields per ID
        raw_per_id.setdefault(str(eid), []).append({
            "provider": (sys_block.get("Provider") or {}).get("@Name") if isinstance(sys_block.get("Provider"), dict) else "",
            "computer": sys_block.get("Computer", ""),
            "data": ed,
        })

    print("# EventID counts:")
    for eid, n in sorted(id_counts.items(), key=lambda kv: kv[0]):
        print(f"  {eid}: {n}")

    print()
    print("# First event per EventID (filtered to interesting fields):")
    for eid in sorted(raw_per_id.keys()):
        instances = raw_per_id[eid]
        first = instances[0]
        print(f"\n--- EID {eid}  ({len(instances)} instances)  provider={first['provider']}  computer={first['computer']}")
        for k in INTERESTING:
            if k in first["data"]:
                v = str(first["data"][k])
                if len(v) > 240:
                    v = v[:240] + "..."
                print(f"  {k}: {v}")
        # Show any non-empty fields not in INTERESTING (so we don't miss anything)
        leftover = {k: v for k, v in first["data"].items()
                    if k not in INTERESTING and v not in (None, "", "-", "0x0", "0x00000000", "0x0000000000000000")}
        if leftover:
            print(f"  -- other non-empty fields:")
            for k, v in leftover.items():
                v = str(v)
                if len(v) > 240:
                    v = v[:240] + "..."
                print(f"    {k}: {v}")

    # Aggregate distinct values across all events for the most evidence-relevant fields
    agg_keys = ["NewProcessName", "ParentProcessName", "Image", "ImagePath", "CommandLine",
                "ServiceName", "SubjectUserName", "TargetUserName", "SamAccountName",
                "IpAddress", "SourceAddress", "Workstation", "ShareName",
                "ObjectName", "ObjectDN", "AttributeLDAPDisplayName", "ObjectClass",
                "TargetObject"]
    agg = {k: Counter() for k in agg_keys}
    for ev in events:
        ed = _flatten_data(ev.get("Event", {}).get("EventData", {}))
        for k in agg_keys:
            v = ed.get(k)
            if v not in (None, "", "-"):
                agg[k][str(v)] += 1
    print()
    print("# Distinct values per evidence-relevant field (aggregated across all events):")
    for k in agg_keys:
        c = agg[k]
        if not c:
            continue
        print(f"  {k}:")
        for v, n in c.most_common(20):
            sv = v if len(v) <= 200 else v[:200] + "..."
            print(f"    ({n}x) {sv}")


if __name__ == "__main__":
    main()
