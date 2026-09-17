"""Generate additional benign CSV samples + their GT/metadata entries.

The current benign corpus (3 samples) is too small to drive a meaningful
FP-rate metric — even one misclassification = 33% FP rate. This script adds
samples covering routine admin operations the model should never flag:

  - GPO refresh (gpupdate /force)
  - WSUS update scan (wuauclt)
  - Defender scheduled quick scan
  - MSI install via msiexec
  - AD replication health check

Each sample is a synthetic but schema-faithful CSV in the same format as
the existing _benign/ files. After generation the script prints next-steps:
add the GT entries, add the metadata entries, and the corpus is usable.
"""
import csv
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


CSV_HEADER = [
    "RecordNumber", "EventRecordId", "TimeCreated", "EventId", "Level",
    "Provider", "Channel", "ProcessId", "ThreadId", "Computer", "ChunkNumber",
    "UserId", "MapDescription", "UserName", "RemoteHost",
    "PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4",
    "PayloadData5", "PayloadData6", "ExecutableInfo", "HiddenRecord",
    "SourceFile", "Keywords", "ExtraDataOffset", "Payload",
]


def _row(record_number, time_created, event_id, level, provider, channel,
         user_id, computer, payload_data):
    """Build one CSV row matching the BENIGN-* file format."""
    return {
        "RecordNumber": str(record_number),
        "EventRecordId": str(record_number),
        "TimeCreated": time_created,
        "EventId": str(event_id),
        "Level": str(level),
        "Provider": provider,
        "Channel": channel,
        "ProcessId": "",
        "ThreadId": "",
        "Computer": computer,
        "ChunkNumber": "",
        "UserId": user_id,
        "MapDescription": "",
        "UserName": "",
        "RemoteHost": "",
        "PayloadData1": "", "PayloadData2": "", "PayloadData3": "",
        "PayloadData4": "", "PayloadData5": "", "PayloadData6": "",
        "ExecutableInfo": "", "HiddenRecord": "", "SourceFile": "",
        "Keywords": "", "ExtraDataOffset": "",
        "Payload": json.dumps({"EventData": {"Data": payload_data}}),
    }


def _kv_data(pairs):
    """Convert [(name, text), ...] into the {Data: [{@Name, #text}, ...]} shape."""
    return [{"@Name": k, "#text": v} for k, v in pairs]


def _write_csv(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    # Match the BOM the existing benign files have so the CSV reader
    # behaves identically.
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADER)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)


# ── Sample 1: GPO refresh ────────────────────────────────────────────────────
def gen_gpo_refresh():
    base = datetime(2025, 9, 20, 8, 30, 0, 0)
    rows = []
    # Sysmon Event 1 — gpupdate.exe spawn by SYSTEM
    rows.append(_row(
        record_number=920001, time_created=str(base),
        event_id=1, level=4,
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        user_id="S-1-5-18", computer="win10-admin.offsec.lan",
        payload_data=_kv_data([
            ("RuleName", "-"),
            ("UtcTime", str(base)),
            ("ProcessGuid", "{1234aabb-100b-100c-aabb-100000000001}"),
            ("ProcessId", "5240"),
            ("Image", "C:\\Windows\\System32\\gpupdate.exe"),
            ("FileVersion", "10.0.19041.5072"),
            ("Description", "Microsoft Group Policy Update Utility"),
            ("Product", "Microsoft Windows Operating System"),
            ("Company", "Microsoft Corporation"),
            ("OriginalFileName", "GPUPDATE.EXE"),
            ("CommandLine", "gpupdate /force"),
            ("CurrentDirectory", "C:\\Windows\\system32\\"),
            ("User", "NT AUTHORITY\\SYSTEM"),
            ("LogonGuid", "{1234aabb-0000-0000-0000-000000000000}"),
            ("LogonId", "0x3e7"),
            ("TerminalSessionId", "0"),
            ("IntegrityLevel", "System"),
            ("ParentProcessId", "1024"),
            ("ParentImage", "C:\\Windows\\System32\\svchost.exe"),
            ("ParentCommandLine", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s gpsvc"),
            ("ParentUser", "NT AUTHORITY\\SYSTEM"),
        ]),
    ))
    # Group Policy log Event 1502 (Group Policy was applied)
    rows.append(_row(
        record_number=920002, time_created=str(base + timedelta(seconds=4)),
        event_id=1502, level=4,
        provider="Microsoft-Windows-GroupPolicy",
        channel="System",
        user_id="S-1-5-18", computer="win10-admin.offsec.lan",
        payload_data=_kv_data([
            ("SupportInfo1", "1"),
            ("SupportInfo2", "5921"),
            ("ProcessingMode", "0"),
            ("ProcessingTimeInMilliseconds", "3214"),
            ("DCName", "\\\\rootdc1.offsec.lan"),
            ("ErrorCode", "0"),
        ]),
    ))
    return rows, "BENIGN-ID1-GPO refresh by SYSTEM via gpupdate.evtx"


# ── Sample 2: Defender scheduled quick scan ────────────────────────────────
def gen_defender_quickscan():
    base = datetime(2025, 9, 20, 2, 0, 0, 0)
    rows = []
    rows.append(_row(
        record_number=920100, time_created=str(base),
        event_id=1000, level=4,
        provider="Microsoft-Windows-Windows Defender",
        channel="Microsoft-Windows-Windows Defender/Operational",
        user_id="S-1-5-18", computer="win10-admin.offsec.lan",
        payload_data=_kv_data([
            ("Product Name", "Microsoft Defender Antivirus"),
            ("Product Version", "4.18.24080.4"),
            ("Scan ID", "{aabbccdd-1234-5678-9012-aabbccddeeff}"),
            ("Scan Type", "Antimalware"),
            ("Scan Parameters", "Quick scan"),
            ("Scan Resources", ""),
            ("User", "NT AUTHORITY\\SYSTEM"),
            ("Domain", ""),
            ("SID", "S-1-5-18"),
        ]),
    ))
    rows.append(_row(
        record_number=920101, time_created=str(base + timedelta(minutes=4, seconds=12)),
        event_id=1001, level=4,
        provider="Microsoft-Windows-Windows Defender",
        channel="Microsoft-Windows-Windows Defender/Operational",
        user_id="S-1-5-18", computer="win10-admin.offsec.lan",
        payload_data=_kv_data([
            ("Product Name", "Microsoft Defender Antivirus"),
            ("Scan ID", "{aabbccdd-1234-5678-9012-aabbccddeeff}"),
            ("Scan Type", "Antimalware"),
            ("Scan Parameters", "Quick scan"),
            ("User", "NT AUTHORITY\\SYSTEM"),
            ("Result Code", "0x00000000"),
        ]),
    ))
    return rows, "BENIGN-ID1000-Defender scheduled quick scan.evtx"


# ── Sample 3: WSUS scan via wuauclt ──────────────────────────────────────────
def gen_wuauclt_scan():
    base = datetime(2025, 9, 20, 4, 15, 0, 0)
    rows = []
    rows.append(_row(
        record_number=920200, time_created=str(base),
        event_id=1, level=4,
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        user_id="S-1-5-18", computer="win10-admin.offsec.lan",
        payload_data=_kv_data([
            ("RuleName", "-"),
            ("UtcTime", str(base)),
            ("ProcessGuid", "{1234aabb-200b-200c-aabb-200000000001}"),
            ("ProcessId", "6420"),
            ("Image", "C:\\Windows\\System32\\wuauclt.exe"),
            ("FileVersion", "10.0.19041.5072"),
            ("Description", "Windows Update"),
            ("Product", "Microsoft Windows Operating System"),
            ("Company", "Microsoft Corporation"),
            ("OriginalFileName", "wuauclt.exe"),
            ("CommandLine", "wuauclt.exe /detectnow /updatenow"),
            ("CurrentDirectory", "C:\\Windows\\system32\\"),
            ("User", "NT AUTHORITY\\SYSTEM"),
            ("LogonGuid", "{1234aabb-0000-0000-0000-000000000000}"),
            ("LogonId", "0x3e7"),
            ("TerminalSessionId", "0"),
            ("IntegrityLevel", "System"),
            ("ParentProcessId", "1024"),
            ("ParentImage", "C:\\Windows\\System32\\svchost.exe"),
            ("ParentCommandLine", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s wuauserv"),
            ("ParentUser", "NT AUTHORITY\\SYSTEM"),
        ]),
    ))
    return rows, "BENIGN-ID1-WSUS update scan via wuauclt.evtx"


# ── Sample 4: Authorised MSI install ────────────────────────────────────────
def gen_msi_install():
    base = datetime(2025, 9, 20, 14, 22, 0, 0)
    rows = []
    rows.append(_row(
        record_number=920300, time_created=str(base),
        event_id=1, level=4,
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        user_id="S-1-5-21-4230534742-2542757381-3142984815-1112",
        computer="win10-admin.offsec.lan",
        payload_data=_kv_data([
            ("RuleName", "-"),
            ("UtcTime", str(base)),
            ("ProcessGuid", "{1234aabb-300b-300c-aabb-300000000001}"),
            ("ProcessId", "7800"),
            ("Image", "C:\\Windows\\System32\\msiexec.exe"),
            ("FileVersion", "5.0.19041.5072"),
            ("Description", "Windows Installer"),
            ("Product", "Windows Installer - Unicode"),
            ("Company", "Microsoft Corporation"),
            ("OriginalFileName", "msiexec.exe"),
            ("CommandLine", "msiexec.exe /i \"\\\\sccm01.offsec.lan\\Apps\\7zip\\7z2408-x64.msi\" /qn"),
            ("CurrentDirectory", "C:\\Windows\\system32\\"),
            ("User", "OFFSEC\\sccm-deploy"),
            ("LogonGuid", "{1234aabb-3000-3000-aabb-300000000000}"),
            ("LogonId", "0x84a23c"),
            ("TerminalSessionId", "0"),
            ("IntegrityLevel", "System"),
            ("ParentProcessId", "1024"),
            ("ParentImage", "C:\\Windows\\CCM\\CcmExec.exe"),
            ("ParentCommandLine", "\"C:\\Windows\\CCM\\CcmExec.exe\""),
            ("ParentUser", "NT AUTHORITY\\SYSTEM"),
        ]),
    ))
    rows.append(_row(
        record_number=920301, time_created=str(base + timedelta(seconds=18)),
        event_id=11707, level=4,
        provider="MsiInstaller",
        channel="Application",
        user_id="S-1-5-21-4230534742-2542757381-3142984815-1112",
        computer="win10-admin.offsec.lan",
        payload_data=_kv_data([
            ("Product", "7-Zip 24.08 (x64)"),
            ("Version", "24.08"),
            ("Manufacturer", "Igor Pavlov"),
            ("Status", "1707"),
            ("LanguageId", "1033"),
        ]),
    ))
    return rows, "BENIGN-ID1-Authorised MSI install via SCCM.evtx"


# ── Sample 5: AD replication health probe (DC machine account) ──────────────
def gen_ad_replication_probe():
    base = datetime(2025, 9, 20, 10, 0, 0, 0)
    rows = []
    # 4624 by ROOTDC2$ logging in to ROOTDC1 to query replication metadata —
    # routine inter-DC traffic that would look identical to a legitimate
    # admin running `repadmin /showrepl`.
    rows.append(_row(
        record_number=920400, time_created=str(base),
        event_id=4624, level=0,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        user_id="", computer="rootdc1.offsec.lan",
        payload_data=_kv_data([
            ("SubjectUserSid", "S-1-5-18"),
            ("SubjectUserName", "ROOTDC1$"),
            ("SubjectDomainName", "OFFSEC"),
            ("SubjectLogonId", "0x3e7"),
            ("TargetUserSid", "S-1-5-21-4230534742-2542757381-3142984815-1006"),
            ("TargetUserName", "ROOTDC2$"),
            ("TargetDomainName", "OFFSEC"),
            ("TargetLogonId", "0x9a4b21c"),
            ("LogonType", "3"),
            ("LogonProcessName", "Kerberos"),
            ("AuthenticationPackageName", "Kerberos"),
            ("WorkstationName", "-"),
            ("LogonGuid", "{aabb1234-0000-0000-0000-000000000001}"),
            ("ProcessId", "0x0"),
            ("ProcessName", "-"),
            ("IpAddress", "10.23.10.2"),
            ("IpPort", "59431"),
            ("ImpersonationLevel", "%%1833"),
        ]),
    ))
    return rows, "BENIGN-ID4624-AD replication health probe by DC.evtx"


GENERATORS = [
    gen_gpo_refresh,
    gen_defender_quickscan,
    gen_wuauclt_scan,
    gen_msi_install,
    gen_ad_replication_probe,
]


def main():
    csv_dir = PROJECT_ROOT / "test_data" / "csv" / "_benign"
    gt_path = PROJECT_ROOT / "ground_truth_evidence.json"
    meta_path = PROJECT_ROOT / "metadata.json"

    gt = json.loads(gt_path.read_text(encoding="utf-8"))
    meta = json.loads(meta_path.read_text(encoding="utf-8"))

    added = 0
    for gen in GENERATORS:
        rows, fname = gen()
        # Stem is the .evtx filename minus the .evtx; CSV uses the same
        # stem so the FileSelector's csv-lookup-by-stem path works.
        stem = fname[:-5]  # strip .evtx
        csv_path = csv_dir / f"{stem}.csv"
        if csv_path.exists():
            print(f"  skip (exists): {csv_path.name}")
            continue
        _write_csv(csv_path, rows)

        # GT entry
        event_ids = sorted({r["EventId"] for r in rows})
        gt["files"][fname] = {
            "malicious": "NO",
            "evidence": {
                "event_ids": event_ids,
                "processes": [],
                "accounts": [],
                "commands": [],
                "network": [],
                "registry": [],
                "attack_processes": [],
                "attack_accounts": [],
                "attack_commands": [],
            },
            "malicious_events": [],
            "explanation_keywords": ["legitimate", "routine", "benign"],
            "difficulty": "easy",
            "test_set": "D",
            "total_events": len(rows),
            "signal_events": 0,
            "signal_ratio": 0.0,
        }

        # Metadata entry
        rel = f"_benign/{fname}"
        meta["files"][fname] = {
            "file_name": fname,
            "tactic_id": "BENIGN",
            "tactic_name": "Benign",
            "technique_id": "",
            "technique_name": "",
            "description": "Benign test artefact (no attack present).",
            "event_ids": event_ids,
            "is_apt_attack": False,
            "is_antivirus": False,
            "relative_path": rel,
            "full_path": f"test_data/evtx/{rel}",
            "source": "synthetic",
            "confidence": "high",
            "difficulty": "easy",
            "test_set": "D",
            "total_events": len(rows),
            "signal_events": 0,
            "signal_ratio": 0.0,
            "excluded": False,
            "exclusion_reason": "",
            "excluded_at": "",
            "csv_only": True,
        }

        added += 1
        print(f"  + {csv_path.name}  ({len(rows)} events)")

    if added:
        gt_path.write_text(json.dumps(gt, indent=2, ensure_ascii=False), encoding="utf-8")
        meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nWrote {added} new benign samples + GT/metadata entries.")
    else:
        print("\nNothing to do.")


if __name__ == "__main__":
    main()
