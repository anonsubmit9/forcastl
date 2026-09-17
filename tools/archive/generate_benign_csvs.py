"""Generate realistic benign-activity CSVs that shape-match EvtxECmd output.

These rows probe false-positive tendency on event IDs that are commonly
flagged malicious (SQL audit, PowerShell Sysmon 1, scheduled task 4698) but
that are mundane in the right context.

Each scenario produces one CSV with the exact 27-column EvtxECmd header. The
Payload column holds a JSON blob with an EventData.Data field shaped like the
corresponding real-world EVTX extract (list-of-dicts for classic Windows
events, single string blob for SQL Server audit).

Run from the repo root:
    python scripts/generate_benign_csvs.py
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterable

EVTXECMD_HEADER = [
    "RecordNumber", "EventRecordId", "TimeCreated", "EventId", "Level",
    "Provider", "Channel", "ProcessId", "ThreadId", "Computer", "ChunkNumber",
    "UserId", "MapDescription", "UserName", "RemoteHost", "PayloadData1",
    "PayloadData2", "PayloadData3", "PayloadData4", "PayloadData5",
    "PayloadData6", "ExecutableInfo", "HiddenRecord", "SourceFile",
    "Keywords", "ExtraDataOffset", "Payload",
]


def _blank_row() -> Dict[str, str]:
    return {col: "" for col in EVTXECMD_HEADER}


def sql_successful_admin_login() -> Iterable[Dict[str, str]]:
    """33205 (SQL Server audit) — LGIS success by expected application account.

    Mirrors the malicious "SQL failed login with disabled SA account" file:
    same EventID 33205, same Provider, same MSSQL01 host — but the action_id
    is LGIS (login success), the principal is a documented service account,
    and the source IP is inside the trusted /24 reserved for application
    tier. A model that flags any 33205 event as malicious will misclassify.
    """
    base_ts = "2025-09-18 14:12:05"
    for i, ts_suffix in enumerate([".1208712", ".8430114", "1.0442018"]):
        payload_string = (
            "audit_schema_version:1\n"
            f"event_time:{base_ts}{ts_suffix}\n"
            "sequence_number:1\n"
            "action_id:LGIS\n"
            "succeeded:true\n"
            "is_column_permission:false\n"
            "session_id:58\n"
            "server_principal_id:261\n"
            "database_principal_id:0\n"
            "target_server_principal_id:0\n"
            "target_database_principal_id:0\n"
            "object_id:0\n"
            "user_defined_event_id:0\n"
            "class_type:LX\n"
            "permission_bitmask:00000000000000000000000000000000\n"
            f"sequence_group_id:A1B2C3D4-E5F6-7890-1234-56789ABCDEF{i}\n"
            "session_server_principal_name:OFFSEC\\svc-sqlreport\n"
            "server_principal_name:OFFSEC\\svc-sqlreport\n"
            "server_principal_sid:01050000000000051500000056d628fc05668f976f2456bb09030000\n"
            "database_principal_name:dbo\n"
            "target_server_principal_name:\n"
            "target_server_principal_sid:\n"
            "target_database_principal_name:\n"
            "server_instance_name:MSSQL01\\RADAR\n"
            "database_name:master\n"
            "schema_name:\n"
            "object_name:\n"
            "statement:Login succeeded for user 'OFFSEC\\svc-sqlreport'. "
            "Connection made using Windows authentication. [CLIENT: 10.23.23.41]\n"
            "additional_information:\n"
            "user_defined_information:\n"
        )
        row = _blank_row()
        row.update({
            "RecordNumber": str(60001 + i),
            "EventRecordId": str(60001 + i),
            "TimeCreated": f"{base_ts}{ts_suffix}",
            "EventId": "33205",
            "Level": "0",
            "Provider": "MSSQL$RADAR",
            "Channel": "Application",
            "Computer": "mssql01.offsec.lan",
            "Payload": json.dumps({"EventData": {"Data": payload_string}}),
        })
        yield row


def admin_powershell_diagnostic() -> Iterable[Dict[str, str]]:
    """Sysmon EventID 1 — admin runs a short diagnostic PowerShell cmdlet.

    Shape-matches the malicious 'WMI spawning PowerShell' case but with:
      - ParentImage explorer.exe (not WmiPrvSE.exe)
      - Plain, readable command line (Get-Service)
      - Signed powershell.exe binary
      - Non-obfuscated arguments
    """
    cmds = [
        ("10360", "powershell.exe Get-Service -Name W32Time"),
        ("10361", "powershell.exe Get-EventLog -LogName System -Newest 10"),
    ]
    base_ts = "2025-09-18 09:04:12.355411"
    for i, (pid, cmdline) in enumerate(cmds):
        data = [
            {"@Name": "RuleName", "#text": "-"},
            {"@Name": "UtcTime", "#text": "2025-09-18 09:04:12.340"},
            {"@Name": "ProcessGuid", "#text": f"{{1234aabb-683b-608c-a30c-0000000{i:04d}}}"},
            {"@Name": "ProcessId", "#text": pid},
            {"@Name": "Image",
             "#text": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
            {"@Name": "FileVersion",
             "#text": "10.0.19041.5072 (WinBuild.160101.0800)"},
            {"@Name": "Description", "#text": "Windows PowerShell"},
            {"@Name": "Product", "#text": "Microsoft® Windows® Operating System"},
            {"@Name": "Company", "#text": "Microsoft Corporation"},
            {"@Name": "OriginalFileName", "#text": "PowerShell.EXE"},
            {"@Name": "CommandLine", "#text": cmdline},
            {"@Name": "CurrentDirectory", "#text": "C:\\Users\\admin\\Documents\\"},
            {"@Name": "User", "#text": "OFFSEC\\admin"},
            {"@Name": "LogonGuid", "#text": "{1234aabb-5501-608c-ad0c-000000000000}"},
            {"@Name": "LogonId", "#text": "0x3e7"},
            {"@Name": "TerminalSessionId", "#text": "1"},
            {"@Name": "IntegrityLevel", "#text": "High"},
            {"@Name": "Hashes",
             "#text": ("SHA1=04C5D2B482F759D8F1D3F1C29AE0E0E2E3E4E5E6,"
                       "MD5=B1E6B62D3A1111D5B08D9A8E3F1F1F1F,"
                       "SHA256=6A5C6D7E8F9A0B1C2D3E4F5061728394A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9D0")},
            {"@Name": "ParentProcessGuid", "#text": "{1234aabb-5a02-608c-a10c-000000000001}"},
            {"@Name": "ParentProcessId", "#text": "4280"},
            {"@Name": "ParentImage", "#text": "C:\\Windows\\explorer.exe"},
            {"@Name": "ParentCommandLine", "#text": "C:\\Windows\\Explorer.EXE"},
            {"@Name": "ParentUser", "#text": "OFFSEC\\admin"},
        ]
        row = _blank_row()
        row.update({
            "RecordNumber": str(8420 + i),
            "EventRecordId": str(8420 + i),
            "TimeCreated": base_ts,
            "EventId": "1",
            "Level": "4",
            "Provider": "Microsoft-Windows-Sysmon",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Computer": "win10-admin.offsec.lan",
            "UserId": "S-1-5-18",
            "Payload": json.dumps({"EventData": {"Data": data}}),
        })
        yield row


def windows_update_scheduled_task() -> Iterable[Dict[str, str]]:
    """EventID 4698 — Microsoft Update maintenance task created by SYSTEM.

    Commonly flagged as persistence. This row is the routine Update Orchestrator
    maintenance task that every Windows host has. Subject is NT AUTHORITY\\SYSTEM,
    task name is a Microsoft-signed path, and the Task Content XML invokes the
    WaaSMedic service (legitimate Windows Update component).
    """
    task_xml = (
        "&lt;?xml version=\"1.0\" encoding=\"UTF-16\"?&gt;"
        "&lt;Task version=\"1.4\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"&gt;"
        "&lt;RegistrationInfo&gt;"
        "&lt;Author&gt;Microsoft Corporation&lt;/Author&gt;"
        "&lt;Description&gt;Performs periodic Windows Update maintenance.&lt;/Description&gt;"
        "&lt;URI&gt;\\Microsoft\\Windows\\UpdateOrchestrator\\Maintenance Install&lt;/URI&gt;"
        "&lt;/RegistrationInfo&gt;"
        "&lt;Principals&gt;&lt;Principal id=\"Author\"&gt;&lt;UserId&gt;S-1-5-18&lt;/UserId&gt;"
        "&lt;RunLevel&gt;HighestAvailable&lt;/RunLevel&gt;&lt;/Principal&gt;&lt;/Principals&gt;"
        "&lt;Actions Context=\"Author\"&gt;&lt;Exec&gt;"
        "&lt;Command&gt;%windir%\\system32\\usoclient.exe&lt;/Command&gt;"
        "&lt;Arguments&gt;StartInstall&lt;/Arguments&gt;"
        "&lt;/Exec&gt;&lt;/Actions&gt;&lt;/Task&gt;"
    )
    data = [
        {"@Name": "SubjectUserSid", "#text": "S-1-5-18"},
        {"@Name": "SubjectUserName", "#text": "SYSTEM"},
        {"@Name": "SubjectDomainName", "#text": "NT AUTHORITY"},
        {"@Name": "SubjectLogonId", "#text": "0x3e7"},
        {"@Name": "TaskName",
         "#text": "\\Microsoft\\Windows\\UpdateOrchestrator\\Maintenance Install"},
        {"@Name": "TaskContent", "#text": task_xml},
        {"@Name": "ClientProcessStartKey",
         "#text": "844424930131969"},
        {"@Name": "ClientProcessId", "#text": "2068"},
        {"@Name": "ParentProcessId", "#text": "1104"},
        {"@Name": "RpcCallClientLocality", "#text": "3"},
        {"@Name": "FQDN", "#text": "win10-admin.offsec.lan"},
    ]
    row = _blank_row()
    row.update({
        "RecordNumber": "912703",
        "EventRecordId": "912703",
        "TimeCreated": "2025-09-18 03:00:02.4419871",
        "EventId": "4698",
        "Level": "0",
        "Provider": "Microsoft-Windows-Security-Auditing",
        "Channel": "Security",
        "Computer": "win10-admin.offsec.lan",
        "UserId": "S-1-5-18",
        "Payload": json.dumps({"EventData": {"Data": data}}),
    })
    yield row


SCENARIOS = [
    ("BENIGN-ID33205-SQL Server successful admin login.csv",
     sql_successful_admin_login),
    ("BENIGN-ID1-Admin PowerShell routine diagnostic.csv",
     admin_powershell_diagnostic),
    ("BENIGN-ID4698-Windows Update scheduled task.csv",
     windows_update_scheduled_task),
]


def write_scenarios(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for fname, factory in SCENARIOS:
        path = out_dir / fname
        rows = list(factory())
        with open(path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=EVTXECMD_HEADER)
            writer.writeheader()
            writer.writerows(rows)
        print(f"[OK] wrote {path} ({len(rows)} rows)")


if __name__ == "__main__":
    write_scenarios(Path("test_data/csv/_benign"))
