"""Phase 2 benign corpus expansion: 22 additional benign scenarios.

The 8 existing benigns aren't enough to drive a credible FP-rate metric — at
that sample size every misclassification swings the rate by 12.5pp and the
verdict layer flags the run as "needs more data" anyway. This script adds 22
scenarios spread across high-FP event IDs so a Comprehensive run will land
above the 30-sample threshold the verdict module enforces.

Each scenario emits one CSV at test_data/csv/_benign/BENIGN-*.csv plus
matching entries in metadata.json (tactic_id=BENIGN, csv_only=true) and
ground_truth_evidence.json (malicious=NO). Run from the repo root:

    python scripts/generate_more_benigns.py

Scenarios were picked to look superficially suspicious in isolation —
Sysmon process creates of LOLBins, privileged operations by service
accounts, account-management actions, scheduled-task creation — so a
detector that pattern-matches "EventID X = bad" will misclassify them.
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


def _kv(pairs):
    return [{"@Name": k, "#text": v} for k, v in pairs]


def _sysmon1(record, ts, computer, user_sid, image, cmdline, user, parent_image,
             parent_cmd, parent_user="NT AUTHORITY\\SYSTEM",
             integrity="System", session_id="0", description="",
             original_filename="", company="Microsoft Corporation"):
    """Helper for Sysmon ID 1 process-create rows — most common shape."""
    return _row(
        record_number=record, time_created=str(ts),
        event_id=1, level=4,
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        user_id=user_sid, computer=computer,
        payload_data=_kv([
            ("RuleName", "-"),
            ("UtcTime", str(ts)),
            ("ProcessGuid", f"{{1234aabb-{record:04x}-aabb-cccc-{record:012d}}}"),
            ("ProcessId", str(4000 + record % 4000)),
            ("Image", image),
            ("FileVersion", "10.0.19041.5072"),
            ("Description", description or image.rsplit("\\", 1)[-1]),
            ("Product", "Microsoft Windows Operating System"),
            ("Company", company),
            ("OriginalFileName", original_filename or image.rsplit("\\", 1)[-1]),
            ("CommandLine", cmdline),
            ("CurrentDirectory", "C:\\Windows\\system32\\"),
            ("User", user),
            ("LogonGuid", "{1234aabb-0000-0000-0000-000000000000}"),
            ("LogonId", "0x3e7"),
            ("TerminalSessionId", session_id),
            ("IntegrityLevel", integrity),
            ("ParentProcessId", "1024"),
            ("ParentImage", parent_image),
            ("ParentCommandLine", parent_cmd),
            ("ParentUser", parent_user),
        ]),
    )


# ── 1: admin opens MMC console from RDP session ─────────────────────────────
def gen_admin_mmc_console():
    base = datetime(2025, 9, 22, 9, 14, 0, 0)
    rows = [_sysmon1(
        record=930101, ts=base, computer="win10-admin.offsec.lan",
        user_sid="S-1-5-21-4230534742-2542757381-3142984815-1010",
        image="C:\\Windows\\System32\\mmc.exe",
        cmdline="\"C:\\Windows\\System32\\mmc.exe\" C:\\Windows\\System32\\dsa.msc",
        user="OFFSEC\\admin", session_id="2", integrity="High",
        parent_image="C:\\Windows\\explorer.exe",
        parent_cmd="C:\\Windows\\Explorer.EXE",
        parent_user="OFFSEC\\admin",
        description="Microsoft Management Console",
        original_filename="MMC.EXE",
    )]
    return rows, "BENIGN-ID1-Admin MMC console session via RDP.evtx"


# ── 2: SCCM creates a patch-deployment scheduled task ────────────────────────
def gen_sccm_schtasks_create():
    base = datetime(2025, 9, 22, 14, 30, 0, 0)
    rows = [_sysmon1(
        record=930102, ts=base, computer="win10-admin.offsec.lan",
        user_sid="S-1-5-18",
        image="C:\\Windows\\System32\\schtasks.exe",
        cmdline="schtasks.exe /create /tn \"Microsoft\\Configuration Manager\\Patch Compliance Scan\" /xml \"C:\\Windows\\CCM\\Tasks\\PatchScan.xml\" /f",
        user="NT AUTHORITY\\SYSTEM",
        parent_image="C:\\Windows\\CCM\\CcmExec.exe",
        parent_cmd="\"C:\\Windows\\CCM\\CcmExec.exe\"",
        description="Manages scheduled tasks",
        original_filename="schtasks.exe",
    )]
    return rows, "BENIGN-ID1-SCCM creates patch deployment scheduled task.evtx"


# ── 3: Helpdesk audits Domain Admins membership via net.exe ──────────────────
def gen_helpdesk_net_group_audit():
    base = datetime(2025, 9, 22, 11, 5, 0, 0)
    rows = [_sysmon1(
        record=930103, ts=base, computer="win10-it01.offsec.lan",
        user_sid="S-1-5-21-4230534742-2542757381-3142984815-1100",
        image="C:\\Windows\\System32\\net.exe",
        cmdline="net.exe group \"Domain Admins\" /domain",
        user="OFFSEC\\helpdesk-svc", session_id="3", integrity="Medium",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        parent_cmd="\"C:\\Windows\\System32\\cmd.exe\"",
        parent_user="OFFSEC\\helpdesk-svc",
        description="Net Command",
        original_filename="net.exe",
    )]
    return rows, "BENIGN-ID1-Helpdesk audits Domain Admins membership.evtx"


# ── 4: SCCM hardware inventory via WMIC ──────────────────────────────────────
def gen_sccm_wmic_inventory():
    base = datetime(2025, 9, 22, 4, 45, 0, 0)
    rows = [_sysmon1(
        record=930104, ts=base, computer="win10-admin.offsec.lan",
        user_sid="S-1-5-18",
        image="C:\\Windows\\System32\\wbem\\WMIC.exe",
        cmdline="wmic.exe /namespace:\\\\root\\ccm path SMS_Client get ClientVersion /format:list",
        user="NT AUTHORITY\\SYSTEM",
        parent_image="C:\\Windows\\CCM\\CcmExec.exe",
        parent_cmd="\"C:\\Windows\\CCM\\CcmExec.exe\"",
        description="WMI Commandline Utility",
        original_filename="wmic.exe",
    )]
    return rows, "BENIGN-ID1-SCCM hardware inventory via wmic.evtx"


# ── 5: Group Policy preferences apply registry change via reg.exe ────────────
def gen_gpo_reg_add():
    base = datetime(2025, 9, 22, 8, 35, 0, 0)
    rows = [_sysmon1(
        record=930105, ts=base, computer="win10-admin.offsec.lan",
        user_sid="S-1-5-18",
        image="C:\\Windows\\System32\\reg.exe",
        cmdline="reg.exe add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\" /v NoAutoUpdate /t REG_DWORD /d 0 /f",
        user="NT AUTHORITY\\SYSTEM",
        parent_image="C:\\Windows\\System32\\svchost.exe",
        parent_cmd="C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s gpsvc",
        description="Registry Console Tool",
        original_filename="reg.exe",
    )]
    return rows, "BENIGN-ID1-GPO applies registry policy via reg add.evtx"


# ── 6: SCCM applies firewall baseline via netsh ──────────────────────────────
def gen_sccm_netsh_firewall():
    base = datetime(2025, 9, 22, 5, 20, 0, 0)
    rows = [_sysmon1(
        record=930106, ts=base, computer="win10-admin.offsec.lan",
        user_sid="S-1-5-18",
        image="C:\\Windows\\System32\\netsh.exe",
        cmdline="netsh.exe advfirewall set domainprofile state on",
        user="NT AUTHORITY\\SYSTEM",
        parent_image="C:\\Windows\\CCM\\CcmExec.exe",
        parent_cmd="\"C:\\Windows\\CCM\\CcmExec.exe\"",
        description="Network Command Shell",
        original_filename="netsh.exe",
    )]
    return rows, "BENIGN-ID1-SCCM enforces firewall domain profile via netsh.evtx"


# ── 7: Windows Update transfers patch via bitsadmin ──────────────────────────
def gen_wu_bitsadmin_transfer():
    base = datetime(2025, 9, 22, 3, 12, 0, 0)
    rows = [_sysmon1(
        record=930107, ts=base, computer="win10-admin.offsec.lan",
        user_sid="S-1-5-18",
        image="C:\\Windows\\System32\\bitsadmin.exe",
        cmdline="bitsadmin.exe /transfer WU_Maintenance /priority normal http://download.windowsupdate.com/c/msdownload/update/software/secu/2025/09/x.cab C:\\Windows\\SoftwareDistribution\\Download\\x.cab",
        user="NT AUTHORITY\\SYSTEM",
        parent_image="C:\\Windows\\System32\\svchost.exe",
        parent_cmd="C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s BITS",
        description="Background Intelligent Transfer Service Admin Tool",
        original_filename="bitsadmin.exe",
    )]
    return rows, "BENIGN-ID1-Windows Update bitsadmin patch transfer.evtx"


# ── 8: Service logon (type 5) — Veeam Backup Service start ───────────────────
def gen_4624_service_logon_veeam():
    base = datetime(2025, 9, 22, 1, 0, 5, 0)
    rows = [_row(
        record_number=930200, time_created=str(base),
        event_id=4624, level=0,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        user_id="", computer="bkp01.offsec.lan",
        payload_data=_kv([
            ("SubjectUserSid", "S-1-5-18"),
            ("SubjectUserName", "BKP01$"),
            ("SubjectDomainName", "OFFSEC"),
            ("SubjectLogonId", "0x3e7"),
            ("TargetUserSid", "S-1-5-21-4230534742-2542757381-3142984815-1234"),
            ("TargetUserName", "svc-veeam"),
            ("TargetDomainName", "OFFSEC"),
            ("TargetLogonId", "0x9b1c2d3"),
            ("LogonType", "5"),
            ("LogonProcessName", "Advapi  "),
            ("AuthenticationPackageName", "Negotiate"),
            ("WorkstationName", "-"),
            ("LogonGuid", "{00000000-0000-0000-0000-000000000000}"),
            ("ProcessId", "0x344"),
            ("ProcessName", "C:\\Windows\\System32\\services.exe"),
            ("IpAddress", "-"),
            ("IpPort", "-"),
            ("ImpersonationLevel", "%%1833"),
        ]),
    )]
    return rows, "BENIGN-ID4624-Service logon for Veeam Backup Service.evtx"


# ── 9: Batch logon (type 4) — Microsoft Update Orchestrator ──────────────────
def gen_4624_batch_logon_uo():
    base = datetime(2025, 9, 22, 3, 0, 0, 0)
    rows = [_row(
        record_number=930201, time_created=str(base),
        event_id=4624, level=0,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        user_id="", computer="win10-admin.offsec.lan",
        payload_data=_kv([
            ("SubjectUserSid", "S-1-5-18"),
            ("SubjectUserName", "WIN10-ADMIN$"),
            ("SubjectDomainName", "OFFSEC"),
            ("SubjectLogonId", "0x3e7"),
            ("TargetUserSid", "S-1-5-18"),
            ("TargetUserName", "SYSTEM"),
            ("TargetDomainName", "NT AUTHORITY"),
            ("TargetLogonId", "0xa12b34c"),
            ("LogonType", "4"),
            ("LogonProcessName", "Advapi  "),
            ("AuthenticationPackageName", "Negotiate"),
            ("WorkstationName", "-"),
            ("ProcessId", "0x344"),
            ("ProcessName", "C:\\Windows\\System32\\services.exe"),
            ("IpAddress", "-"),
            ("IpPort", "-"),
        ]),
    )]
    return rows, "BENIGN-ID4624-Batch logon for Update Orchestrator task.evtx"


# ── 10: RDP logon (type 10) from corporate jumpbox ───────────────────────────
def gen_4624_rdp_jumpbox():
    base = datetime(2025, 9, 22, 9, 13, 47, 0)
    rows = [_row(
        record_number=930202, time_created=str(base),
        event_id=4624, level=0,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        user_id="", computer="win10-admin.offsec.lan",
        payload_data=_kv([
            ("SubjectUserSid", "S-1-0-0"),
            ("SubjectUserName", "-"),
            ("SubjectDomainName", "-"),
            ("SubjectLogonId", "0x0"),
            ("TargetUserSid", "S-1-5-21-4230534742-2542757381-3142984815-1010"),
            ("TargetUserName", "admin"),
            ("TargetDomainName", "OFFSEC"),
            ("TargetLogonId", "0xc44d12e"),
            ("LogonType", "10"),
            ("LogonProcessName", "User32 "),
            ("AuthenticationPackageName", "Negotiate"),
            ("WorkstationName", "JUMP01"),
            ("ProcessId", "0x4a8"),
            ("ProcessName", "C:\\Windows\\System32\\winlogon.exe"),
            ("IpAddress", "10.23.50.10"),  # corporate jumpbox subnet
            ("IpPort", "51422"),
            ("ImpersonationLevel", "%%1833"),
        ]),
    )]
    return rows, "BENIGN-ID4624-Admin RDP from corporate jumpbox.evtx"


# ── 11: SMB share access (type 3) — user reads from public share ────────────
def gen_4624_smb_public_share():
    base = datetime(2025, 9, 22, 10, 7, 22, 0)
    rows = [_row(
        record_number=930203, time_created=str(base),
        event_id=4624, level=0,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        user_id="", computer="fileserver01.offsec.lan",
        payload_data=_kv([
            ("SubjectUserSid", "S-1-0-0"),
            ("SubjectUserName", "-"),
            ("SubjectDomainName", "-"),
            ("SubjectLogonId", "0x0"),
            ("TargetUserSid", "S-1-5-21-4230534742-2542757381-3142984815-2001"),
            ("TargetUserName", "jdoe"),
            ("TargetDomainName", "OFFSEC"),
            ("TargetLogonId", "0x55d77a2"),
            ("LogonType", "3"),
            ("LogonProcessName", "Kerberos"),
            ("AuthenticationPackageName", "Kerberos"),
            ("WorkstationName", "-"),
            ("ProcessId", "0x0"),
            ("ProcessName", "-"),
            ("IpAddress", "10.23.30.45"),
            ("IpPort", "49827"),
        ]),
    )]
    return rows, "BENIGN-ID4624-User SMB read from public share.evtx"


# ── 12: 4673 — SeBackupPrivilege invoked by Veeam ────────────────────────────
def gen_4673_veeam_backup_priv():
    base = datetime(2025, 9, 22, 1, 5, 12, 0)
    rows = [_row(
        record_number=930300, time_created=str(base),
        event_id=4673, level=0,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        user_id="", computer="bkp01.offsec.lan",
        payload_data=_kv([
            ("SubjectUserSid", "S-1-5-21-4230534742-2542757381-3142984815-1234"),
            ("SubjectUserName", "svc-veeam"),
            ("SubjectDomainName", "OFFSEC"),
            ("SubjectLogonId", "0x9b1c2d3"),
            ("ObjectServer", "Security"),
            ("ServiceName", "-"),
            ("PrivilegeList", "SeBackupPrivilege"),
            ("ProcessId", "0x1c08"),
            ("ProcessName", "C:\\Program Files\\Veeam\\Backup and Replication\\Backup\\VeeamAgent.exe"),
        ]),
    )]
    return rows, "BENIGN-ID4673-Veeam backup uses SeBackupPrivilege.evtx"


# ── 13: 4674 — Defender reads registry during scan ──────────────────────────
def gen_4674_defender_registry_read():
    base = datetime(2025, 9, 22, 2, 4, 0, 0)
    rows = [_row(
        record_number=930301, time_created=str(base),
        event_id=4674, level=0,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        user_id="", computer="win10-admin.offsec.lan",
        payload_data=_kv([
            ("SubjectUserSid", "S-1-5-18"),
            ("SubjectUserName", "WIN10-ADMIN$"),
            ("SubjectDomainName", "OFFSEC"),
            ("SubjectLogonId", "0x3e7"),
            ("ObjectServer", "Security"),
            ("ObjectType", "Key"),
            ("ObjectName", "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
            ("HandleId", "0x4d8"),
            ("AccessMask", "0x20019"),
            ("PrivilegeList", "-"),
            ("ProcessId", "0x14b8"),
            ("ProcessName", "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24080.4-0\\MsMpEng.exe"),
        ]),
    )]
    return rows, "BENIGN-ID4674-Defender reads Run key during scan.evtx"


# ── 14: 4672 — Special privileges assigned to admin during scheduled MMC ────
def gen_4672_admin_special_privs():
    base = datetime(2025, 9, 22, 9, 13, 49, 0)
    rows = [_row(
        record_number=930302, time_created=str(base),
        event_id=4672, level=0,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        user_id="", computer="win10-admin.offsec.lan",
        payload_data=_kv([
            ("SubjectUserSid", "S-1-5-21-4230534742-2542757381-3142984815-1010"),
            ("SubjectUserName", "admin"),
            ("SubjectDomainName", "OFFSEC"),
            ("SubjectLogonId", "0xc44d12e"),
            ("PrivilegeList",
             "SeSecurityPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\tSeRestorePrivilege\n\t\t\t"
             "SeTakeOwnershipPrivilege\n\t\t\tSeDebugPrivilege\n\t\t\tSeSystemEnvironmentPrivilege\n\t\t\t"
             "SeLoadDriverPrivilege\n\t\t\tSeImpersonatePrivilege"),
        ]),
    )]
    return rows, "BENIGN-ID4672-Admin RDP session special privileges.evtx"


# ── 15: 4720 — Helpdesk creates user account (onboarding) ───────────────────
def gen_4720_helpdesk_create_user():
    base = datetime(2025, 9, 22, 10, 32, 0, 0)
    rows = [_row(
        record_number=930400, time_created=str(base),
        event_id=4720, level=0,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        user_id="", computer="rootdc1.offsec.lan",
        payload_data=_kv([
            ("TargetUserName", "msmith"),
            ("TargetDomainName", "OFFSEC"),
            ("TargetSid", "S-1-5-21-4230534742-2542757381-3142984815-3100"),
            ("SubjectUserSid", "S-1-5-21-4230534742-2542757381-3142984815-1100"),
            ("SubjectUserName", "helpdesk-svc"),
            ("SubjectDomainName", "OFFSEC"),
            ("SubjectLogonId", "0x6e2f1a9"),
            ("PrivilegeList", "-"),
            ("SamAccountName", "msmith"),
            ("DisplayName", "Mary Smith"),
            ("UserPrincipalName", "msmith@offsec.lan"),
            ("UserAccountControl", "%%2080"),  # NORMAL_ACCOUNT
            ("UserParameters", "-"),
            ("PasswordLastSet", "<never>"),
            ("AccountExpires", "<never>"),
            ("PrimaryGroupId", "513"),
            ("AllowedToDelegateTo", "-"),
        ]),
    )]
    return rows, "BENIGN-ID4720-Helpdesk creates user during onboarding.evtx"


# ── 16: 4732 — Helpdesk adds user to Software Devs group ────────────────────
def gen_4732_helpdesk_group_add():
    base = datetime(2025, 9, 22, 10, 35, 0, 0)
    rows = [_row(
        record_number=930401, time_created=str(base),
        event_id=4732, level=0,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        user_id="", computer="rootdc1.offsec.lan",
        payload_data=_kv([
            ("MemberName", "-"),
            ("MemberSid", "S-1-5-21-4230534742-2542757381-3142984815-3100"),
            ("TargetUserName", "Software Devs"),
            ("TargetDomainName", "OFFSEC"),
            ("TargetSid", "S-1-5-21-4230534742-2542757381-3142984815-2410"),
            ("SubjectUserSid", "S-1-5-21-4230534742-2542757381-3142984815-1100"),
            ("SubjectUserName", "helpdesk-svc"),
            ("SubjectDomainName", "OFFSEC"),
            ("SubjectLogonId", "0x6e2f1a9"),
            ("PrivilegeList", "-"),
        ]),
    )]
    return rows, "BENIGN-ID4732-Helpdesk adds user to Software Devs group.evtx"


# ── 17: 4738 — Helpdesk resets password for locked-out user ─────────────────
def gen_4738_helpdesk_password_reset():
    base = datetime(2025, 9, 22, 11, 2, 0, 0)
    rows = [_row(
        record_number=930402, time_created=str(base),
        event_id=4738, level=0,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        user_id="", computer="rootdc1.offsec.lan",
        payload_data=_kv([
            ("TargetUserName", "rjones"),
            ("TargetDomainName", "OFFSEC"),
            ("TargetSid", "S-1-5-21-4230534742-2542757381-3142984815-2099"),
            ("SubjectUserSid", "S-1-5-21-4230534742-2542757381-3142984815-1100"),
            ("SubjectUserName", "helpdesk-svc"),
            ("SubjectDomainName", "OFFSEC"),
            ("SubjectLogonId", "0x6e2f1a9"),
            ("PrivilegeList", "-"),
            ("SamAccountName", "rjones"),
            ("DisplayName", "<value not set>"),
            ("UserPrincipalName", "<value not set>"),
            ("HomeDirectory", "<value not set>"),
            ("HomePath", "<value not set>"),
            ("ScriptPath", "<value not set>"),
            ("ProfilePath", "<value not set>"),
            ("UserWorkstations", "<value not set>"),
            ("PasswordLastSet", "9/22/2025 11:02:00 AM"),
            ("AccountExpires", "<never>"),
            ("PrimaryGroupId", "513"),
            ("AllowedToDelegateTo", "-"),
            ("OldUacValue", "0x210"),
            ("NewUacValue", "0x210"),
            ("UserAccountControl", "-"),
            ("UserParameters", "<value not set>"),
            ("SidHistory", "-"),
            ("LogonHours", "<value not set>"),
        ]),
    )]
    return rows, "BENIGN-ID4738-Helpdesk password reset for locked user.evtx"


# ── 18: 4702 — Microsoft updates existing scheduled task ────────────────────
def gen_4702_ms_task_update():
    base = datetime(2025, 9, 22, 0, 5, 0, 0)
    task_xml = (
        "&lt;?xml version=\"1.0\" encoding=\"UTF-16\"?&gt;"
        "&lt;Task version=\"1.4\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"&gt;"
        "&lt;RegistrationInfo&gt;"
        "&lt;Author&gt;Microsoft Corporation&lt;/Author&gt;"
        "&lt;URI&gt;\\Microsoft\\Windows\\Diagnosis\\Scheduled&lt;/URI&gt;"
        "&lt;/RegistrationInfo&gt;&lt;Principals&gt;&lt;Principal id=\"Author\"&gt;"
        "&lt;UserId&gt;S-1-5-18&lt;/UserId&gt;&lt;/Principal&gt;&lt;/Principals&gt;"
        "&lt;Actions Context=\"Author\"&gt;&lt;Exec&gt;"
        "&lt;Command&gt;%windir%\\system32\\rundll32.exe&lt;/Command&gt;"
        "&lt;Arguments&gt;dfdts.dll,DfdSetupTracingTask&lt;/Arguments&gt;"
        "&lt;/Exec&gt;&lt;/Actions&gt;&lt;/Task&gt;"
    )
    rows = [_row(
        record_number=930403, time_created=str(base),
        event_id=4702, level=0,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        user_id="S-1-5-18", computer="win10-admin.offsec.lan",
        payload_data=_kv([
            ("SubjectUserSid", "S-1-5-18"),
            ("SubjectUserName", "SYSTEM"),
            ("SubjectDomainName", "NT AUTHORITY"),
            ("SubjectLogonId", "0x3e7"),
            ("TaskName", "\\Microsoft\\Windows\\Diagnosis\\Scheduled"),
            ("TaskContent", task_xml),
            ("ClientProcessStartKey", "844424930262147"),
            ("ClientProcessId", "2068"),
            ("ParentProcessId", "1104"),
            ("RpcCallClientLocality", "3"),
            ("FQDN", "win10-admin.offsec.lan"),
        ]),
    )]
    return rows, "BENIGN-ID4702-Microsoft updates Diagnosis scheduled task.evtx"


# ── 19: 7045 — Adobe Acrobat Update Service installed ───────────────────────
def gen_7045_adobe_updater():
    base = datetime(2025, 9, 22, 14, 25, 0, 0)
    rows = [_row(
        record_number=930500, time_created=str(base),
        event_id=7045, level=4,
        provider="Service Control Manager",
        channel="System",
        user_id="S-1-5-21-4230534742-2542757381-3142984815-1112",
        computer="win10-admin.offsec.lan",
        payload_data=_kv([
            ("ServiceName", "AdobeARMservice"),
            ("ImagePath", "\"C:\\Program Files (x86)\\Common Files\\Adobe\\ARM\\1.0\\armsvc.exe\""),
            ("ServiceType", "user mode service"),
            ("StartType", "auto start"),
            ("AccountName", "LocalSystem"),
        ]),
    )]
    return rows, "BENIGN-ID7045-Adobe Acrobat Update Service install.evtx"


# ── 20: 4768 + 4769 — Kerberos TGT/TGS for normal user mapping a drive ──────
def gen_kerberos_drive_map():
    base = datetime(2025, 9, 22, 9, 0, 30, 0)
    rows = []
    rows.append(_row(
        record_number=930600, time_created=str(base),
        event_id=4768, level=0,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        user_id="", computer="rootdc1.offsec.lan",
        payload_data=_kv([
            ("TargetUserName", "jdoe"),
            ("TargetDomainName", "OFFSEC.LAN"),
            ("TargetSid", "S-1-5-21-4230534742-2542757381-3142984815-2001"),
            ("ServiceName", "krbtgt"),
            ("ServiceSid", "S-1-5-21-4230534742-2542757381-3142984815-502"),
            ("TicketOptions", "0x40810010"),
            ("Status", "0x0"),
            ("TicketEncryptionType", "0x12"),
            ("PreAuthType", "2"),
            ("IpAddress", "::ffff:10.23.30.45"),
            ("IpPort", "53221"),
            ("CertIssuerName", "-"),
            ("CertSerialNumber", "-"),
            ("CertThumbprint", "-"),
        ]),
    ))
    rows.append(_row(
        record_number=930601, time_created=str(base + timedelta(seconds=1)),
        event_id=4769, level=0,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        user_id="", computer="rootdc1.offsec.lan",
        payload_data=_kv([
            ("TargetUserName", "jdoe@OFFSEC.LAN"),
            ("TargetDomainName", "OFFSEC.LAN"),
            ("ServiceName", "FILESERVER01$"),
            ("ServiceSid", "S-1-5-21-4230534742-2542757381-3142984815-1500"),
            ("TicketOptions", "0x40810000"),
            ("TicketEncryptionType", "0x12"),
            ("IpAddress", "::ffff:10.23.30.45"),
            ("IpPort", "53222"),
            ("Status", "0x0"),
            ("LogonGuid", "{00000000-0000-0000-0000-000000000000}"),
            ("TransmittedServices", "-"),
        ]),
    ))
    return rows, "BENIGN-ID4768-Kerberos TGT and TGS for user drive map.evtx"


# ── 21: 4663 — File access on finance share by accountant ───────────────────
def gen_4663_finance_share_access():
    base = datetime(2025, 9, 22, 14, 18, 0, 0)
    rows = [_row(
        record_number=930602, time_created=str(base),
        event_id=4663, level=0,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        user_id="", computer="fileserver01.offsec.lan",
        payload_data=_kv([
            ("SubjectUserSid", "S-1-5-21-4230534742-2542757381-3142984815-2105"),
            ("SubjectUserName", "kpatel"),
            ("SubjectDomainName", "OFFSEC"),
            ("SubjectLogonId", "0xa1b2c3d"),
            ("ObjectServer", "Security"),
            ("ObjectType", "File"),
            ("ObjectName", "F:\\Finance\\Q3-2025\\Reconciliation.xlsx"),
            ("HandleId", "0x9c4"),
            ("AccessList", "%%4416"),  # ReadData (or ListDirectory)
            ("AccessMask", "0x1"),
            ("ProcessId", "0x4"),
            ("ProcessName", ""),
            ("ResourceAttributes", "S:AI"),
        ]),
    )]
    return rows, "BENIGN-ID4663-Accountant reads finance share file.evtx"


# ── 23: rundll32.exe printui.dll — admin sets up a network printer ──────────
def gen_rundll32_printui():
    base = datetime(2025, 9, 22, 10, 45, 0, 0)
    rows = [_sysmon1(
        record=930800, ts=base, computer="win10-admin.offsec.lan",
        user_sid="S-1-5-21-4230534742-2542757381-3142984815-1010",
        image="C:\\Windows\\System32\\rundll32.exe",
        cmdline="rundll32.exe printui.dll,PrintUIEntry /ga /n \\\\printsrv01\\HR-LaserJet",
        user="OFFSEC\\admin", session_id="2", integrity="High",
        parent_image="C:\\Windows\\explorer.exe",
        parent_cmd="C:\\Windows\\Explorer.EXE",
        parent_user="OFFSEC\\admin",
        description="Windows host process (Rundll32)",
        original_filename="RUNDLL32.EXE",
    )]
    return rows, "BENIGN-ID1-Admin sets up network printer via printui.evtx"


# ── 24: certutil.exe -hashfile — SCCM verifies content file integrity ───────
def gen_certutil_hashfile():
    base = datetime(2025, 9, 22, 7, 12, 0, 0)
    rows = [_sysmon1(
        record=930801, ts=base, computer="win10-admin.offsec.lan",
        user_sid="S-1-5-18",
        image="C:\\Windows\\System32\\certutil.exe",
        cmdline="certutil.exe -hashfile \"C:\\Windows\\ccmcache\\7\\setup.exe\" SHA256",
        user="NT AUTHORITY\\SYSTEM",
        parent_image="C:\\Windows\\CCM\\CcmExec.exe",
        parent_cmd="\"C:\\Windows\\CCM\\CcmExec.exe\"",
        description="CertUtil.exe",
        original_filename="CertUtil.exe.mui",
    )]
    return rows, "BENIGN-ID1-SCCM verifies content hash via certutil.evtx"


# ── 25: vssadmin list shadows — Veeam enumerates VSS prior to backup ────────
def gen_vssadmin_list_shadows():
    base = datetime(2025, 9, 22, 1, 4, 30, 0)
    rows = [_sysmon1(
        record=930802, ts=base, computer="bkp01.offsec.lan",
        user_sid="S-1-5-21-4230534742-2542757381-3142984815-1234",
        image="C:\\Windows\\System32\\vssadmin.exe",
        cmdline="vssadmin.exe list shadows",
        user="OFFSEC\\svc-veeam", session_id="0", integrity="System",
        parent_image="C:\\Program Files\\Veeam\\Backup and Replication\\Backup\\VeeamAgent.exe",
        parent_cmd="\"C:\\Program Files\\Veeam\\Backup and Replication\\Backup\\VeeamAgent.exe\" --job=DailyFileServer",
        parent_user="OFFSEC\\svc-veeam",
        description="Command Line Interface for Microsoft® Volume Shadow Copy Service",
        original_filename="VSSADMIN.EXE",
    )]
    return rows, "BENIGN-ID1-Veeam enumerates VSS shadow copies.evtx"


# ── 22: 4104 — PowerShell ScriptBlock for SCCM compliance check ─────────────
def gen_4104_sccm_compliance_ps():
    base = datetime(2025, 9, 22, 6, 0, 0, 0)
    script = (
        "# Configuration Manager - Compliance settings client extensions\n"
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$svc = Get-Service -Name CcmExec\n"
        "if ($svc.Status -ne 'Running') { return 'NonCompliant' }\n"
        "$ver = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\CCM').ClientVersion\n"
        "if ($ver -lt '5.00.9128') { return 'NonCompliant' }\n"
        "return 'Compliant'\n"
    )
    rows = [_row(
        record_number=930700, time_created=str(base),
        event_id=4104, level=4,  # Verbose
        provider="Microsoft-Windows-PowerShell",
        channel="Microsoft-Windows-PowerShell/Operational",
        user_id="S-1-5-18", computer="win10-admin.offsec.lan",
        payload_data=_kv([
            ("MessageNumber", "1"),
            ("MessageTotal", "1"),
            ("ScriptBlockText", script),
            ("ScriptBlockId", "{aabbccdd-1111-2222-3333-444455556666}"),
            ("Path", "C:\\Windows\\CCM\\SystemTemp\\compliance-ccmclient.ps1"),
        ]),
    )]
    return rows, "BENIGN-ID4104-SCCM compliance check PowerShell script.evtx"


GENERATORS = [
    gen_admin_mmc_console,
    gen_sccm_schtasks_create,
    gen_helpdesk_net_group_audit,
    gen_sccm_wmic_inventory,
    gen_gpo_reg_add,
    gen_sccm_netsh_firewall,
    gen_wu_bitsadmin_transfer,
    gen_4624_service_logon_veeam,
    gen_4624_batch_logon_uo,
    gen_4624_rdp_jumpbox,
    gen_4624_smb_public_share,
    gen_4673_veeam_backup_priv,
    gen_4674_defender_registry_read,
    gen_4672_admin_special_privs,
    gen_4720_helpdesk_create_user,
    gen_4732_helpdesk_group_add,
    gen_4738_helpdesk_password_reset,
    gen_4702_ms_task_update,
    gen_7045_adobe_updater,
    gen_kerberos_drive_map,
    gen_4663_finance_share_access,
    gen_4104_sccm_compliance_ps,
    gen_rundll32_printui,
    gen_certutil_hashfile,
    gen_vssadmin_list_shadows,
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
        stem = fname[:-5]  # strip .evtx
        csv_path = csv_dir / f"{stem}.csv"
        if csv_path.exists():
            print(f"  skip (exists): {csv_path.name}")
            continue
        csv_dir.mkdir(parents=True, exist_ok=True)
        with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADER)
            writer.writeheader()
            for r in rows:
                writer.writerow(r)

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

        rel = f"_benign/{stem}.csv"
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
            "full_path": f"test_data/csv/{rel}",
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
