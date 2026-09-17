#!/usr/bin/env python3
"""Fill ground truth gaps in ground_truth_evidence.json."""
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

INCOMPLETE_ENTRIES = {
    "ID770-Success DLL loaded by DNS server.evtx": {
        "malicious_events": ["Event 770: DNS server plugin DLL loaded - potential persistence via DLL hijacking"],
        "explanation_keywords": ["dll injection", "dns server", "hijack execution", "persistence"]
    },
    "ID5124-OCSP security settings changed.evtx": {
        "malicious_events": ["Event 5124: OCSP responder security settings modified - potential PKI tampering"],
        "explanation_keywords": ["ocsp", "certificate services", "pki", "security settings modification"]
    },
    "ID800-4103-4104-LSASS dump with LSASSY (PowerShell).evtx": {
        "malicious_events": ["LSASS memory dump via LSASSY tool using PowerShell for credential extraction"],
        "explanation_keywords": ["lsass", "lsassy", "credential dumping", "memory dump", "powershell"]
    },
    "ID4103-4104-OpenSSH server install.evtx": {
        "malicious_events": ["OpenSSH server installation via PowerShell Add-WindowsCapability for remote access"],
        "explanation_keywords": ["openssh", "ssh server", "remote access", "lateral movement", "installation"]
    },
}

KEYWORDS = {
    "ID 4765 - SID history added.evtx": ["sid history injection", "privilege escalation", "token manipulation"],
    "ID 4865 4706 - trust added.evtx": ["domain trust", "trust manipulation", "privilege escalation"],
    "ID 768,775,793,796,817,840-BitLocker encryption activated.evtx": ["bitlocker", "disk encryption", "data encryption", "impact"],
    "ID-4688 Native Windows sniffer Pktmon usage.evtx": ["pktmon", "packet capture", "traffic sniffing", "network monitoring"],
    "ID1-SYSMON driver unload (FilterManager).evtx": ["sysmon", "driver unload", "defense evasion", "security tool disabled"],
    "ID104-1102-Event log cleared.evtx": ["event log cleared", "anti-forensics", "log tampering"],
    "ID11-DNS hosts files modified.evtx": ["hosts file", "dns manipulation", "data manipulation"],
    "ID11-Exchange transport config modified.evtx": ["exchange", "transport config", "mail server persistence"],
    "ID11715-SQL Server started in single mode for psw recovery.evtx": ["sql server", "single user mode", "password recovery"],
    "ID12-LSA Protect mode enabled RunAsPPL.evtx": ["lsa protection", "runasppl", "registry modification", "credential protection"],
    "ID2004-Any any firewall rule created.evtx": ["firewall rule", "permissive rule", "defense evasion"],
    "ID3-59-60-BITS job created.evtx": ["bits", "background transfer", "persistence", "download"],
    "ID316,300,301,316,823,848-Mimispool printer server instal.evtx": ["mimispool", "print spooler", "dll side-loading", "privilege escalation"],
    "ID325-327-IFM created - ESENT.evtx": ["ifm", "ntds.dit", "credential dumping", "esent"],
    "ID33205-SQL Server  audit object disabled.evtx": ["sql server", "audit disabled", "defense evasion", "logging disabled"],
    "ID33205-SQL Server Database audit specification disabled.evtx": ["sql server", "database audit", "audit disabled", "defense evasion"],
    "ID33205-SQL Server Disabled SA user activated.evtx": ["sql server", "sa account", "account activation", "persistence"],
    "ID33205-SQL Server audit specification disabled.evtx": ["sql server", "audit specification", "audit disabled", "defense evasion"],
    "ID33205-SQL Server local user created.evtx": ["sql server", "user creation", "persistence", "database account"],
    "ID33205-SQL Server member added to database role.evtx": ["sql server", "database role", "privilege escalation", "account manipulation"],
    "ID33205-SQL Server member added to server role.evtx": ["sql server", "sysadmin role", "privilege escalation", "account manipulation"],
    "ID33205-SQL Server user linked to a database.evtx": ["sql server", "database user", "account manipulation", "persistence"],
    "ID354-808-Mimispool printer installation (PrintNightmare).evtx": ["printnightmare", "mimispool", "print spooler", "dll side-loading"],
    "ID4-OpenSSH server listening.evtx": ["openssh", "ssh server", "remote access", "lateral movement"],
    "ID4103-4104-OpenSSH server activation and config.evtx": ["openssh", "ssh configuration", "remote access", "powershell"],
    "ID4661-Password policy enumeration.evtx": ["password policy", "discovery", "policy enumeration"],
    "ID4661-SAM sensitive domain users & groups discovery.evtx": ["sam database", "domain enumeration", "group discovery", "reconnaissance"],
    "ID4662-4624-Honeypot account property read.evtx": ["honeypot account", "account discovery", "deception detection"],
    "ID4662-Domain group enumeration CME.evtx": ["crackmapexec", "domain group", "group enumeration", "discovery"],
    "ID4662-Sensitve DPAPI attributes accessed.evtx": ["dpapi", "credential access", "password store", "sensitive attributes"],
    "ID4664-symbolic link created.evtx": ["symbolic link", "persistence", "file system manipulation"],
    "ID4688,6416,4648-SystemNightMare.evtx": ["systemnightmare", "dll side-loading", "privilege escalation", "log clearing"],
    "ID4688-5447-4950-Firewall disabled (command).evtx": ["firewall disabled", "netsh", "defense evasion", "security tool disabled"],
    "ID4688-Audit policy clear attempt.evtx": ["auditpol", "audit policy", "log tampering", "defense evasion"],
    "ID4688-Audit policy deactivation attempt.evtx": ["auditpol", "audit policy", "logging disabled", "defense evasion"],
    "ID4688-Audit policy enumerated.evtx": ["auditpol", "audit policy", "discovery", "security configuration"],
    "ID4688-BITS transfer initiated.evtx": ["bitsadmin", "bits transfer", "file download", "persistence"],
    "ID4688-Certutil download.evtx": ["certutil", "file download", "lolbin", "defense evasion"],
    "ID4688-Firewall configuration enumerated (command).evtx": ["netsh", "firewall enumeration", "network discovery"],
    "ID4688-Group discovery via commandline.evtx": ["net group", "domain group", "discovery", "enumeration"],
    "ID4688-IFM created.evtx": ["ntdsutil", "ifm", "credential dumping", "ntds.dit"],
    "ID4688-Linux Subsystem installation (WSL).evtx": ["wsl", "linux subsystem", "defense evasion", "dism"],
    "ID4688-Network share discovery or connection via commandline.evtx": ["net view", "net use", "network share", "discovery"],
    "ID4688-Network share manipulation via commandline.evtx": ["net share", "smb", "admin share", "lateral movement"],
    "ID4688-Password policy discovery via commandline.evtx": ["net accounts", "password policy", "discovery"],
    "ID4688-SPN added to an account.evtx": ["setspn", "spn", "kerberoasting setup", "persistence"],
    "ID4688-SQL Server started in single mode for psw recovery.evtx": ["sql server", "single user mode", "password recovery", "sqlservr"],
    "ID4688-User creation via commandline.evtx": ["net user", "account creation", "persistence"],
    "ID4688-User enumeration via command.evtx": ["net user", "account enumeration", "discovery"],
    "ID4704-4705-User righ assigned to account.evtx": ["user rights", "privilege assignment", "token manipulation"],
    "ID4717-4718-System security granded to account.evtx": ["system security", "privilege assignment", "access token"],
    "ID4719-Audit policy deactivation.evtx": ["audit policy", "policy change", "logging disabled", "defense evasion"],
    "ID472, 4728 Hidden user creation.evtx": ["hidden account", "registry manipulation", "account creation", "persistence"],
    "ID4720-Admin like user created.evtx": ["admin account", "account creation", "persistence"],
    "ID4720-Fake computer account created.evtx": ["fake computer", "machine account", "account creation"],
    "ID4720-Local user created.evtx": ["local account", "account creation", "persistence"],
    "ID4722-Guest account activated.evtx": ["guest account", "account activation", "persistence"],
    "ID4728-4756-Member added to sensitive domain groups.evtx": ["domain admins", "enterprise admins", "group membership", "privilege escalation"],
    "ID4728-Massive account group membership change.evtx": ["mass group change", "group membership", "account manipulation"],
    "ID4728-Member adding to a group by the same account.evtx": ["self-enrollment", "group membership", "account manipulation"],
    "ID4732-4733-Quick added-removed user from local group.evtx": ["quick add-remove", "group manipulation", "evasion"],
    "ID4732-DNSadmin new member added.evtx": ["dnsadmins", "group membership", "privilege escalation"],
    "ID4732-User added to local admin groups.evtx": ["local admin", "group membership", "privilege escalation"],
    "ID4738,5136-SPN set on user account.evtx": ["spn", "kerberoasting", "account manipulation"],
    "ID4738-Account is sensitive and cannot be delegated.evtx": ["delegation", "account flag", "account manipulation"],
    "ID4738-Account with password not required.evtx": ["password not required", "account flag", "weak security"],
    "ID4738-Do not require Kerberos preauthentication.evtx": ["asrep roasting", "kerberos preauth", "account flag"],
    "ID4738-Password cannot be changed.evtx": ["password policy", "account flag", "persistence"],
    "ID4738-Password never expires.evtx": ["password expiry", "account flag", "persistence"],
    "ID4738-Use only Kerberos DES encryption types.evtx": ["des encryption", "weak encryption", "kerberos downgrade"],
    "ID4738-User set with reversible psw encryption.evtx": ["reversible encryption", "weak password storage", "account flag"],
    "ID4739-Domain policy changed by non system account.evtx": ["domain policy", "policy change", "defense evasion"],
    "ID4742,5136-SPN set on computer account.evtx": ["spn", "computer account", "kerberoasting", "account manipulation"],
    "ID4756-Exchange admin group change.evtx": ["exchange", "admin group", "privilege escalation"],
    "ID4756-Exchange critical group change (DCsync).evtx": ["exchange servers", "dcsync", "credential dumping", "replication"],
    "ID4768-4769-Kerberos host ticket without a trailing $.evtx": ["kerberos", "missing dollar sign", "anomalous ticket"],
    "ID4768-Kerberos AS-REP Roasting.evtx": ["asrep roasting", "kerberos", "credential access"],
    "ID4769-Golden ticket issued.evtx": ["golden ticket", "kerberos", "forged ticket", "persistence"],
    "ID4769-Kerberoast ticket with low encryption.evtx": ["kerberoasting", "weak encryption", "service ticket"],
    "ID4769-Kerberos TGS host enumeration (Bloodhound).evtx": ["bloodhound", "kerberos enumeration", "tgs", "discovery"],
    "ID4781-4738-User renamed to admin or likely.evtx": ["account rename", "admin impersonation", "persistence"],
    "ID4781-Computer account renamed without a trailing $ (CVE-2021-42278).evtx": ["samaccountname spoofing", "cve-2021-42278", "nopac"],
    "ID4794-4688-DSRM password set with NTDSutil.evtx": ["dsrm", "ntdsutil", "directory services", "credential access"],
    "ID4885,4876,4877,5123,5124-ADCS PKI OCSP.evtx": ["adcs", "pki", "certificate services", "ocsp"],
    "ID4908-Special group table changed.evtx": ["special groups", "audit configuration", "defense evasion"],
    "ID5007-Defender threat exclusion (native).evtx": ["windows defender", "exclusion", "antivirus bypass", "defense evasion"],
    "ID5136-4662 AD object owner changed.evtx": ["ad object", "owner change", "permissions", "persistence"],
    "ID5136-4662 sensitive GPO edited.evtx": ["gpo", "group policy", "policy modification", "privilege escalation"],
    "ID5136-AdminSDholder backdoor obfuscation (via localizationDisplayId).evtx": ["adminsdholder", "backdoor", "obfuscation", "persistence"],
    "ID5136-AdminSDholder permissions changed.evtx": ["adminsdholder", "permissions", "persistence", "privilege escalation"],
    "ID5136-Computer account set for RBCD delegation.evtx": ["rbcd", "resource-based delegation", "kerberos", "lateral movement"],
    "ID5136-Permission change on OU by computer.evtx": ["ou permissions", "acl modification", "defense evasion"],
    "ID5136-Permission change on OU by user.evtx": ["ou permissions", "acl modification", "defense evasion"],
    "ID5136-Permission change on top root AD (DCsync).evtx": ["dcsync", "ad root permissions", "replication rights"],
    "ID5136-Permissions changed on a GPO.evtx": ["gpo permissions", "acl modification", "defense evasion"],
    "ID5140-ADMIN$ share connection with Golden ticket.evtx": ["admin share", "golden ticket", "lateral movement", "smb"],
    "ID5142- New file share created.evtx": ["file share", "smb share", "lateral movement"],
    "ID5142-5143-Mimispool print share created and modified.evtx": ["mimispool", "print share", "printnightmare", "lateral movement"],
    "ID5143-File share permissions changed.evtx": ["share permissions", "acl modification", "defense evasion"],
    "ID5145-DNS hosts files access via network share.evtx": ["dns hosts", "network share", "remote file access"],
    "ID5145-Print spooler bug abuse.evtx": ["print spooler", "spoolss", "coerced authentication", "mitm"],
    "ID541-DNS server auditing changed.evtx": ["dns auditing", "logging disabled", "defense evasion"],
    "ID5600-proxy configuration changed.evtx": ["proxy", "command and control", "network configuration"],
    "ID60-High volume file downloaded with BITS.evtx": ["bits", "file download", "high volume", "ingress tool transfer"],
    "ID800-4103-4104-Clear event log attempt.evtx": ["clear-eventlog", "powershell", "log tampering", "anti-forensics"],
}


def main():
    gt_path = PROJECT_ROOT / "ground_truth_evidence.json"
    meta_path = PROJECT_ROOT / "metadata.json"

    with open(gt_path, "r", encoding="utf-8") as f:
        gt = json.load(f)
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    meta_files = meta["files"]
    gt_files = gt["files"]

    # 1. Fix incomplete entries
    fixed_incomplete = 0
    for fname, extra in INCOMPLETE_ENTRIES.items():
        if fname not in gt_files:
            print(f"  WARNING: {fname} not found in ground_truth_evidence.json")
            continue
        m = meta_files.get(fname, {})
        entry = gt_files[fname]
        entry["difficulty"] = m.get("difficulty", "easy")
        entry["test_set"] = m.get("test_set", "A")
        entry["total_events"] = m.get("total_events", 0)
        entry["signal_events"] = m.get("signal_events", 0)
        entry["signal_ratio"] = m.get("signal_ratio", 0.0)
        entry["malicious_events"] = extra["malicious_events"]
        entry["explanation_keywords"] = extra["explanation_keywords"]
        fixed_incomplete += 1
        print(f"  FIXED incomplete: {fname}")

    # 2. Fill empty keywords
    filled_keywords = 0
    for fname, keywords in KEYWORDS.items():
        if fname not in gt_files:
            print(f"  WARNING: {fname} not found in ground_truth_evidence.json")
            continue
        entry = gt_files[fname]
        if entry.get("explanation_keywords"):
            print(f"  SKIP (already has keywords): {fname}")
            continue
        entry["explanation_keywords"] = keywords
        filled_keywords += 1

    # Write back
    with open(gt_path, "w", encoding="utf-8") as f:
        json.dump(gt, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"\nDone: fixed {fixed_incomplete} incomplete entries, filled {filled_keywords} keyword entries")


if __name__ == "__main__":
    main()
