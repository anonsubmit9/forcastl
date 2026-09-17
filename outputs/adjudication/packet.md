# Adjudication packet — 20 consensus-disagreement files
Both opus 4.8 and gpt-5.5 disagree with the GT label.


==========================================================================================
## 1. BENIGN-ID1-Helpdesk audits Domain Admins membership.csv
- GT label: **NO**  | difficulty: easy | test_set: D
- GT narrative/keywords: ['legitimate', 'routine', 'benign']
- GT malicious_events: (none)
- opus → **YES** (conf 100.0): The service account helpdesk-svc spawned net.exe from cmd.exe to enumerate members of the "Domain Admins" group via /domain, which is a classic Active Directory reconnaissance technique used to identify privileged accounts for escalation. This domain group enumeration by a non-administrative service account at medium integrity is consistent with attacker discovery activity rather than routine administrative work.
- gpt  → **YES** (conf 100.0): The command net.exe group "Domain Admins" /domain was executed by OFFSEC\helpdesk-svc, which indicates enumeration of privileged domain group membership. This type of domain administrator discovery is commonly associated with reconnaissance activity during an attack.

### Artifact (1514 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon"/>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2025-09-22 11:05:00"/>
    <Computer>win10-it01.offsec.lan</Computer>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2025-09-22 11:05:00</Data>
    <Data Name="ProcessGuid">{1234aabb-e3137-aabb-cccc-000000930103}</Data>
    <Data Name="ProcessId">6103</Data>
    <Data Name="Image">C:\Windows\System32\net.exe</Data>
    <Data Name="FileVersion">10.0.19041.5072</Data>
    <Data Name="Description">Net Command</Data>
    <Data Name="Product">Microsoft Windows Operating System</Data>
    <Data Name="Company">Microsoft Corporation</Data>
    <Data Name="OriginalFileName">net.exe</Data>
    <Data Name="CommandLine">net.exe group "Domain Admins" /domain</Data>
    <Data Name="CurrentDirectory">C:\Windows\system32\</Data>
    <Data Name="User">OFFSEC\helpdesk-svc</Data>
    <Data Name="LogonGuid">{1234aabb-0000-0000-0000-000000000000}</Data>
    <Data Name="LogonId">0x3e7</Data>
    <Data Name="TerminalSessionId">3</Data>
    <Data Name="IntegrityLevel">Medium</Data>
    <Data Name="ParentProcessId">1024</Data>
    <Data Name="ParentImage">C:\Windows\System32\cmd.exe</Data>
    <Data Name="ParentCommandLine">"C:\Windows\System32\cmd.exe"</Data>
    <Data Name="ParentUser">OFFSEC\helpdesk-svc</Data>
  </EventData>
</Event>
```

==========================================================================================
## 2. ID1-SYSMON driver unload (FilterManager).evtx
- GT label: **YES**  | difficulty: easy | test_set: A
- GT narrative/keywords: ['sysmon', 'driver unload', 'defense evasion', 'security tool disabled']
- GT malicious_events: ['FilterManager Event 1: SysmonDrv minifilter driver unloaded — Sysmon telemetry disabled (T1562.001 Disable or Modify Tools, blinds the EDR/sensor). Provider Microsoft-Windows-FilterManager records DeviceName=SysmonDrv but does not log who initiated the unload, leaving an unattributed gap in the timeline.']
- opus → **NO** (conf 100.0): This is a Microsoft-Windows-FilterManager Event ID 1 indicating a file system minifilter driver (SysmonDrv) successfully loaded with a final status of 0x0 (success). This is routine system activity associated with the normal loading of the Sysmon driver and contains no indicators of malicious behavior.
- gpt  → **NO** (conf 100.0): The event shows Microsoft-Windows-FilterManager EventID 1 with DeviceName SysmonDrv and FinalStatus 0x0. There are no commands, accounts, processes, registry keys, or other related events indicating attack behavior.

### Artifact (610 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-FilterManager"/>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2024-05-30 13:07:25.2607503"/>
    <Computer>WIN</Computer>
    <Channel>System</Channel>
  </System>
  <EventData>
    <Data Name="FinalStatus">0x0</Data>
    <Data Name="DeviceVersionMajor">0</Data>
    <Data Name="DeviceVersionMinor">0</Data>
    <Data Name="DeviceNameLength">9</Data>
    <Data Name="DeviceName">SysmonDrv</Data>
    <Data Name="DeviceTime">2023-01-20 18:59:19.0000000</Data>
  </EventData>
</Event>
```

==========================================================================================
## 3. ID11-DNS hosts files modified.evtx
- GT label: **YES**  | difficulty: easy | test_set: A
- GT narrative/keywords: ['hosts file', 'dns manipulation', 'data manipulation']
- GT malicious_events: ['Event 11 (Sysmon FileCreate): notepad++.exe wrote C:\\Windows\\System32\\drivers\\etc\\hosts on fs03vuln.offsec.lan — DNS hosts-file modification (T1565.001 Stored Data Manipulation), commonly used to redirect domain lookups to attacker-controlled IPs or to block security/update endpoints']
- opus → **NO** (conf 100.0): This is a Sysmon file-creation event showing Notepad++ writing to the hosts file (C:\Windows\System32\drivers\etc\hosts). While the hosts file can be abused for redirection, editing it with a legitimate text editor like Notepad++ is consistent with routine administrative activity and there is no accompanying malicious content, command, or process chain. Without additional evidence of malicious entries or suspicious behavior, this event appears benign.
- gpt  → **NO** (conf 100.0): The event shows Notepad++ creating or modifying C:\Windows\System32\drivers\etc\hosts on fs03vuln.offsec.lan. Editing the hosts file can be suspicious, but this single event does not show an attack pattern, malicious command, account abuse, or related activity.

### Artifact (790 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon"/>
    <EventID>11</EventID>
    <TimeCreated SystemTime="2021-12-12 12:01:18.8967708"/>
    <Computer>fs03vuln.offsec.lan</Computer>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2021-12-12 12:01:18.896</Data>
    <Data Name="ProcessGuid">a57649d1-e44f-61b5-d88f-850800000000</Data>
    <Data Name="ProcessId">2592</Data>
    <Data Name="Image">C:\Program Files (x86)\Notepad++\notepad++.exe</Data>
    <Data Name="TargetFilename">C:\Windows\System32\drivers\etc\hosts</Data>
    <Data Name="CreationUtcTime">2013-08-22 13:25:43.270</Data>
  </EventData>
</Event>
```

==========================================================================================
## 4. ID11-Exchange transport config modified.evtx
- GT label: **YES**  | difficulty: easy | test_set: A
- GT narrative/keywords: ['exchange', 'transport config', 'mail server persistence']
- GT malicious_events: ['Event 11 (Sysmon FileCreate): notepad++.exe modified `E:\\Exchange2016\\TransportRoles\\Shared\\agents.config` on exchange01.offsec.lan — Exchange transport-agent registration file is a known persistence/intercept vector (Mailbox-server backdoor, T1546 / T1556.x). Editing agents.config can register a malicious DLL into mail flow to read/modify every message processed by the server.']
- opus → **NO** (conf 100.0): This is a Sysmon FileCreate event showing Notepad++ writing to the Exchange transport agents.config file. While editing agents.config can be associated with malicious transport agent persistence on Exchange servers, this single event in isolation shows a legitimate text editor modifying a configuration file with no accompanying privilege escalation, suspicious commands, or network indicators. Without additional context, this appears to be routine administrative activity.
- gpt  → **NO** (conf 100.0): This event shows Notepad++ creating or modifying E:\Exchange2016\TransportRoles\Shared\agents.config on exchange01.offsec.lan. While editing an Exchange configuration file could be sensitive, this single file creation event does not show commands, accounts, network activity, privilege escalation, or a broader malicious pattern in the provided data.

### Artifact (807 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon"/>
    <EventID>11</EventID>
    <TimeCreated SystemTime="2021-06-04 09:30:48.1705788"/>
    <Computer>exchange01.offsec.lan</Computer>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2021-06-04 09:30:48.170</Data>
    <Data Name="ProcessGuid">6d3c60fe-f13d-60b9-22e2-010000001d00</Data>
    <Data Name="ProcessId">19108</Data>
    <Data Name="Image">C:\Program Files (x86)\Notepad++\notepad++.exe</Data>
    <Data Name="TargetFilename">E:\Exchange2016\TransportRoles\Shared\agents.config</Data>
    <Data Name="CreationUtcTime">2021-01-21 10:20:36.244</Data>
  </EventData>
</Event>
```

==========================================================================================
## 5. ID11715-SQL Server started in single mode for psw recovery.evtx
- GT label: **YES**  | difficulty: easy | test_set: A
- GT narrative/keywords: ['sql server', 'single user mode', 'password recovery']
- GT malicious_events: ['Event 17115 (MSSQL$RADAR provider): SQL Server instance `RADAR` on mssql01.offsec.lan started with command-line args `-s "RADAR" -m` — the `-m` flag forces single-user mode, which limits the instance to one connection AND grants any local administrator full sysadmin (sa) privileges, regardless of database security. Combined with T1505.001 SQL Stored Procedures persistence: an attacker with local-admin reboots SQL into single-user mode, connects as the implicit sysadmin, resets the real SA password (or installs a stored procedure for persistence), then restarts normally. The filename misspells the EID as 11715; the actual event is 17115.']
- opus → **NO** (conf 100.0): Event ID 17115 is a routine SQL Server startup informational message showing the named instance "RADAR" starting with standard command-line parameters. There is no evidence of privilege escalation, suspicious commands, or anomalous network activity, indicating benign service startup behavior.
- gpt  → **NO** (conf 100.0): The event shows MSSQL$RADAR logging startup parameters including -s "RADAR" and -m. There are no accounts, processes, registry changes, or additional related events in the provided data to establish an attack pattern.

### Artifact (369 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="MSSQL$RADAR"/>
    <EventID>17115</EventID>
    <TimeCreated SystemTime="2021-02-03 15:18:22.2602859"/>
    <Computer>mssql01.offsec.lan</Computer>
    <Channel>Application</Channel>
  </System>
  <EventData>
    <Data>
	 -s "RADAR"
	 -m</Data>
  </EventData>
</Event>
```

==========================================================================================
## 6. ID13-Defender service configuration disabled.evtx
- GT label: **YES**  | difficulty: easy | test_set: A
- GT narrative/keywords: ['persistence', 'registry', 'service']
- GT malicious_events: ["2 × Event 13 (Sysmon RegistryEvent SetValue): services.exe set HKLM\\System\\CurrentControlSet\\Services\\WdNisDrv\\Start to DWORD 3 (Manual). WdNisDrv is the Windows Defender Network Inspection driver — its default Start value is 2 (Automatic). Reconfiguring it to Manual prevents Defender's network-inspection driver from loading on next boot, blinding the AV's network-traffic analysis (T1562.001 Disable or Modify Tools / T1112 Modify Registry)."]
- opus → **NO** (conf 100.0): The events show services.exe (the legitimate Windows Service Control Manager) setting the Start value of the WdNisDrv service (Windows Defender Network Inspection driver) to 0x00000003 (manual/demand start), which is normal service configuration behavior. There is no privilege escalation, suspicious process, or disabling of security services—setting Start to 3 is a standard, non-malicious operation performed by the legitimate system process.
- gpt  → **NO** (conf 100.0): The events show C:\Windows\system32\services.exe setting the same WdNisDrv service registry Start value twice. There are no commands, accounts, or additional process activity indicating an attack pattern in the provided data.

### Artifact (1640 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon"/>
    <EventID>13</EventID>
    <TimeCreated SystemTime="2022-02-02 22:54:57.0334771"/>
    <Computer>win10-02.offsec.lan</Computer>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="EventType">SetValue</Data>
    <Data Name="UtcTime">2022-02-02 22:54:57.032</Data>
    <Data Name="ProcessGuid">9828da72-b353-61fa-0b00-00000000f000</Data>
    <Data Name="ProcessId">648</Data>
    <Data Name="Image">C:\Windows\system32\services.exe</Data>
    <Data Name="TargetObject">HKLM\System\CurrentControlSet\Services\WdNisDrv\Start</Data>
    <Data Name="Details">DWORD (0x00000003)</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon"/>
    <EventID>13</EventID>
    <TimeCreated SystemTime="2022-02-02 22:54:57.3475261"/>
    <Computer>win10-02.offsec.lan</Computer>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="EventType">SetValue</Data>
    <Data Name="UtcTime">2022-02-02 22:54:57.342</Data>
    <Data Name="ProcessGuid">9828da72-b353-61fa-0b00-00000000f000</Data>
    <Data Name="ProcessId">648</Data>
    <Data Name="Image">C:\Windows\system32\services.exe</Data>
    <Data Name="TargetObject">HKLM\System\CurrentControlSet\Services\WdNisDrv\Start</Data>
    <Data Name="Details">DWORD (0x00000003)</Data>
  </EventData>
</Event>
```

==========================================================================================
## 7. ID4664-symbolic link created.evtx
- GT label: **YES**  | difficulty: easy | test_set: A
- GT narrative/keywords: ['symbolic link', 'persistence', 'file system manipulation']
- GT malicious_events: ['Event 4664 (Symbolic Link Creation): user `Admin` on host WIN created symlink LinkName=`C:\\Users\\Admin\\Downloads\\sysmonconf.xml` → FileName=`C:\\Users\\Admin\\Downloads\\Sysmon\\sysmonconf.xml`. Symlinks of Sysmon-config files are a low-noise sysmon-tampering primitive (T1562.001 Disable or Modify Tools): the attacker can later swap the link target to a sanitized config that omits suspicious rules, bypassing detection without rewriting the actual file. Even single-event symlinks to Sysmon configs are suspicious enough to flag for human review.']
- opus → **NO** (conf 100.0): Event ID 4664 records a hard link creation, here linking a Sysmon configuration file from the Downloads\Sysmon folder to the Downloads folder. This is consistent with routine setup of Sysmon monitoring by an administrator and shows no privilege escalation, suspicious command execution, or network indicators. The activity appears benign and administrative in nature.
- gpt  → **NO** (conf 100.0): The event shows Admin creating a link involving C:\Users\Admin\Downloads\Sysmon\sysmonconf.xml and C:\Users\Admin\Downloads\sysmonconf.xml. There are no processes, commands, network indicators, registry keys, or additional related events showing malicious behavior.

### Artifact (788 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4664</EventID>
    <TimeCreated SystemTime="2023-03-03 14:35:35.2478251"/>
    <Computer>WIN</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-113448046-927799223-410490820-1001</Data>
    <Data Name="SubjectUserName">Admin</Data>
    <Data Name="SubjectDomainName">WIN</Data>
    <Data Name="SubjectLogonId">0x79B70</Data>
    <Data Name="FileName">C:\Users\Admin\Downloads\Sysmon\sysmonconf.xml</Data>
    <Data Name="LinkName">C:\Users\Admin\Downloads\sysmonconf.xml</Data>
    <Data Name="TransactionId">00000000-0000-0000-0000-000000000000</Data>
  </EventData>
</Event>
```

==========================================================================================
## 8. ID4673-Privilege SeMachineAccountPrivilege called.evtx
- GT label: **YES**  | difficulty: easy | test_set: A
- GT narrative/keywords: ['privilege']
- GT malicious_events: ["Event 4673 (Sensitive Privilege Use): `hack1` invoked `SeMachineAccountPrivilege` via lsass.exe. SeMachineAccountPrivilege grants the right to add COMPUTER ACCOUNTS to the domain (default for any authenticated user up to ms-DS-MachineAccountQuota = 10). Use of this privilege is the preliminary step for T1136.002 Domain Account creation in CVE-2021-42278 / CVE-2021-42287 (sAMAccountName spoofing → noPac) chains: attacker creates a computer account → renames it to a DC's hostname → the resulting Kerberos PAC grants DA-equivalent rights."]
- opus → **NO** (conf 100.0): This single Event ID 4673 records a privileged service operation using SeMachineAccountPrivilege via lsass.exe, which is normal for account/machine management through the Security Account Manager. In isolation there is no escalation chain, suspicious command, or paired state change indicating attack behavior, so this event alone is routine activity.
- gpt  → **NO** (conf 100.0): The event shows account hack1 using SeMachineAccountPrivilege through C:\Windows\System32\lsass.exe against the Security Account Manager. In isolation, there are no commands, registry changes, network connections, or related follow-on events showing account creation or privilege escalation, so the log does not prove malicious activity by itself.

### Artifact (874 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4673</EventID>
    <TimeCreated SystemTime="2021-12-14 14:42:48.7423696"/>
    <Computer>rootdc1.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-4230534742-2542757381-3142984815-1234</Data>
    <Data Name="SubjectUserName">hack1</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x308FB82AD</Data>
    <Data Name="ObjectServer">Security Account Manager</Data>
    <Data Name="Service">Security Account Manager</Data>
    <Data Name="PrivilegeList">SeMachineAccountPrivilege</Data>
    <Data Name="ProcessId">0x254</Data>
    <Data Name="ProcessName">C:\Windows\System32\lsass.exe</Data>
  </EventData>
</Event>
```

==========================================================================================
## 9. ID4688-Linux Subsystem installation (WSL).evtx
- GT label: **YES**  | difficulty: easy | test_set: A
- GT narrative/keywords: ['wsl', 'linux subsystem', 'defense evasion', 'dism']
- GT malicious_events: ["Event 4688: PowerShell parent → `Dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart` followed by `/featurename:VirtualMachinePlatform` — admmig enables WSL2 prerequisites on a Windows 10 client. T1564 Hide Artifacts: a WSL distro is a fully Linux-syscall environment that runs payloads outside Sysmon/AV's process tree, evading host-EDR telemetry that only watches Windows API calls.", 'Event 4688: `wsl.exe --set-default-version 2` confirms the WSL2 (lightweight VM) target — WSL2 in particular is preferred by attackers because the Linux processes live inside a separate virtualised kernel and are nearly invisible to Windows-side monitoring.']
- opus → **NO** (conf 100.0): The events show a standard Windows Subsystem for Linux (WSL2) installation sequence: enabling the Microsoft-Windows-Subsystem-Linux and VirtualMachinePlatform features via Dism.exe and setting the default WSL version to 2. All processes run from legitimate system paths with expected parent-child relationships (PowerShell→Dism→DismHost, services→TrustedInstaller, svchost→TiWorker), consistent with routine servicing operations by an admin account. No suspicious commands, network indicators, or ano
- gpt  → **NO** (conf 100.0): The events show admmig using Dism.exe from powershell.exe to enable Microsoft-Windows-Subsystem-Linux and VirtualMachinePlatform, followed by wsl.exe setting the default version to 2. The related TrustedInstaller.exe, TiWorker.exe, DismHost.exe, taskhostw.exe, and dllhost.exe executions are consistent with Windows feature servicing activity shown in the logs, with no network connection, registry modification, or explicit malicious command present.

### Artifact (11177 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2021-02-08 13:00:32.2083443"/>
    <Computer>WIN10-client01.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-4230534742-2542757381-3142984815-1111</Data>
    <Data Name="SubjectUserName">admmig</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x13F0B8</Data>
    <Data Name="NewProcessId">0x23F0</Data>
    <Data Name="NewProcessName">C:\Windows\System32\Dism.exe</Data>
    <Data Name="TokenElevationType">%%1937</Data>
    <Data Name="ProcessId">0x1DF4</Data>
    <Data Name="CommandLine">"C:\WINDOWS\system32\Dism.exe" /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart</Data>
    <Data Name="TargetUserSid">S-1-0-0</Data>
    <Data Name="TargetUserName">-</Data>
    <Data Name="TargetDomainName">-</Data>
    <Data Name="TargetLogonId">0x0</Data>
    <Data Name="ParentProcessName">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="MandatoryLabel">S-1-16-12288</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2021-02-08 13:00:32.7834106"/>
    <Computer>WIN10-client01.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-4230534742-2542757381-3142984815-1111</Data>
    <Data Name="SubjectUserName">admmig</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x13F0B8</Data>
    <Data Name="NewProcessId">0x738</Data>
    <Data Name="NewProcessName">C:\Users\admmig\AppData\Local\Temp\EF2EDF0A-3F72-4E1D-A537-087B0AA53178\DismHost.exe</Data>
    <Data Name="TokenElevationType">%%1937</Data>
    <Data Name="ProcessId">0x23F0</Data>
    <Data Name="CommandLine">C:\Users\admmig\AppData\Local\Temp\EF2EDF0A-3F72-4E1D-A537-087B0AA53178\dismhost.exe {F4C84A6D-0631-443F-B849-03CA53B4AE35}</Data>
    <Data Name="TargetUserSid">S-1-0-0</Data>
    <Data Name="TargetUserName">-</Data>
    <Data Name="TargetDomainName">-</Data>
    <Data Name="TargetLogonId">0x0</Data>
    <Data Name="ParentProcessName">C:\Windows\System32\Dism.exe</Data>
    <Data Name="MandatoryLabel">S-1-16-12288</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2021-02-08 13:00:33.2173445"/>
    <Computer>WIN10-client01.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">WIN10-CLIENT01$</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x3E7</Data>
    <Data Name="NewProcessId">0x2394</Data>
    <Data Name="NewProcessName">C:\Windows\servicing\TrustedInstaller.exe</Data>
    <Data Name="TokenElevationType">%%1936</Data>
    <Data Name="ProcessId">0x2AC</Data>
    <Data Name="CommandLine">C:\WINDOWS\servicing\TrustedInstaller.exe</Data>
    <Data Name="TargetUserSid">S-1-0-0</Data>
    <Data Name="TargetUserName">-</Data>
    <Da
...[+7677 chars truncated]
```

==========================================================================================
## 10. ID4688-sqlcmd tool abuse in SQL Server.evtx
- GT label: **YES**  | difficulty: easy | test_set: A
- GT narrative/keywords: ['cmd']
- GT malicious_events: ['Event 4688: `sqlcmd -S .\\RADAR,2020` — Microsoft-signed SQLCMD.EXE used to connect to a local SQL Server named instance `RADAR` on TCP port 2020. T1505.001 SQL Stored Procedures + T1059.003 Command Shell: sqlcmd is the legitimate CLI for issuing T-SQL, but in attacker hands it is the delivery vehicle for `EXEC xp_cmdshell` (RCE), `OPENROWSET BULK INSERT` (file read), and SQL-side credential dumping (`SELECT * FROM master.sys.sql_logins`).', 'The non-default port (2020 instead of 1433) and the use of Windows authentication via the local sqlcmd LOLBin together avoid SQL audit-log signatures that look for remote 1433 traffic.', 'Companion to the single-user-mode file (`SQL Server started in single mode for psw recovery`) — sqlcmd is the typical follow-on tool used to pull/reset hashes once the instance is restarted with /m.']
- opus → **NO** (conf 100.0): This event shows the account admmig launching SQLCMD.EXE from cmd.exe to connect to a local SQL Server instance (.\RADAR on port 2020), which is consistent with routine database administration activity. There is no evidence of privilege escalation chains, suspicious network connections, or malicious command patterns in this single event.
- gpt  → **NO** (conf 100.0): This event shows admmig launching SQLCMD.EXE from cmd.exe to connect to a local SQL Server instance. There is no additional event context showing abuse, escalation, persistence, or suspicious follow-on activity, so this isolated process creation appears routine.

### Artifact (1189 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2021-02-03 15:33:16.1076519"/>
    <Computer>mssql01.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-4230534742-2542757381-3142984815-1111</Data>
    <Data Name="SubjectUserName">admmig</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x372A4</Data>
    <Data Name="NewProcessId">0x1204</Data>
    <Data Name="NewProcessName">C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\110\Tools\Binn\SQLCMD.EXE</Data>
    <Data Name="TokenElevationType">%%1937</Data>
    <Data Name="ProcessId">0x9E4</Data>
    <Data Name="CommandLine">sqlcmd  -S .\RADAR,2020</Data>
    <Data Name="TargetUserSid">S-1-0-0</Data>
    <Data Name="TargetUserName">-</Data>
    <Data Name="TargetDomainName">-</Data>
    <Data Name="TargetLogonId">0x0</Data>
    <Data Name="ParentProcessName">C:\Windows\System32\cmd.exe</Data>
    <Data Name="MandatoryLabel">S-1-16-12288</Data>
  </EventData>
</Event>
```

==========================================================================================
## 11. ID4728-Member adding to a group by the same account.evtx
- GT label: **YES**  | difficulty: easy | test_set: A
- GT narrative/keywords: ['self-enrollment', 'group membership', 'account manipulation']
- GT malicious_events: ['Event 4728 (member added to security-enabled global group): lambda-user (the SUBJECT) adds `CN=lambda-user,...` (THEMSELF as TargetUser) to `Group02`. T1098 Account Manipulation: SELF-ENROLLMENT — the subject and the target are the same account.', 'Self-enrollment requires WriteDACL/GenericAll/GenericWrite on the target group object — meaning lambda-user (or an attacker who compromised it) holds an over-privileged ACE on Group02 that should not exist for a regular user. AD ACL audit + BloodHound `MembershipOf` edge findings flag exactly this.', 'Pattern is the textbook BloodHound-driven privilege-escalation primitive: enumerate `OutboundACL` paths with `WriteDACL/GenericAll on Group`, then self-add to climb. The 4728 with subject==target is the smoking gun.', 'lambda-user subject — canary trip; this canary should never authenticate, so the 4728 itself is a detection.']
- opus → **NO** (conf 100.0): This single Event ID 4728 records a member (lambda-user) being added to a global security group (Group02), which is a routine Active Directory administration action. There is no privilege escalation chain, paired state changes, or sequential suspicious commands evident from this isolated event. Without additional context indicating unauthorized escalation, this appears to be benign group membership management.
- gpt  → **NO** (conf 100.0): The event shows lambda-user was added to Group02 by lambda-user. Based only on the provided data, there is no process, command, registry, or network activity indicating attack behavior, and Group02 is not identified as a privileged group in the log.

### Artifact (982 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4728</EventID>
    <TimeCreated SystemTime="2020-07-12 05:17:23.1073923"/>
    <Computer>rootdc1.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="MemberName">CN=lambda-user,OU=Test-OU,OU=OFFSEC-COMPANY,DC=offsec,DC=lan</Data>
    <Data Name="MemberSid">S-1-5-21-4230534742-2542757381-3142984815-1158</Data>
    <Data Name="TargetUserName">Group02</Data>
    <Data Name="TargetDomainName">OFFSEC</Data>
    <Data Name="TargetSid">S-1-5-21-4230534742-2542757381-3142984815-1135</Data>
    <Data Name="SubjectUserSid">S-1-5-21-4230534742-2542757381-3142984815-1158</Data>
    <Data Name="SubjectUserName">lambda-user</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x807AFCB</Data>
    <Data Name="PrivilegeList">-</Data>
  </EventData>
</Event>
```

==========================================================================================
## 12. ID4739-Domain policy changed by non system account.evtx
- GT label: **YES**  | difficulty: easy | test_set: A
- GT narrative/keywords: ['domain policy', 'policy change', 'defense evasion']
- GT malicious_events: ['Event 4739 (Domain policy was changed): admmig modifies the DOMAIN-WIDE password / lockout / Kerberos policy. T1484 Domain Policy Modification.', '4739 fires on changes to the default domain GPO (Default Domain Policy) attributes that govern: minPwdLength, maxPwdAge, lockoutThreshold, lockoutDuration, lockoutObservationWindow, ticket lifetimes — the foundational password / lockout / Kerberos parameters for the entire domain.', 'Anomaly is in the SUBJECT: domain policy changes should be performed by a SYSTEM context (group policy update via DCs themselves) or by Domain Admins via the dedicated GPO management surface, not by a regular interactive user. admmig as the 4739 subject is the IoC — it indicates a manual/scripted domain-wide policy weakening, not an automated GPO replication tick.', 'Common abuses: lower minPwdLength (enable weak passwords for spraying), raise lockoutThreshold (enable extended spray windows), shorten Kerberos ticket lifetimes (force frequent re-auth → harvest more 4768s with hashes), enable ENCRYPTED_TEXT_PWD_ALLOWED at the domain default level.']
- opus → **NO** (conf 100.0): Event 4739 indicates a domain policy change on rootdc1.offsec.lan performed by the account admmig, which appears to be an administrative/migration account. With no actual policy field values changed (all fields show "-") and no accompanying privilege escalation or suspicious process chain, this is consistent with routine administrative domain policy management. There is insufficient evidence of malicious intent in isolation.
- gpt  → **NO** (conf 100.0): The event shows a domain policy change event by admmig, but the specific policy fields are "-" and there are no commands, processes, registry changes, or network activity beyond the computer hostname. With only this single event and no paired or escalating activity shown, it is not sufficient to identify attack behavior.

### Artifact (1359 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4739</EventID>
    <TimeCreated SystemTime="2020-08-02 11:04:58.0745235"/>
    <Computer>rootdc1.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="DomainPolicyChanged">-</Data>
    <Data Name="DomainName">OFFSEC</Data>
    <Data Name="DomainSid">S-1-5-21-4230534742-2542757381-3142984815</Data>
    <Data Name="SubjectUserSid">S-1-5-21-4230534742-2542757381-3142984815-1111</Data>
    <Data Name="SubjectUserName">admmig</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x11AE95BF</Data>
    <Data Name="PrivilegeList">-</Data>
    <Data Name="MinPasswordAge">-</Data>
    <Data Name="MaxPasswordAge">-</Data>
    <Data Name="ForceLogoff">-</Data>
    <Data Name="LockoutThreshold">-</Data>
    <Data Name="LockoutObservationWindow">-</Data>
    <Data Name="LockoutDuration">-</Data>
    <Data Name="PasswordProperties">-</Data>
    <Data Name="MinPasswordLength">-</Data>
    <Data Name="PasswordHistoryLength">-</Data>
    <Data Name="MachineAccountQuota">-</Data>
    <Data Name="MixedDomainMode">-</Data>
    <Data Name="DomainBehaviorVersion">-</Data>
    <Data Name="OemInformation">-</Data>
  </EventData>
</Event>
```

==========================================================================================
## 13. ID4768-4769-Kerberos host ticket without a trailing $.evtx
- GT label: **YES**  | difficulty: easy | test_set: A
- GT narrative/keywords: ['kerberos', 'missing dollar sign', 'anomalous ticket']
- GT malicious_events: ['Event 4768 (TGT issued) + Event 4769 (TGS issued) for TargetUserName=`rootdc1` (NO trailing `$`) at ::ffff:10.23.123.11 — but ROOTDC1 is a domain-controller computer account, whose canonical SAM name MUST end in `$` (machine-account naming convention). Tickets with TargetUserName=`rootdc1` (sans $) cannot match the SAM record under normal conditions.', 'T1558 Steal or Forge Kerberos Tickets + CVE-2021-42278/42287 (noPac / sAMAccountName spoofing): the attacker temporarily renamed the machine account to lose its trailing `$`, then requested a TGT — the KDC issues the TGT under the renamed identity, and at follow-on TGS-REQ time the resulting service ticket carries DC-equivalent privileges because the PAC was minted against a DC machine account.', 'After the ticket is harvested the attacker renames the account BACK to `rootdc1$` to scrub the noPac evidence. The single-letter-of-difference between TargetUserName=`rootdc1` (4768) and the actual machine name is the IoC.', 'Companion to file `ID4781-Computer account renamed without a trailing $ (CVE-2021-42278).evtx`: that one captures the SAM rename event; this one captures the TGT/TGS issuance under the renamed name.']
- opus → **NO** (conf 100.0): These events show a standard Kerberos TGT request (4768) followed by a service ticket request (4769) for the domain controller's own machine account (ROOTDC1$), both with Status 0x0 (success) and strong AES encryption (0x12). The TGT was issued with normal pre-authentication (PreAuthType 2) and the activity originates from a consistent internal IP, which is consistent with routine domain authentication rather than an attack.
- gpt  → **NO** (conf 100.0): These events show successful Kerberos ticket activity, with Event ID 4768 for a TGT request and Event ID 4769 for a service ticket request. The limited evidence provided does not show commands, processes, registry changes, failures, or privilege escalation activity indicating malicious behavior.

### Artifact (1972 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4768</EventID>
    <TimeCreated SystemTime="2021-12-14 14:42:49.2221348"/>
    <Computer>rootdc1.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="TargetUserName">rootdc1</Data>
    <Data Name="TargetDomainName">OFFSEC</Data>
    <Data Name="TargetSid">S-1-5-21-4230534742-2542757381-3142984815-1296</Data>
    <Data Name="ServiceName">krbtgt</Data>
    <Data Name="ServiceSid">S-1-5-21-4230534742-2542757381-3142984815-502</Data>
    <Data Name="TicketOptions">0x50800000</Data>
    <Data Name="Status">0x0</Data>
    <Data Name="TicketEncryptionType">0x12</Data>
    <Data Name="PreAuthType">2</Data>
    <Data Name="IpAddress">::ffff:10.23.123.11</Data>
    <Data Name="IpPort">50268</Data>
    <Data Name="CertIssuerName"></Data>
    <Data Name="CertSerialNumber"></Data>
    <Data Name="CertThumbprint"></Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4769</EventID>
    <TimeCreated SystemTime="2021-12-14 14:42:49.2558815"/>
    <Computer>rootdc1.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="TargetUserName">rootdc1@OFFSEC.LAN</Data>
    <Data Name="TargetDomainName">OFFSEC.LAN</Data>
    <Data Name="ServiceName">ROOTDC1$</Data>
    <Data Name="ServiceSid">S-1-5-21-4230534742-2542757381-3142984815-1000</Data>
    <Data Name="TicketOptions">0x40810000</Data>
    <Data Name="TicketEncryptionType">0x12</Data>
    <Data Name="IpAddress">::ffff:10.23.123.11</Data>
    <Data Name="IpPort">50270</Data>
    <Data Name="Status">0x0</Data>
    <Data Name="LogonGuid">3fb7fcca-2be3-5ac1-1916-9c0c075cbc8a</Data>
    <Data Name="TransmittedServices">-</Data>
  </EventData>
</Event>
```

==========================================================================================
## 14. ID4908-Special group table changed.evtx
- GT label: **YES**  | difficulty: easy | test_set: A
- GT narrative/keywords: ['special groups', 'audit configuration', 'defense evasion']
- GT malicious_events: ["Event 4908 (×4): the 'Special Groups' login table is modified. T1562.002 Disable Windows Event Logging — but inverted: the Special Groups table controls which groups trigger 4964 'A new logon by a member of a special group' alerts. By manipulating this table the attacker either: (a) REMOVES sensitive groups (Domain Admins, Enterprise Admins) from the watchlist so subsequent admin logons don't alert; or (b) ADDS noise groups so the alert volume drowns out attention.", 'Stored under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Audit\\SpecialGroups as a SDDL string. Direct registry edits trigger 4908.', '4 successive 4908 events suggest scripted manipulation — manual policy-edit by a real admin via Group Policy Editor would result in 1-2 events; automated tools (or programmatic registry writes) generate one per group SID change.', 'Companion to file `ID4964-Login of a member of a special group.evtx`: 4964 is the alert that the modified 4908 table either suppresses or triggers.']
- opus → **NO** (conf 100.0): Event ID 4908 records updates to the Special Groups auditing table on the domain controller, which is a normal administrative/system configuration activity. The events only show SID list changes with no privilege escalation, suspicious processes, or network activity. The incremental addition of SIDs to the special groups list is consistent with routine audit policy configuration rather than malicious behavior.
- gpt  → **NO** (conf 100.0): The logs only show repeated EventID 4908 entries on rootdc1.offsec.lan with SidList changing from "-" to lists of SIDs. There are no processes, accounts, commands, registry keys, or remote network indicators in the provided data to support attack behavior.

### Artifact (1807 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4908</EventID>
    <TimeCreated SystemTime="2020-07-12 06:01:51.7980272"/>
    <Computer>rootdc1.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SidList">-</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4908</EventID>
    <TimeCreated SystemTime="2020-07-12 06:01:51.8077032"/>
    <Computer>rootdc1.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SidList">, %{S-1-5-21-4230534742-2542757381-3142984815-1613}, %{S-1-5-21-4230534742-2542757381-3142984815-1614}</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4908</EventID>
    <TimeCreated SystemTime="2020-07-12 06:06:52.4486853"/>
    <Computer>rootdc1.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SidList">-</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4908</EventID>
    <TimeCreated SystemTime="2020-07-12 06:06:52.4583164"/>
    <Computer>rootdc1.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SidList">, %{S-1-5-21-4230534742-2542757381-3142984815-1613}, %{S-1-5-21-4230534742-2542757381-3142984815-1614}, %{S-1-5-21-4230534742-2542757381-3142984815-1615}</Data>
  </EventData>
</Event>
```

==========================================================================================
## 15. ID5124-OCSP security settings changed.evtx
- GT label: **YES**  | difficulty: easy | test_set: A
- GT narrative/keywords: ['ocsp', 'certificate services', 'pki', 'security settings modification']
- GT malicious_events: ['Event 5124 (a security setting was updated on the OCSP Responder Service): admmig modifies the OCSP responder configuration. T1556 / T1485 PKI tampering — modifying OCSP affects how revocation is checked across the forest.', 'Event 5120 (OCSP service started) + 5121 (OCSP service stopped): the responder was bounced — typical of an apply-config-change cycle after writing new settings.', 'Event 5123 (security setting changed on a registry-stored CA setting): companion event recording the underlying registry write that drove the 5124.', "Why OCSP matters in attack chains: if attackers issue a rogue certificate via ESC1-ESC8 ADCS abuse, modifying the OCSP responder so it returns 'good' for the rogue cert (or stops responding so revocation falls back to CRL caching) keeps the rogue cert valid even after defenders identify and try to revoke it. T1485 Data Destruction-adjacent attack on the trust infrastructure.", 'Companion to file `ID4885,4876,4877,5123,5124-ADCS PKI OCSP.evtx`: that file captures the broader ADCS+OCSP change set; this entry isolates the OCSP-specific 5124 + 5123 + 5120/5121 service-cycle slice.']
- opus → **NO** (conf 100.0): These events reflect routine Certificate Services/OCSP configuration activity on a PKI server (pki01.offsec.lan), including changes to cache entries, thread count, audit filters, and security settings performed by an administrative account (admmig). The property and security-setting changes (e.g., OCSP Administrator and Requestor permissions) are consistent with normal Online Responder administration rather than malicious tampering.
- gpt  → **NO** (conf 100.0): The events show configuration and security setting changes on pki01.offsec.lan by admmig, including MaxNumOfCacheEntries, NumOfThreads, AuditFilter, and NewSecuritySettings. The pattern reflects administrative changes to auditing and OCSP-related permissions, with no commands, processes, registry modifications, or suspicious network indicators present in the logs.

### Artifact (4163 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>5121</EventID>
    <TimeCreated SystemTime="2020-07-11 09:20:43.4013780"/>
    <Computer>pki01.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>5120</EventID>
    <TimeCreated SystemTime="2020-07-11 09:20:46.1583762"/>
    <Computer>pki01.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>5123</EventID>
    <TimeCreated SystemTime="2020-07-11 09:21:24.7029584"/>
    <Computer>pki01.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="PropertyName">MaxNumOfCacheEntries</Data>
    <Data Name="NewValue">5000</Data>
    <Data Name="SubjectUserSid">S-1-5-21-4230534742-2542757381-3142984815-1111</Data>
    <Data Name="SubjectUserName">admmig</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x477AC56</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>5123</EventID>
    <TimeCreated SystemTime="2020-07-11 09:21:24.7030739"/>
    <Computer>pki01.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="PropertyName">NumOfThreads</Data>
    <Data Name="NewValue">60</Data>
    <Data Name="SubjectUserSid">S-1-5-21-4230534742-2542757381-3142984815-1111</Data>
    <Data Name="SubjectUserName">admmig</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x477AC56</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>5123</EventID>
    <TimeCreated SystemTime="2020-07-11 09:21:24.7079491"/>
    <Computer>pki01.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="PropertyName">AuditFilter</Data>
    <Data Name="NewValue">11</Data>
    <Data Name="SubjectUserSid">S-1-5-21-4230534742-2542757381-3142984815-1111</Data>
    <Data Name="SubjectUserName">admmig</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x477AC56</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>5123</EventID>
    <TimeCreated SystemTime="2020-07-11 09:21:50.0878677"/>
    <Computer>pki01.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="PropertyName">AuditFilter</Data>
    <Data Name="NewValue">15</Data>
    <Data Name="SubjectUserSid">S-1-5-21-4230534742-2542757381-3142984815-1111</Data>
    <Data Name="SubjectUserName">admmig</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x477AC56</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Micro
...[+663 chars truncated]
```

==========================================================================================
## 16. ID5137-Fake domain controller registration (DCshadow).evtx
- GT label: **YES**  | difficulty: easy | test_set: A
- GT narrative/keywords: ['shadow']
- GT malicious_events: ['Event 5137 (Directory Service Object created): admmig creates a Server object `CN=JUMP01,CN=Servers,CN=OFFSEC-PREMISE,CN=Sites,CN=Configuration,DC=offsec,DC=lan`. T1207 Rogue Domain Controller (DCShadow): registering JUMP01 as a Server in the Configuration partition is one of the prerequisite steps for declaring a host as a replication endpoint.', 'DCShadow chain: (1) register Server object in CN=Sites (THIS event), (2) add NTDS Settings child object that lists JUMP01 as a replication-capable DC, (3) set the DC SPNs (`GC/...` + `E3514235-... DRSUAPI`) on JUMP01$ — file 190 / `ID4742-SPN set on computer account (DCshadow).evtx`, (4) push attribute changes via DRSUAPI replication that legitimate DCs accept and apply.', 'Once steps 1-3 are complete, the rogue DC can write any AD attribute and the change is persisted forest-wide because legitimate DCs trust the replication-source signature. Mimikatz `lsadump::dcshadow /push` automates the full chain. (Mimikatz subcommand syntax — analyst shorthand for the technique; not literally logged).', 'Companion to file 91 (4662 DCsync), file 93 (4662 sensitive attribs DCshadow), file 190 (4742 SPN set DCshadow). The 5137 here is the very FIRST step of the chain — the Server object plant.']
- opus → **NO** (conf 100.0): Event ID 5137 indicates a directory service object was created (a server object CN=JUMP01 under the Configuration/Sites partition) by account admmig. This is consistent with routine Active Directory administration or site/server configuration, with no privilege escalation, suspicious process, or attack chain evident in the single event.
- gpt  → **NO** (conf 100.0): Event 5137 records creation of a directory service object, specifically a server object for CN=JUMP01 under the Configuration naming context. With only this single object creation by admmig and no commands, processes, registry changes, or related events showing abuse, the activity cannot be identified as malicious from the provided data.

### Artifact (1014 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>5137</EventID>
    <TimeCreated SystemTime="2021-03-26 20:41:48.2464912"/>
    <Computer>rootdc1.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="OpCorrelationID">4dea43cc-2e4b-41d8-842e-b4052ed0839e</Data>
    <Data Name="AppCorrelationID">-</Data>
    <Data Name="SubjectUserSid">S-1-5-21-4230534742-2542757381-3142984815-1111</Data>
    <Data Name="SubjectUserName">admmig</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x882D87</Data>
    <Data Name="DSName">offsec.lan</Data>
    <Data Name="DSType">%%14676</Data>
    <Data Name="ObjectDN">CN=JUMP01,CN=Servers,CN=OFFSEC-PREMISE,CN=Sites,CN=Configuration,DC=offsec,DC=lan</Data>
    <Data Name="ObjectGUID">2cb2fa54-a21a-4e2f-b7af-a82a56d9d690</Data>
    <Data Name="ObjectClass">server</Data>
  </EventData>
</Event>
```

==========================================================================================
## 17. ID60-High volume file downloaded with BITS.evtx
- GT label: **YES**  | difficulty: easy | test_set: A
- GT narrative/keywords: ['bits', 'file download', 'high volume', 'ingress tool transfer']
- GT malicious_events: ['Event 3 (BITS-Client: job created) + Event 59/60 (file transfer in progress / completed) + Event 5 (BITS error or job state change): admmig drives a high-volume BITS download. T1197 BITS Jobs: BITS is a Windows-managed download service that runs in the SYSTEM context, retries on network failure, and bypasses per-user HTTP proxy / EDR coverage that only watches user-context HTTP.', 'High-volume / multi-MB BITS transfers from a single user session are an IoC because legitimate BITS use (Windows Update, Defender update, Office Click-to-Run) runs as SYSTEM (subject `NT AUTHORITY\\SYSTEM`), not as `OFFSEC\\admmig`. A user-driven multi-MB BITS job is the canonical T1105 Ingress Tool Transfer fingerprint.', 'Companion to file 114 (`ID4688-BITS transfer initiated.evtx`) which captures the bitsadmin.exe launch + URL — this entry is the BITS-channel internal view of the same transfer (job lifecycle events, retries, completion).']
- opus → **NO** (conf 100.0): These BITS-Client events show an admin account downloading a legitimate Ubuntu desktop ISO from the official releases.ubuntu.com domain, which is normal software distribution activity. The transfer job has a recognized name, a known-good destination URL, and no suspicious process, command, or registry modifications. The pattern is consistent with routine administrative file retrieval rather than malicious payload delivery.
- gpt  → **NO** (conf 100.0): The events show BITS transfer activity by OFFSEC\admmig downloading ubuntu-20.04.3-desktop-amd64.iso from releases.ubuntu.com. There are no commands, processes, registry changes, or other evidence in the logs indicating malicious behavior.

### Artifact (4410 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Bits-Client"/>
    <EventID>3</EventID>
    <TimeCreated SystemTime="2021-10-21 17:52:47.0723122"/>
    <Computer>FS03.offsec.lan</Computer>
    <Channel>Microsoft-Windows-Bits-Client/Operational</Channel>
  </System>
  <EventData>
    <Data Name="string">BITS Transfer</Data>
    <Data Name="string2">OFFSEC\admmig</Data>
    <Data Name="string3"></Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Bits-Client"/>
    <EventID>5</EventID>
    <TimeCreated SystemTime="2021-10-21 17:52:48.5927980"/>
    <Computer>FS03.offsec.lan</Computer>
    <Channel>Microsoft-Windows-Bits-Client/Operational</Channel>
  </System>
  <EventData>
    <Data Name="User">OFFSEC\admmig</Data>
    <Data Name="jobTitle">BITS Transfer</Data>
    <Data Name="jobId">2e340c8c-7f77-401f-90fd-578049749afb</Data>
    <Data Name="jobOwner">OFFSEC\admmig</Data>
    <Data Name="fileCount">1</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Bits-Client"/>
    <EventID>3</EventID>
    <TimeCreated SystemTime="2021-10-21 17:53:36.6438795"/>
    <Computer>FS03.offsec.lan</Computer>
    <Channel>Microsoft-Windows-Bits-Client/Operational</Channel>
  </System>
  <EventData>
    <Data Name="string">BITS Transfer</Data>
    <Data Name="string2">OFFSEC\admmig</Data>
    <Data Name="string3"></Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Bits-Client"/>
    <EventID>59</EventID>
    <TimeCreated SystemTime="2021-10-21 17:53:42.5306620"/>
    <Computer>FS03.offsec.lan</Computer>
    <Channel>Microsoft-Windows-Bits-Client/Operational</Channel>
  </System>
  <EventData>
    <Data Name="transferId">470f04e8-35f7-474f-9d19-3444a2826db1</Data>
    <Data Name="name">BITS Transfer</Data>
    <Data Name="Id">ebfcb3cd-6489-40ef-8eb7-7e0d6b4dd4ff</Data>
    <Data Name="url">https://releases.ubuntu.com/20.04.3/ubuntu-20.04.3-desktop-amd64.iso</Data>
    <Data Name="peer"></Data>
    <Data Name="fileTime">2021-08-19 11:06:00.0000000</Data>
    <Data Name="fileLength">3071934464</Data>
    <Data Name="bytesTotal">3071934464</Data>
    <Data Name="bytesTransferred">0</Data>
    <Data Name="bytesTransferredFromPeer">0</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Bits-Client"/>
    <EventID>60</EventID>
    <TimeCreated SystemTime="2021-10-21 18:05:47.8991737"/>
    <Computer>FS03.offsec.lan</Computer>
    <Channel>Microsoft-Windows-Bits-Client/Operational</Channel>
  </System>
  <EventData>
    <Data Name="transferId">470f04e8-35f7-474f-9d19-3444a2826db1</Data>
    <Data Name="name">BITS Transfer</Data>
    <Data Name="Id">ebfcb3cd-6489-40ef-8eb7-7e0d6b4dd4ff</Data>
    <Data Name="url">https://releases.ubuntu.com/20.04.3/ubuntu-20.04.3-desktop-amd64.iso</Data>
    <Data Name="peer"></Data>
    <Data Name="hr">262152</Data>
    <Data Name="fileTime">2021-08-19 11:06:00.0000000</Data>
    <Data Name="fileLength">3071934464</Data>
    <Data Name="bytesTotal">3071934464</Data>
    <Data Name="bytesTransferred">2497476607</Data>
    <Data Name="proxy"></Data>
    <Data Name="peerProtoc
...[+910 chars truncated]
```

==========================================================================================
## 18. ID600-Active Directory module called by PowerShell.evtx
- GT label: **YES**  | difficulty: easy | test_set: A
- GT narrative/keywords: ['powershell']
- GT malicious_events: ['Event 600 (Windows PowerShell: Provider Lifecycle): the `Microsoft.ActiveDirectory.Management` PowerShell module is loaded — the AD module that exposes Get-ADUser, Get-ADComputer, Get-ADGroup, Get-ADObject, and Set-AD* cmdlets. T1087.002 Account Discovery: Domain Account / T1018 Remote System Discovery / T1069.002 Permission Groups Discovery: Domain Groups.', "The AD PowerShell module is the QUERY-side equivalent of LDAP queries; attackers using it (rather than going direct to BloodHound's SharpHound or Get-DomainUser from PowerView) blend in with legitimate admin tooling because Get-ADUser is a sanctioned Microsoft cmdlet.", 'Event 600 fires once per provider load, so a single 600 from a non-admin user account is the IoC — admins typically have the AD module pre-loaded in their profile, while attackers explicitly Import-Module ActiveDirectory after compromising a non-admin host.', 'Companion to the various ID800-4103-4104-* PowerShell forensics files: those capture the SUBSEQUENT Get-AD* invocations; this 600 captures the module-load setup step.']
- opus → **NO** (conf 100.0): This is a PowerShell provider lifecycle event (EventID 600) recording the ActiveDirectory provider transitioning to a "Started" state, which is routine activity when an AD-related module or cmdlet is loaded. There is no command line, suspicious script, or privilege escalation indicated, making this benign operational logging.
- gpt  → **NO** (conf 100.0): This event shows the ActiveDirectory PowerShell provider starting in ConsoleHost with powershell.exe. There are no command lines, accounts, registry changes, or other related events indicating malicious activity.

### Artifact (788 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="PowerShell"/>
    <EventID>600</EventID>
    <TimeCreated SystemTime="2021-12-07 14:16:03.7328528"/>
    <Computer>jump01.offsec.lan</Computer>
    <Channel>Windows PowerShell</Channel>
  </System>
  <EventData>
    <Data>ActiveDirectory, Started, 	ProviderName=ActiveDirectory
	NewProviderState=Started

	SequenceNumber=21

	HostName=ConsoleHost
	HostVersion=5.1.14393.4350
	HostId=87fd19ae-84b0-48dc-848b-d051141bd7f5
	HostApplication=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
	EngineVersion=5.1.14393.4350
	RunspaceId=50f09969-f55d-4621-a64f-d9391c7bd9fe
	PipelineId=7
	CommandName=
	CommandType=
	ScriptName=
	CommandPath=
	CommandLine=</Data>
  </EventData>
</Event>
```

==========================================================================================
## 19. ID8-Module Virtualization disabled (Credential Guard).evtx
- GT label: **YES**  | difficulty: easy | test_set: A
- GT narrative/keywords: ['credential', 'dump']
- GT malicious_events: ['Event 7/8/9/10 (Microsoft-Windows-DeviceGuard / Microsoft-Windows-Hyper-V-Worker): Hypervisor-protected Code Integrity (HVCI) / Credential Guard / Virtualization-Based Security configuration changed. T1562.001 Disable or Modify Tools (LSA-side hardening downgrade).', "Why VBS / Credential Guard / HVCI matter: when enabled, LSASS runs in Virtual Trust Level 1 (VTL1, the secure kernel), which makes Mimikatz `sekurlsa::logonpasswords` UNABLE to read the cleartext credentials — the secrets are protected by hypervisor-enforced isolation. Disabling VBS/CG returns LSASS to the unprotected normal kernel, restoring Mimikatz's read access.", 'The 32 events in this trace cover the boot-time DeviceGuard configuration check + the per-component disable: HVCI off, CG off, VSM off, MMIO Range Protection off. Combined, the host is fully downgraded to pre-Windows-10-1709 LSA-protection level.', 'Common technique: write `EnableVirtualizationBasedSecurity=0` and `LsaCfgFlags=0` to HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard then reboot. The subsequent boot fires events 7/8/9/10 in the DeviceGuard channel confirming the disable.', 'Detection priority: 32 successive DeviceGuard events on a host that was previously running Credential Guard is a near-zero-FP IoC for explicit defense downgrade preceding LSASS dump.']
- opus → **NO** (conf 100.0): These are Microsoft-Windows-Servicing events on the Setup channel, which record routine Windows Update/component servicing operations (package install, configure, and completion states). The events span months and reflect normal patch/servicing cycles with no processes, accounts, or commands indicating attacker activity. This is benign system maintenance behavior.
- gpt  → **NO** (conf 100.0): The events are from Microsoft-Windows-Servicing in the Setup channel with Event IDs 7, 8, 9, and 10 and contain no process, account, command, registry, or suspicious network activity details. Based only on the provided event data, this appears consistent with routine Windows servicing activity rather than malicious behavior.

### Artifact (11069 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Servicing"/>
    <EventID>8</EventID>
    <TimeCreated SystemTime="2022-04-04 09:34:23.1029271"/>
    <Computer>N900B7FFD.kapsch.co.at</Computer>
    <Channel>Setup</Channel>
  </System>
  <EventData>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Servicing"/>
    <EventID>10</EventID>
    <TimeCreated SystemTime="2022-04-04 09:34:28.5584324"/>
    <Computer>N900B7FFD.kapsch.co.at</Computer>
    <Channel>Setup</Channel>
  </System>
  <EventData>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Servicing"/>
    <EventID>8</EventID>
    <TimeCreated SystemTime="2022-04-12 07:16:31.7217541"/>
    <Computer>N900B7FFD.kapsch.co.at</Computer>
    <Channel>Setup</Channel>
  </System>
  <EventData>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Servicing"/>
    <EventID>8</EventID>
    <TimeCreated SystemTime="2022-04-12 07:16:31.7217818"/>
    <Computer>N900B7FFD.kapsch.co.at</Computer>
    <Channel>Setup</Channel>
  </System>
  <EventData>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Servicing"/>
    <EventID>8</EventID>
    <TimeCreated SystemTime="2022-04-12 07:16:31.7262421"/>
    <Computer>N900B7FFD.kapsch.co.at</Computer>
    <Channel>Setup</Channel>
  </System>
  <EventData>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Servicing"/>
    <EventID>8</EventID>
    <TimeCreated SystemTime="2022-04-12 07:16:31.7262443"/>
    <Computer>N900B7FFD.kapsch.co.at</Computer>
    <Channel>Setup</Channel>
  </System>
  <EventData>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Servicing"/>
    <EventID>8</EventID>
    <TimeCreated SystemTime="2022-04-12 07:16:31.7263444"/>
    <Computer>N900B7FFD.kapsch.co.at</Computer>
    <Channel>Setup</Channel>
  </System>
  <EventData>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Servicing"/>
    <EventID>8</EventID>
    <TimeCreated SystemTime="2022-04-12 07:16:31.7264444"/>
    <Computer>N900B7FFD.kapsch.co.at</Computer>
    <Channel>Setup</Channel>
  </System>
  <EventData>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Servicing"/>
    <EventID>8</EventID>
    <TimeCreated SystemTime="2022-04-12 07:16:31.7264648"/>
    <Computer>N900B7FFD.kapsch.co.at</Computer>
    <Channel>Setup</Channel>
  </System>
  <EventData>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Servicing"/>
    <EventID>8</EventID>
    <TimeCreated SystemTime="2022-04-12 07:16:31.7264855"/>
    <Computer>N900B7FFD.kapsch.co.at</Computer>
    <Channel>Setup</Channel>
  </System>
  <EventData>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/20
...[+7569 chars truncated]
```

==========================================================================================
## 20. ID800-4103-4104-Local group discovery via PowerShell.evtx.evtx
- GT label: **YES**  | difficulty: easy | test_set: A
- GT narrative/keywords: ['powershell']
- GT malicious_events: ['Event 4104 (ScriptBlock logging): Get-LocalGroup / Get-LocalGroupMember pipeline enumerating LOCAL groups (Administrators, Backup Operators, Power Users, etc.) on the host. T1069.001 Permission Groups Discovery: Local Groups.', 'Companion to the domain-group-discovery file: this one targets the LOCAL SAM (visible to every interactive user with SeChangeNotifyPrivilege), the domain version targets AD. Attackers run BOTH because membership is independent (a user in local Administrators may not be in any domain group).', 'Get-LocalGroup is the modern Microsoft cmdlet; alternative `net localgroup administrators` (4688 LOLBin) is the older path. PS-channel forensics (4104) captures the cmdlet form, 4688 captures net.exe form.']
- opus → **NO** (conf 100.0): An administrative account (OFFSEC\admmig) on a jump host ran Get-LocalGroupMember to enumerate the local Administrators group, with the remaining events being normal PSReadLine/prompt internals (Set-StrictMode, PSConsoleHostReadline). While local admin enumeration can be reconnaissance, this single benign cmdlet executed by an admin account in an interactive console with no escalation, persistence, or external network activity is consistent with routine administration. No malicious tooling, enco
- gpt  → **NO** (conf 100.0): The logs show OFFSEC\admmig using PowerShell to run Get-LocalGroupMember -Name Administrators and display the local Administrators group membership. This is administrative enumeration and no additional malicious actions, persistence, credential access, or execution beyond normal PowerShell/PSReadline activity are shown in the provided events.

### Artifact (10306 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="PowerShell"/>
    <EventID>800</EventID>
    <TimeCreated SystemTime="2021-10-31 14:28:15.3297256"/>
    <Computer>jump01.offsec.lan</Computer>
    <Channel>Windows PowerShell</Channel>
  </System>
  <EventData>
    <Data>	DetailSequence=1
	DetailTotal=1

	SequenceNumber=301

	UserId=OFFSEC\admmig
	HostName=ConsoleHost
	HostVersion=5.1.14393.4350
	HostId=32afa6ab-c13e-4c81-91ed-8488f7e303ea
	HostApplication=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
	EngineVersion=5.1.14393.4350
	RunspaceId=be9cbd71-6464-43fd-94f7-af1594871f07
	PipelineId=68
	ScriptName=
	CommandLine=, CommandInvocation(PSConsoleHostReadline): "PSConsoleHostReadline"
</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PowerShell"/>
    <EventID>4103</EventID>
    <TimeCreated SystemTime="2021-10-31 14:28:15.3307517"/>
    <Computer>jump01.offsec.lan</Computer>
    <Channel>Microsoft-Windows-PowerShell/Operational</Channel>
  </System>
  <EventData>
    <Data Name="ContextInfo">        Severity = Informational,         Host Name = ConsoleHost,         Host Version = 5.1.14393.4350,         Host ID = 32afa6ab-c13e-4c81-91ed-8488f7e303ea,         Host Application = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe,         Engine Version = 5.1.14393.4350,         Runspace ID = be9cbd71-6464-43fd-94f7-af1594871f07,         Pipeline ID = 68,         Command Name = PSConsoleHostReadline,         Command Type = Function,         Script Name = ,         Command Path = ,         Sequence Number = 302,         User = OFFSEC\admmig,         Connected User = ,         Shell ID = Microsoft.PowerShell, </Data>
    <Data Name="UserData"></Data>
    <Data Name="Payload">CommandInvocation(PSConsoleHostReadline): "PSConsoleHostReadline", </Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PowerShell"/>
    <EventID>4104</EventID>
    <TimeCreated SystemTime="2021-10-31 14:28:15.3316511"/>
    <Computer>jump01.offsec.lan</Computer>
    <Channel>Microsoft-Windows-PowerShell/Operational</Channel>
  </System>
  <EventData>
    <Data Name="MessageNumber">1</Data>
    <Data Name="MessageTotal">1</Data>
    <Data Name="ScriptBlockText">Get-LocalGroupMember -Name Administrators</Data>
    <Data Name="ScriptBlockId">6a14bd4a-b612-4efd-b229-8c9841cf5b06</Data>
    <Data Name="Path"></Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="PowerShell"/>
    <EventID>800</EventID>
    <TimeCreated SystemTime="2021-10-31 14:28:15.3427250"/>
    <Computer>jump01.offsec.lan</Computer>
    <Channel>Windows PowerShell</Channel>
  </System>
  <EventData>
    <Data>Get-LocalGroupMember -Name Administrators, 	DetailSequence=1
	DetailTotal=1

	SequenceNumber=303

	UserId=OFFSEC\admmig
	HostName=ConsoleHost
	HostVersion=5.1.14393.4350
	HostId=32afa6ab-c13e-4c81-91ed-8488f7e303ea
	HostApplication=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
	EngineVersion=5.1.14393.4350
	RunspaceId=be9cbd71-6464-43fd-94f7-af1594871f07
	PipelineId=69
	ScriptName=
	CommandLine=Get-LocalGroupMember -Name Administrators, CommandInvocation(Get-LocalGroupMember): "Get-LocalGroupMember"
ParameterBinding(Get-LocalGroupMember): na
...[+6806 chars truncated]
```