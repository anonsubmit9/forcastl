# Label audit batch 2 — single-model disagreements (18) + adjudication


========================================================================================
## 1. BENIGN-ID1-Admin PsExec remote diagnostic.csv
- GT=**NO** | diff=medium test_set=D | DISAGREEING MODEL: **gpt**
- GT malicious_events: (none)
- opus → **NO**: An admin account (OFFSEC\admmig) used PsExec from a jump host to run a single read-only diagnostic command (systeminfo) on SRV05 via a legitimate Kerberos network logon. The PSEXESVC service and SYSTEM-level process spawn are normal PsExec behavior, and the activity is consistent with routine administrative reconnaissance rather than mali
- gpt  → **YES**: PsExec64.exe was launched by OFFSEC\admmig from powershell.exe to \\SRV05 to run systeminfo, followed by a Kerberos network logon to srv05.offsec.lan from 10.23.30.10. On srv05.offsec.lan, C:\Windows\PSEXESVC.exe ran under NT AUTHORITY\SYSTEM and spawned systeminfo.exe, showing a remote execution pattern consistent with attack behavior.

### Artifact (3335 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon"/>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2025-09-23 13:02:11"/>
    <Computer>win-jump01.offsec.lan</Computer>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
  </System>
  <EventData>
    <Data Name="Image">C:\Tools\PsExec64.exe</Data>
    <Data Name="CommandLine">PsExec64.exe \\SRV05 -accepteula -u OFFSEC\admmig systeminfo</Data>
    <Data Name="User">OFFSEC\admmig</Data>
    <Data Name="IntegrityLevel">High</Data>
    <Data Name="ParentImage">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="ParentCommandLine">powershell.exe</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2025-09-23 13:02:12"/>
    <Computer>srv05.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserName">-</Data>
    <Data Name="TargetUserName">admmig</Data>
    <Data Name="TargetDomainName">OFFSEC</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="AuthenticationPackageName">Kerberos</Data>
    <Data Name="LogonProcessName">Kerberos</Data>
    <Data Name="IpAddress">10.23.30.10</Data>
    <Data Name="WorkstationName">WIN-JUMP01</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon"/>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2025-09-23 13:02:12"/>
    <Computer>srv05.offsec.lan</Computer>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
  </System>
  <EventData>
    <Data Name="Image">C:\Windows\PSEXESVC.exe</Data>
    <Data Name="CommandLine">C:\Windows\PSEXESVC.exe</Data>
    <Data Name="User">NT AUTHORITY\SYSTEM</Data>
    <Data Name="IntegrityLevel">System</Data>
    <Data Name="ParentImage">C:\Windows\System32\services.exe</Data>
    <Data Name="ParentCommandLine">C:\Windows\system32\services.exe</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon"/>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2025-09-23 13:02:13"/>
    <Computer>srv05.offsec.lan</Computer>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
  </System>
  <EventData>
    <Data Name="Image">C:\Windows\System32\systeminfo.exe</Data>
    <Data Name=
...[+735 chars]
```

========================================================================================
## 2. ID33205-SQL Server member added to database role.evtx
- GT=**NO** | diff=easy test_set=A | DISAGREEING MODEL: **gpt**
- GT malicious_events: (none)
- opus → **NO**: This is a SQL Server audit event (action APRL, succeeded) where the administrative principal OFFSEC\admmig added the principal test-sql to the db_accessadmin database role. This type of role membership change performed by an admin account is a routine database administration operation, and there is no privilege-escalation chain or anomalo
- gpt  → **YES**: The event shows a succeeded database role membership change where OFFSEC\admmig added test-sql to the db_accessadmin role. Granting db_accessadmin membership is a privilege change that can enable control over database access, indicating malicious privilege escalation behavior based on the logged statement.

### Artifact (1307 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="MSSQL$RADAR"/>
    <EventID>33205</EventID>
    <TimeCreated SystemTime="2020-07-15 21:10:18.6086660"/>
    <Computer>mssql01.offsec.lan</Computer>
    <Channel>Application</Channel>
  </System>
  <EventData>
    <Data>audit_schema_version:1
event_time:2020-07-15 21:10:18.5774151
sequence_number:1
action_id:APRL
succeeded:true
is_column_permission:false
session_id:54
server_principal_id:2
database_principal_id:1
target_server_principal_id:264
target_database_principal_id:5
object_id:16385
user_defined_event_id:0
class_type:RL
permission_bitmask:00000000000000000000000000000000
sequence_group_id:2BA48BB0-7079-4C13-AD08-9751FD9A83F7
session_server_principal_name:OFFSEC\admmig
server_principal_name:OFFSEC\admmig
server_principal_sid:01050000000000051500000056d628fc05668f976f2456bb57040000
database_principal_name:dbo
target_server_principal_name:test-sql
target_server_principal_sid:ff3873c6bcf5c04f89e4773e8797f200
target_database_principal_name:test-sql
server_instance_name:MSSQL01\RADAR
database_name:RCS-TEST-db
schema_name:
object_name:db_accessadmin
statement:ALTER ROLE [db_accessadmin] ADD MEMBER [test-sql]
additional_information:
user_defined_information:
</Data>
  </EventData>
</Event>
```

========================================================================================
## 3. ID2004-Any any firewall rule created.evtx
- GT=**YES** | diff=easy test_set=A | DISAGREEING MODEL: **gpt**
- GT malicious_events: Event 2004 (Microsoft-Windows-Windows Firewall With Advanced Security) on jump01.offsec.lan: new firewall rule created with RuleName='any crazy rule', RuleId={48A712F0-078E-4A6C-AA87-2545E5F432BA}, Action=3 (Allow), Direction=1 (Inbound), P
- opus → **YES**: A new firewall rule named "any crazy rule" was added (Event ID 2004) applying to all profiles, all local/remote addresses (*), all protocols, with no application/port scoping. The overly permissive, suspiciously named rule modified via mmc.exe by a non-default RID 1111 account suggests an attacker weakening firewall protections to enable 
- gpt  → **NO**: The event shows a Windows Firewall rule named "any crazy rule" associated with C:\Windows\System32\mmc.exe and a modifying user SID. Although the rule is broad with LocalAddresses "*" and RemoteAddresses "*", this single event does not show a malicious sequence or additional attack behavior in the provided data.

### Artifact (1591 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Windows Firewall With Advanced Security"/>
    <EventID>2004</EventID>
    <TimeCreated SystemTime="2021-02-22 22:57:19.4354802"/>
    <Computer>jump01.offsec.lan</Computer>
    <Channel>Microsoft-Windows-Windows Firewall With Advanced Security/Firewall</Channel>
  </System>
  <EventData>
    <Data Name="RuleId">{48A712F0-078E-4A6C-AA87-2545E5F432BA}</Data>
    <Data Name="RuleName">any crazy rule</Data>
    <Data Name="Origin">1</Data>
    <Data Name="ApplicationPath"></Data>
    <Data Name="ServiceName"></Data>
    <Data Name="Direction">1</Data>
    <Data Name="Protocol">256</Data>
    <Data Name="LocalPorts"></Data>
    <Data Name="RemotePorts"></Data>
    <Data Name="Action">3</Data>
    <Data Name="Profiles">2147483647</Data>
    <Data Name="LocalAddresses">*</Data>
    <Data Name="RemoteAddresses">*</Data>
    <Data Name="RemoteMachineAuthorizationList"></Data>
    <Data Name="RemoteUserAuthorizationList"></Data>
    <Data Name="EmbeddedContext"></Data>
    <Data Name="Flags">1</Data>
    <Data Name="Active">1</Data>
    <Data Name="EdgeTraversal">0</Data>
    <Data Name="LooseSourceMapped">0</Data>
    <Data Name="SecurityOptions">0</Data>
    <Data Name="ModifyingUser">S-1-5-21-4230534742-2542757381-3142984815-1111</Data>
    <Data Name="ModifyingApplication">C:\Windows\System32\mmc.exe</Data>
    <Data Name="SchemaVersion">538</Data>
    <Data Name="RuleStatus">65536</Data>
    <Data Name="LocalOnlyMapped">0</Data>
  </EventData>
</Event>
```

========================================================================================
## 4. ID316,300,301,316,823,848-Mimispool printer server instal.evtx
- GT=**YES** | diff=easy test_set=A | DISAGREEING MODEL: **gpt**
- GT malicious_events: Event 300 (PrintService PrinterCreated): printer `Kiwi Legit Printer` created on fs03vuln.offsec.lan — the printer name is a Mimikatz/gentilkiwi signature (mimikatz.exe `misc::printnightmare` / Mimispool module).
- opus → **YES**: The PrintService Admin log shows repeated Event ID 823 (driver/configuration changes) interleaved with Operational events 808/848/849-style driver-loading and 300/301/302/316 spooler activity on a host named "fs03vuln," consistent with PrintNightmare (CVE-2021-34527) exploitation where malicious print drivers are added/loaded via the spoo
- gpt  → **NO**: The events show a cluster of Microsoft-Windows-PrintService Admin and Operational activity on fs03vuln.offsec.lan, but the EventData fields are empty. There are no accounts, processes, commands, registry paths, or remote network indicators in the provided logs to confirm attack behavior.

### Artifact (4192 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PrintService"/>
    <EventID>823</EventID>
    <TimeCreated SystemTime="2021-10-27 10:09:16.2809298"/>
    <Computer>fs03vuln.offsec.lan</Computer>
    <Channel>Microsoft-Windows-PrintService/Admin</Channel>
  </System>
  <EventData>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PrintService"/>
    <EventID>823</EventID>
    <TimeCreated SystemTime="2021-10-27 10:12:33.4642419"/>
    <Computer>fs03vuln.offsec.lan</Computer>
    <Channel>Microsoft-Windows-PrintService/Admin</Channel>
  </System>
  <EventData>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PrintService"/>
    <EventID>823</EventID>
    <TimeCreated SystemTime="2021-10-27 10:12:47.3235757"/>
    <Computer>fs03vuln.offsec.lan</Computer>
    <Channel>Microsoft-Windows-PrintService/Admin</Channel>
  </System>
  <EventData>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PrintService"/>
    <EventID>302</EventID>
    <TimeCreated SystemTime="2021-10-27 10:14:21.3699768"/>
    <Computer>fs03vuln.offsec.lan</Computer>
    <Channel>Microsoft-Windows-PrintService/Operational</Channel>
  </System>
  <EventData>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PrintService"/>
    <EventID>849</EventID>
    <TimeCreated SystemTime="2021-10-27 10:14:21.3699768"/>
    <Computer>fs03vuln.offsec.lan</Computer>
    <Channel>Microsoft-Windows-PrintService/Operational</Channel>
  </System>
  <EventData>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PrintService"/>
    <EventID>301</EventID>
    <TimeCreated SystemTime="2021-10-27 10:14:21.3699768"/>
    <Computer>fs03vuln.offsec.lan</Computer>
    <Channel>Microsoft-Windows-PrintService/Operational</Channel>
  </System>
  <EventData>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PrintService"/>
    <EventID>316</EventID>
    <TimeCreated SystemTime="2021-10-27 10:14:27.3099495"/>
    <Computer>fs03vuln.offsec.lan</Computer>
    <Channel>Microsoft-Windows-PrintService/Ope
...[+1592 chars]
```

========================================================================================
## 5. ID33205-SQL Server local user created.evtx
- GT=**YES** | diff=easy test_set=A | DISAGREEING MODEL: **gpt**
- GT malicious_events: Event 33205 (SQL audit) by OFFSEC\admmig (database principal `dbo`) on MSSQL01\RADAR: executed `CREATE LOGIN [test-sql] WITH PASSWORD=N'******', DEFAULT_DATABASE=[master], CHECK_EXPIRATION=OFF, CHECK_POLICY=OFF`. New SQL login `test-sql` cr
- opus → **YES**: A new SQL Server login "test-sql" was created with both CHECK_EXPIRATION and CHECK_POLICY disabled, which weakens password security controls and is a common persistence technique used by attackers. The action_id "CR" (CREATE) succeeded on the master database, and creating a backdoor login with policy enforcement disabled is suspicious and
- gpt  → **NO**: The event shows a successful SQL audit action where OFFSEC\admmig created the login test-sql in the master database. Although CHECK_POLICY=OFF and CHECK_EXPIRATION=OFF can be suspicious, the provided data contains only this single login creation event and no additional evidence of abuse or attack behavior.

### Artifact (1309 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="MSSQL$RADAR"/>
    <EventID>33205</EventID>
    <TimeCreated SystemTime="2020-07-15 21:05:18.1608154"/>
    <Computer>mssql01.offsec.lan</Computer>
    <Channel>Application</Channel>
  </System>
  <EventData>
    <Data>audit_schema_version:1
event_time:2020-07-15 21:05:15.2315183
sequence_number:1
action_id:CR  
succeeded:true
is_column_permission:false
session_id:52
server_principal_id:2
database_principal_id:1
target_server_principal_id:0
target_database_principal_id:0
object_id:264
user_defined_event_id:0
class_type:SL
permission_bitmask:00000000000000000000000000000000
sequence_group_id:0F5E049F-DE52-439E-A9B1-77399994367B
session_server_principal_name:OFFSEC\admmig
server_principal_name:OFFSEC\admmig
server_principal_sid:01050000000000051500000056d628fc05668f976f2456bb57040000
database_principal_name:dbo
target_server_principal_name:
target_server_principal_sid:
target_database_principal_name:
server_instance_name:MSSQL01\RADAR
database_name:master
schema_name:
object_name:test-sql
statement:CREATE LOGIN [test-sql] WITH PASSWORD=N'******', DEFAULT_DATABASE=[master], CHECK_EXPIRATION=OFF, CHECK_POLICY=OFF
additional_information:
user_defined_information:
</Data>
  </EventData>
</Event>
```

========================================================================================
## 6. ID354-808-Mimispool printer installation (PrintNightmare).evtx
- GT=**YES** | diff=easy test_set=A | DISAGREEING MODEL: **gpt**
- GT malicious_events: Event 316 (DriverAdded): driver `Generic / Text Only` (Windows x64, Version-3) added with the standard 14-DLL list (UNIDRV, TTY*, etc.) — the legitimate driver shell used to side-load the malicious DLL.
- opus → **YES**: The rapid sequence of PrintService events including 808 (failed to load a plugin module) and 823 on FS03.offsec.lan within milliseconds is consistent with PrintNightmare (CVE-2021-34527) exploitation, where a malicious printer driver/DLL is loaded via the spooler. The paired driver-add (300/301/302/304/306) and plugin-load-failure (808) e
- gpt  → **NO**: The logs show a sequence of Microsoft-Windows-PrintService events on FS03.offsec.lan with no EventData containing processes, accounts, commands, registry paths, or remote network indicators. Based only on the provided data, there is not enough evidence to identify attack behavior.

### Artifact (5294 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PrintService"/>
    <EventID>316</EventID>
    <TimeCreated SystemTime="2021-10-27 10:28:26.1510830"/>
    <Computer>FS03.offsec.lan</Computer>
    <Channel>Microsoft-Windows-PrintService/Operational</Channel>
  </System>
  <EventData>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PrintService"/>
    <EventID>300</EventID>
    <TimeCreated SystemTime="2021-10-27 10:28:26.2292129"/>
    <Computer>FS03.offsec.lan</Computer>
    <Channel>Microsoft-Windows-PrintService/Operational</Channel>
  </System>
  <EventData>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PrintService"/>
    <EventID>304</EventID>
    <TimeCreated SystemTime="2021-10-27 10:28:26.2292129"/>
    <Computer>FS03.offsec.lan</Computer>
    <Channel>Microsoft-Windows-PrintService/Operational</Channel>
  </System>
  <EventData>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PrintService"/>
    <EventID>306</EventID>
    <TimeCreated SystemTime="2021-10-27 10:28:26.2292129"/>
    <Computer>FS03.offsec.lan</Computer>
    <Channel>Microsoft-Windows-PrintService/Operational</Channel>
  </System>
  <EventData>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PrintService"/>
    <EventID>306</EventID>
    <TimeCreated SystemTime="2021-10-27 10:28:26.2448345"/>
    <Computer>FS03.offsec.lan</Computer>
    <Channel>Microsoft-Windows-PrintService/Operational</Channel>
  </System>
  <EventData>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PrintService"/>
    <EventID>354</EventID>
    <TimeCreated SystemTime="2021-10-27 10:28:26.2604608"/>
    <Computer>FS03.offsec.lan</Computer>
    <Channel>Microsoft-Windows-PrintService/Admin</Channel>
  </System>
  <EventData>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PrintService"/>
    <EventID>306</EventID>
    <TimeCreated SystemTime="2021-10-27 10:28:26.2604608"/>
    <Computer>FS03.offsec.lan</Computer>
    <Channel>Microsoft-Windows-PrintService/Operational</Channe
...[+2694 chars]
```

========================================================================================
## 7. ID4103-4104-OpenSSH server activation and config.evtx
- GT=**YES** | diff=hard test_set=A | DISAGREEING MODEL: **opus**
- GT malicious_events: Among 240 PowerShell ScriptBlock/Pipeline events, the dispositive line is `Start-Service sshd` — manual activation of the OpenSSH server (T1133 External Remote Services / T1505 Server Software Component). The other ~239 events are PowerShel
- opus → **NO**: An administrator account (OFFSEC\admmig) is enabling and configuring the OpenSSH server service for automatic startup and querying SSH-related firewall rules, which are standard system administration tasks. The remaining 4104 events are normal PowerShell module auto-loading of the NetSecurity cmdlet definitions triggered by the Get-NetFir
- gpt  → **YES**: The logs show OFFSEC\admmig using PowerShell to start the sshd service and then set sshd to StartupType 'Automatic'. This sequence, followed by checking SSH-related firewall rules with Get-NetFirewallRule -Name *ssh*, indicates enabling persistent remote access rather than routine PowerShell module activity.

### Artifact (1515827 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PowerShell"/>
    <EventID>4103</EventID>
    <TimeCreated SystemTime="2021-04-22 10:19:29.4765312"/>
    <Computer>win10-02.offsec.lan</Computer>
    <Channel>Microsoft-Windows-PowerShell/Operational</Channel>
  </System>
  <EventData>
    <Data Name="ContextInfo">        Severity = Informational,         Host Name = ConsoleHost,         Host Version = 5.1.19041.906,         Host ID = 95e96d56-040a-43c5-9b7c-b459d24bbb56,         Host Application = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe,         Engine Version = 5.1.19041.906,         Runspace ID = d1a7cc59-e5d0-4b40-bf2e-0e4265f432c0,         Pipeline ID = 22,         Command Name = PSConsoleHostReadLine,         Command Type = Function,         Script Name = ,         Command Path = ,         Sequence Number = 90,         User = OFFSEC\admmig,         Connected User = ,         Shell ID = Microsoft.PowerShell, </Data>
    <Data Name="UserData"></Data>
    <Data Name="Payload">CommandInvocation(PSConsoleHostReadLine): "PSConsoleHostReadLine", </Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PowerShell"/>
    <EventID>4104</EventID>
    <TimeCreated SystemTime="2021-04-22 10:19:29.4793192"/>
    <Computer>win10-02.offsec.lan</Computer>
    <Channel>Microsoft-Windows-PowerShell/Operational</Channel>
  </System>
  <EventData>
    <Data Name="MessageNumber">1</Data>
    <Data Name="MessageTotal">1</Data>
    <Data Name="ScriptBlockText">Start-Service sshd</Data>
    <Data Name="ScriptBlockId">5cc7cdc9-cad8-44e2-9161-f03661b8dcdb</Data>
    <Data Name="Path"></Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PowerShell"/>
    <EventID>4103</EventID>
    <TimeCreated SystemTime="2021-04-22 10:19:30.0357020"/>
    <Computer>win10-02.offsec.lan</Computer>
    <Channel>Microsoft-Windows-PowerShell/Operational</Channel>
  </System>
  <EventData>
    <Data Name="ContextInfo">        Severity = Informational,         Host Name = ConsoleHost,         Host Version = 5.1.19041.906,         Host ID = 95e96d56-040a-43c5-9b7c-b459d24bbb56,         Host Application = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe,         Engine Version = 5.1.19041.906,         Runspace ID = d1a7cc59-e5d0-4b40-bf2e-0e4265f432c0,         Pipeline ID = 23,         Command Name = Start-Service,
...[+1513227 chars]
```

========================================================================================
## 8. ID4103-4104-OpenSSH server install.evtx
- GT=**YES** | diff=hard test_set=A | DISAGREEING MODEL: **opus**
- GT malicious_events: OpenSSH server installation via PowerShell Add-WindowsCapability for remote access
- opus → **NO**: The logs show an administrator (OFFSEC\admmig) installing the OpenSSH Server capability via the standard Add-WindowsCapability cmdlet, which loads the Dism module and registers normal command aliases. While installing OpenSSH could enable remote access, the activity is performed interactively by an admin account using legitimate built-in 
- gpt  → **YES**: OFFSEC\admmig used PowerShell to run Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 on win10-02.offsec.lan, which adds OpenSSH Server remote access capability. The sequence also shows subsequent PowerShell execution as OFFSEC\SYSTEM, making the pattern suspicious for enabling persistent remote access rather than routine int

### Artifact (34508 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PowerShell"/>
    <EventID>4103</EventID>
    <TimeCreated SystemTime="2021-04-22 10:02:14.3939392"/>
    <Computer>win10-02.offsec.lan</Computer>
    <Channel>Microsoft-Windows-PowerShell/Operational</Channel>
  </System>
  <EventData>
    <Data Name="ContextInfo">        Severity = Informational,         Host Name = ConsoleHost,         Host Version = 5.1.19041.906,         Host ID = 95e96d56-040a-43c5-9b7c-b459d24bbb56,         Host Application = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe,         Engine Version = 5.1.19041.906,         Runspace ID = d1a7cc59-e5d0-4b40-bf2e-0e4265f432c0,         Pipeline ID = 3,         Command Name = PSConsoleHostReadLine,         Command Type = Function,         Script Name = ,         Command Path = ,         Sequence Number = 20,         User = OFFSEC\admmig,         Connected User = ,         Shell ID = Microsoft.PowerShell, </Data>
    <Data Name="UserData"></Data>
    <Data Name="Payload">CommandInvocation(PSConsoleHostReadLine): "PSConsoleHostReadLine", </Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PowerShell"/>
    <EventID>4104</EventID>
    <TimeCreated SystemTime="2021-04-22 10:02:14.4062532"/>
    <Computer>win10-02.offsec.lan</Computer>
    <Channel>Microsoft-Windows-PowerShell/Operational</Channel>
  </System>
  <EventData>
    <Data Name="MessageNumber">1</Data>
    <Data Name="MessageTotal">1</Data>
    <Data Name="ScriptBlockText">Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0</Data>
    <Data Name="ScriptBlockId">fa9d0714-1fcd-4765-ab4f-ccea100a4b1a</Data>
    <Data Name="Path"></Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PowerShell"/>
    <EventID>4103</EventID>
    <TimeCreated SystemTime="2021-04-22 10:02:14.6190458"/>
    <Computer>win10-02.offsec.lan</Computer>
    <Channel>Microsoft-Windows-PowerShell/Operational</Channel>
  </System>
  <EventData>
    <Data Name="ContextInfo">        Severity = Informational,         Host Name = ConsoleHost,         Host Version = 5.1.19041.906,         Host ID = 95e96d56-040a-43c5-9b7c-b459d24bbb56,         Host Application = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe,         Engine Version = 5.1.19041.906,         Runspace ID = d1a7cc59-e5d0-4b40-bf2e-0e4265f432c0,         Pipeline ID =
...[+31908 chars]
```

========================================================================================
## 9. ID4625-failed login with denied access due to account restriction.evtx
- GT=**YES** | diff=easy test_set=A | DISAGREEING MODEL: **gpt**
- GT malicious_events: 2 × Event 4625 LogonType 10 (RemoteInteractive = RDP) from IpAddress 10.23.23.9, AuthPackage=Negotiate, LogonProcess=User32, SubjectUserName=`FS03$` (the destination machine account context). The failures triggered an account-restriction po
- opus → **YES**: Multiple failed RDP logons (LogonType 10) with Status 0xC000006E (bad username/password) from the same source IP 10.23.23.9 against FS03 within roughly two minutes indicate a remote brute-force/credential-guessing attempt. The repeated interactive remote authentication failures from a single host targeting unspecified accounts is consiste
- gpt  → **NO**: The logs show two failed LogonType 10 authentication attempts involving C:\Windows\System32\winlogon.exe from 10.23.23.9. With only two failures and no successful logon, command execution, privilege escalation, or other suspicious follow-on activity present in the provided data, this is insufficient to identify attack behavior.

### Artifact (2583 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2021-10-23 21:50:11.6665197"/>
    <Computer>FS03.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">FS03$</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x3E7</Data>
    <Data Name="TargetUserSid">S-1-0-0</Data>
    <Data Name="TargetUserName">-</Data>
    <Data Name="TargetDomainName">-</Data>
    <Data Name="Status">0xC000006E</Data>
    <Data Name="FailureReason">%%2313</Data>
    <Data Name="SubStatus">0x0</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="LogonProcessName">User32 </Data>
    <Data Name="AuthenticationPackageName">Negotiate</Data>
    <Data Name="WorkstationName">-</Data>
    <Data Name="TransmittedServices">-</Data>
    <Data Name="LmPackageName">-</Data>
    <Data Name="KeyLength">0</Data>
    <Data Name="ProcessId">0x1310</Data>
    <Data Name="ProcessName">C:\Windows\System32\winlogon.exe</Data>
    <Data Name="IpAddress">10.23.23.9</Data>
    <Data Name="IpPort">0</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2021-10-23 21:51:57.2125134"/>
    <Computer>FS03.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">FS03$</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x3E7</Data>
    <Data Name="TargetUserSid">S-1-0-0</Data>
    <Data Name="TargetUserName">-</Data>
    <Data Name="TargetDomainName">-</Data>
    <Data Name="Status">0xC000006E</Data>
    <Data Name="FailureReason">%%2313</Data>
    <Data Name="SubStatus">0x0</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="LogonProcessName">User32 </Data>
    <Data Name="AuthenticationPackageName">Negotiate</Data>
    <Data Name="WorkstationName">-</Data>
    <Data Name="TransmittedServices">-</Data>
    <Data Name="LmPackageName">-</Data>
    <Data Name="KeyLength">0</Data>
    <Data Name="ProcessId">0xDB4</Data>
    <Data Name="ProcessName">C:\Windows\System32\winlogon.exe</Data>
    <Data Name="IpAddress">10.23.23.9</Data>
    <Data Name="IpPort">0</Data>
  </EventData>
</Event>
```

========================================================================================
## 10. ID4661-Suspicious SAM access to password attributes by LSASS (Dcshadow).evtx
- GT=**YES** | diff=easy test_set=A | DISAGREEING MODEL: **gpt**
- GT malicious_events: 20 × Event 4661 with SubjectUserName=`ROOTDC1$` (the DC's own machine account context) — lsass.exe touching `DC=offsec,DC=lan`, `CN=Builtin,DC=offsec,DC=lan`, `CN=Server,CN=System,DC=offsec,DC=lan`, and `S-1-5-32-544` (BUILTIN\Administrator
- opus → **YES**: The logs show repeated SAM object access (4661) against SAM_SERVER, SAM_DOMAIN, and SAM_ALIAS S-1-5-32-544 (Builtin Administrators) with full access masks, enumerating domain and Builtin objects in a tight burst then repeating ~5 minutes later. This systematic enumeration of the SAM database and the Administrators alias on a domain contro
- gpt  → **NO**: The events show repeated 4661 access to Security Account Manager objects by ROOTDC1$ using C:\Windows\System32\lsass.exe. There are no command lines, registry keys, or remote network indicators in the logs, and the activity is limited to the system account and LSASS process on rootdc1.offsec.lan.

### Artifact (37014 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4661</EventID>
    <TimeCreated SystemTime="2021-03-26 20:42:48.6144925"/>
    <Computer>rootdc1.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">ROOTDC1$</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x3E7</Data>
    <Data Name="ObjectServer">Security Account Manager</Data>
    <Data Name="ObjectType">SAM_SERVER</Data>
    <Data Name="ObjectName">CN=Server,CN=System,DC=offsec,DC=lan</Data>
    <Data Name="HandleId">0x1D35E251D80</Data>
    <Data Name="TransactionId">00000000-0000-0000-0000-000000000000</Data>
    <Data Name="AccessList">%%1537, %%1538, %%1539, %%1540, %%5376, %%5377, %%5378, %%5379, %%5380, %%5381, %%5382, %%5383, %%5384, </Data>
    <Data Name="AccessReason">-</Data>
    <Data Name="AccessMask">0xF01FF</Data>
    <Data Name="PrivilegeList">-</Data>
    <Data Name="Properties">---, {bf967aad-0de6-11d0-a285-00aa003049e2}, </Data>
    <Data Name="RestrictedSidCount">0</Data>
    <Data Name="ProcessId">0x230</Data>
    <Data Name="ProcessName">C:\Windows\System32\lsass.exe</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4661</EventID>
    <TimeCreated SystemTime="2021-03-26 20:42:48.6146356"/>
    <Computer>rootdc1.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">ROOTDC1$</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x3E7</Data>
    <Data Name="ObjectServer">Security Account Manager</Data>
    <Data Name="ObjectType">SAM_DOMAIN</Data>
    <Data Name="ObjectName">DC=offsec,DC=lan</Data>
    <Data Name="HandleId">0x1D35E250570</Data>
    <Data Name="TransactionId">00000000-0000-0000-0000-000000000000</Data>
    <Data Name="AccessList">%%1537, %%1538, %%1539, %%1540, %%5392, %%5394, %%5395, %%5396, %%5397, %%5398, %%5399, %%5400, </Data>
    <Data Name="AccessReason">-</Data>
    <Data Name="AccessMask">0xF01FD</Data>
    <Data Name="PrivilegeList">-</Data>
    <Data Name="Properties">---, {19195a5a-6da0-11d0-afd3-00c04fd930c9}, %%1537, %%1538, %%1539, %%1540, %%5392, %%5394, %%5395, %%5396, %%5397, %%5398, %%5399, %%5400, {c7407360-20bf-11d0-a768-00aa006
...[+34414 chars]
```

========================================================================================
## 11. ID4663-Task Manager used to dump LSASS process.evtx
- GT=**YES** | diff=easy test_set=A | DISAGREEING MODEL: **gpt**
- GT malicious_events: 2 × Event 4663 (Object Access attempt) by Administrator from Taskmgr.exe targeting `\Device\HarddiskVolume4\Windows\System32\lsass.exe` with read access — the Task Manager 'Create Dump File' interactive feature reads lsass memory to write a
- opus → **YES**: Taskmgr.exe repeatedly accessed lsass.exe (AccessMask 0x10, read access) under the privileged Administrator account, a behavior consistent with credential dumping via memory access to the LSASS process. While Task Manager can legitimately interact with processes, the paired read-access events against LSASS handles are a strong indicator o
- gpt  → **NO**: The events show C:\Windows\System32\Taskmgr.exe accessing the process object \Device\HarddiskVolume4\Windows\System32\lsass.exe under the Administrator account. There are no command lines, registry changes, network connections, or additional correlated activity in the provided logs to establish malicious behavior.

### Artifact (2066 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4663</EventID>
    <TimeCreated SystemTime="2022-11-04 10:47:07.3599296"/>
    <Computer>AD01.kdmo.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-1089590679-3038349081-645448463-500</Data>
    <Data Name="SubjectUserName">Administrator</Data>
    <Data Name="SubjectDomainName">KDMO</Data>
    <Data Name="SubjectLogonId">0x6007A</Data>
    <Data Name="ObjectServer">Security</Data>
    <Data Name="ObjectType">Process</Data>
    <Data Name="ObjectName">\Device\HarddiskVolume4\Windows\System32\lsass.exe</Data>
    <Data Name="HandleId">0x9EC</Data>
    <Data Name="AccessList">%%4484, </Data>
    <Data Name="AccessMask">0x10</Data>
    <Data Name="ProcessId">0x110C</Data>
    <Data Name="ProcessName">C:\Windows\System32\Taskmgr.exe</Data>
    <Data Name="ResourceAttributes">-</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4663</EventID>
    <TimeCreated SystemTime="2022-11-04 10:47:07.3606636"/>
    <Computer>AD01.kdmo.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-1089590679-3038349081-645448463-500</Data>
    <Data Name="SubjectUserName">Administrator</Data>
    <Data Name="SubjectDomainName">KDMO</Data>
    <Data Name="SubjectLogonId">0x6007A</Data>
    <Data Name="ObjectServer">Security</Data>
    <Data Name="ObjectType">Process</Data>
    <Data Name="ObjectName">\Device\HarddiskVolume4\Windows\System32\lsass.exe</Data>
    <Data Name="HandleId">0x89C</Data>
    <Data Name="AccessList">%%4484, </Data>
    <Data Name="AccessMask">0x10</Data>
    <Data Name="ProcessId">0x110C</Data>
    <Data Name="ProcessName">C:\Windows\System32\Taskmgr.exe</Data>
    <Data Name="ResourceAttributes">-</Data>
  </EventData>
</Event>
```

========================================================================================
## 12. ID4717-4718-System security granded to account.evtx
- GT=**YES** | diff=easy test_set=A | DISAGREEING MODEL: **opus**
- GT malicious_events: Event 4717 (System security access granted): admmig grants `SeDenyServiceLogonRight` to TargetSid `S-1-5-21-…-1158` (lambda-user, the canary). The 'deny logon as service' right paired-write is part of a logon-rights manipulation primitive —
- opus → **NO**: The two events show user rights policy changes where SeDenyServiceLogonRight was granted (4717) then removed (4718) for the same target SID by the same administrative account admmig within seconds. This paired grant/removal of a deny-logon right on the same identifier is consistent with routine policy adjustment or migration activity, not
- gpt  → **YES**: The same account, admmig, granted and then removed SeDenyServiceLogonRight on the same TargetSid within a short time window. This paired state change on the same identifier indicates suspicious manipulation of logon rights rather than a standalone benign administrative event.

### Artifact (1450 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4717</EventID>
    <TimeCreated SystemTime="2020-07-12 20:06:37.6617806"/>
    <Computer>fs02.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-4230534742-2542757381-3142984815-1111</Data>
    <Data Name="SubjectUserName">admmig</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x202DAC8</Data>
    <Data Name="TargetSid">S-1-5-21-4230534742-2542757381-3142984815-1158</Data>
    <Data Name="AccessGranted">SeDenyServiceLogonRight</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4718</EventID>
    <TimeCreated SystemTime="2020-07-12 20:07:05.8424048"/>
    <Computer>fs02.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-4230534742-2542757381-3142984815-1111</Data>
    <Data Name="SubjectUserName">admmig</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x202DAC8</Data>
    <Data Name="TargetSid">S-1-5-21-4230534742-2542757381-3142984815-1158</Data>
    <Data Name="AccessRemoved">SeDenyServiceLogonRight</Data>
  </EventData>
</Event>
```

========================================================================================
## 13. ID4719-Audit policy deactivation.evtx
- GT=**YES** | diff=easy test_set=A | DISAGREEING MODEL: **gpt**
- GT malicious_events: Event 4719 (×30): admmig disables auditing across many subcategories in rapid succession — Account Logon (Kerberos), Logon/Logoff, Object Access, Privilege Use, Detailed Tracking (process creation), Policy Change, Account Management, DS Acc
- opus → **YES**: A single account (admmig) generated a rapid burst of 4719 "System audit policy was changed" events at the exact same timestamp across virtually every audit subcategory on FS03.offsec.lan. The %%8450 ("Failure removed") and %%8448 changes systematically disabling auditing across all categories is a strong indicator of an attacker attemptin
- gpt  → **NO**: The logs show repeated Event ID 4719 audit policy changes by the account admmig on FS03.offsec.lan at the same timestamp. No processes, commands, network indicators, registry keys, or other events are present to show attack activity beyond audit policy modification.

### Artifact (24124 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4719</EventID>
    <TimeCreated SystemTime="2021-10-25 18:30:36.5159063"/>
    <Computer>FS03.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-4230534742-2542757381-3142984815-1111</Data>
    <Data Name="SubjectUserName">admmig</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x123550</Data>
    <Data Name="CategoryId">%%8272</Data>
    <Data Name="SubcategoryId">%%12288</Data>
    <Data Name="SubcategoryGuid">0cce9210-69ae-11d9-bed3-505054503030</Data>
    <Data Name="AuditPolicyChanges">%%8448</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4719</EventID>
    <TimeCreated SystemTime="2021-10-25 18:30:36.5159063"/>
    <Computer>FS03.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-4230534742-2542757381-3142984815-1111</Data>
    <Data Name="SubjectUserName">admmig</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x123550</Data>
    <Data Name="CategoryId">%%8272</Data>
    <Data Name="SubcategoryId">%%12289</Data>
    <Data Name="SubcategoryGuid">0cce9211-69ae-11d9-bed3-505054503030</Data>
    <Data Name="AuditPolicyChanges">%%8448, %%8450</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4719</EventID>
    <TimeCreated SystemTime="2021-10-25 18:30:36.5159063"/>
    <Computer>FS03.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-4230534742-2542757381-3142984815-1111</Data>
    <Data Name="SubjectUserName">admmig</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x123550</Data>
    <Data Name="CategoryId">%%8272</Data>
    <Data Name="SubcategoryId">%%12290</Data>
    <Data Name="SubcategoryGuid">0cce9212-69ae-11d9-bed3-505054503030</Data>
    <Data Name="AuditPolicyChanges">%%8448, %%8450</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4719</EventID>
    <TimeCreated SystemTi
...[+21524 chars]
```

========================================================================================
## 14. ID4964-Login of a member of a special group.evtx
- GT=**YES** | diff=easy test_set=A | DISAGREEING MODEL: **gpt**
- GT malicious_events: Event 4964 (×8): logons by accounts that are members of a 'Special Groups' watchlist (configured via 4908). admmig + ROOTDC1$ + LOCAL SERVICE all show up as 'special-group members' in this trace.
- opus → **YES**: Event 4964 indicates logons by accounts flagged as "special groups," and the repeated tagging of admmig (S-1-5-21-...-1111) carrying the monitored SID S-1-5-21-4230534742-2542757381-3142984815-1613 across many rapid logons on a domain controller (rootdc1.offsec.lan) is consistent with privileged-credential abuse. The clustering of numerou
- gpt  → **NO**: The events show repeated 4964 logon notifications where special groups were assigned to new logons for admmig. No process execution, commands, registry changes, or remote network source indicators are present in the logs to demonstrate attack behavior.

### Artifact (8082 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4964</EventID>
    <TimeCreated SystemTime="2020-07-12 06:01:42.2411354"/>
    <Computer>rootdc1.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-19</Data>
    <Data Name="SubjectUserName">LOCAL SERVICE</Data>
    <Data Name="SubjectDomainName">NT AUTHORITY</Data>
    <Data Name="SubjectLogonId">0x3E5</Data>
    <Data Name="LogonGuid">00000000-0000-0000-0000-000000000000</Data>
    <Data Name="TargetUserSid">S-1-5-21-4230534742-2542757381-3142984815-1111</Data>
    <Data Name="TargetUserName">admmig</Data>
    <Data Name="TargetDomainName">OFFSEC</Data>
    <Data Name="TargetLogonId">0x80E3882</Data>
    <Data Name="TargetLogonGuid">00000000-0000-0000-0000-000000000000</Data>
    <Data Name="SidList">, %{S-1-5-21-4230534742-2542757381-3142984815-1613}</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4964</EventID>
    <TimeCreated SystemTime="2020-07-12 06:01:57.7042143"/>
    <Computer>rootdc1.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">ROOTDC1$</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x3E7</Data>
    <Data Name="LogonGuid">00000000-0000-0000-0000-000000000000</Data>
    <Data Name="TargetUserSid">S-1-5-21-4230534742-2542757381-3142984815-1111</Data>
    <Data Name="TargetUserName">admmig</Data>
    <Data Name="TargetDomainName">OFFSEC</Data>
    <Data Name="TargetLogonId">0x80E977E</Data>
    <Data Name="TargetLogonGuid">00000000-0000-0000-0000-000000000000</Data>
    <Data Name="SidList">, %{S-1-5-21-4230534742-2542757381-3142984815-1613}</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4964</EventID>
    <TimeCreated SystemTime="2020-07-12 06:01:57.7092890"/>
    <Computer>rootdc1.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">ROOTDC1$</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x3E7</Data>
    <Data Name="LogonGuid">00000000-0000-0000-0000-0000000
...[+5482 chars]
```

========================================================================================
## 15. ID5136-4662 sensitive GPO edited.evtx
- GT=**YES** | diff=easy test_set=A | DISAGREEING MODEL: **gpt**
- GT malicious_events: Event 5136 (×many, directory service object modified): admmig modifies a Group Policy Object stored at `CN={127328D6-A8A8-49E3-BA71-410C945F42CE},CN=POLICIES,CN=SYSTEM,DC=OFFSEC,DC=LAN` — the GPO's Group Policy Container in AD.
- opus → **YES**: The account admmig modified a groupPolicyContainer object (versionNumber incremented from 1 to 2) under CN=POLICIES,CN=SYSTEM, indicating a Group Policy Object edit, followed immediately by repeated directory object access events. The GPO modification chain combined with subsequent rapid object-access enumeration on the domain controller 
- gpt  → **NO**: The logs show directory object access events and a groupPolicyContainer versionNumber change by admmig, followed by machine account object access from FS02$ and ROOTDC1$. There are no process executions, command lines, registry changes, or explicit malicious indicators in the provided event data to confirm attack behavior.

### Artifact (14510 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4662</EventID>
    <TimeCreated SystemTime="2021-02-22 22:47:38.9988523"/>
    <Computer>rootdc1.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-4230534742-2542757381-3142984815-1111</Data>
    <Data Name="SubjectUserName">admmig</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x24E2CBF6</Data>
    <Data Name="ObjectServer">DS</Data>
    <Data Name="ObjectType">%{f30e3bc2-9ff0-11d1-b603-0000f80367c1}</Data>
    <Data Name="ObjectName">%{244db979-f8ae-4695-9e37-2104a17a967f}</Data>
    <Data Name="OperationType">Object Access</Data>
    <Data Name="HandleId">0x0</Data>
    <Data Name="AccessList">%%7685, </Data>
    <Data Name="AccessMask">0x20</Data>
    <Data Name="Properties">%%7685, {771727b1-31b8-4cdf-ae62-4fe39fadf89e}, {bf967a76-0de6-11d0-a285-00aa003049e2}, {f30e3bc2-9ff0-11d1-b603-0000f80367c1}, </Data>
    <Data Name="AdditionalInfo">-</Data>
    <Data Name="AdditionalInfo2"></Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>5136</EventID>
    <TimeCreated SystemTime="2021-02-22 22:47:43.6450515"/>
    <Computer>rootdc1.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="OpCorrelationID">90949b97-6477-4d47-ab9d-e291f4fe8e34</Data>
    <Data Name="AppCorrelationID">-</Data>
    <Data Name="SubjectUserSid">S-1-5-21-4230534742-2542757381-3142984815-1111</Data>
    <Data Name="SubjectUserName">admmig</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x24E2CBF6</Data>
    <Data Name="DSName">offsec.lan</Data>
    <Data Name="DSType">%%14676</Data>
    <Data Name="ObjectDN">CN={127328D6-A8A8-49E3-BA71-410C945F42CE},CN=POLICIES,CN=SYSTEM,DC=OFFSEC,DC=LAN</Data>
    <Data Name="ObjectGUID">244db979-f8ae-4695-9e37-2104a17a967f</Data>
    <Data Name="ObjectClass">groupPolicyContainer</Data>
    <Data Name="AttributeLDAPDisplayName">versionNumber</Data>
    <Data Name="AttributeSyntaxOID">2.5.5.9</Data>
    <Data Name="AttributeValue">1</Data>
    <Data Name="OperationType">%%14675</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>5136</EventID>
    
...[+11910 chars]
```

========================================================================================
## 16. ID5142- New file share created.evtx
- GT=**YES** | diff=easy test_set=A | DISAGREEING MODEL: **opus**
- GT malicious_events: Event 5142 (network share was added): admmig publishes a NEW SMB share `hidden-share$` (note the trailing `$` to make it a hidden/admin-style share) backed by the path `Users\admmig\Desktop`. T1135 Network Share Discovery prep / T1071 steal
- opus → **NO**: The events show a share creation (5142) and network file accesses (5145) by the account admmig accessing files within its own user profile (Users\admmig\Desktop) over the C$ administrative share. While administrative share access and a hidden-share$ creation in C:\TOOLS could warrant monitoring, the activity is self-scoped to the same use
- gpt  → **YES**: The logs show admmig creating a hidden share \\*\hidden-share$ mapped to C:\TOOLS\hidden-share$, followed shortly by access to the administrative share \\*\C$ from 10.23.23.9. The use of a hidden share and administrative share access in close sequence is suspicious and consistent with unauthorized staging or remote access activity.

### Artifact (3723 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>5142</EventID>
    <TimeCreated SystemTime="2020-07-11 17:16:20.9137798"/>
    <Computer>fs02.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-4230534742-2542757381-3142984815-1111</Data>
    <Data Name="SubjectUserName">admmig</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x202DAC8</Data>
    <Data Name="ShareName">\\*\hidden-share$</Data>
    <Data Name="ShareLocalPath">C:\TOOLS\hidden-share$</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>5145</EventID>
    <TimeCreated SystemTime="2020-07-11 17:16:42.5764840"/>
    <Computer>fs02.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-4230534742-2542757381-3142984815-1111</Data>
    <Data Name="SubjectUserName">admmig</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x3023704</Data>
    <Data Name="ObjectType">File</Data>
    <Data Name="IpAddress">10.23.23.9</Data>
    <Data Name="IpPort">60602</Data>
    <Data Name="ShareName">\\*\C$</Data>
    <Data Name="ShareLocalPath">\??\C:\</Data>
    <Data Name="RelativeTargetName">Users\admmig\Desktop\desktop.ini</Data>
    <Data Name="AccessMask">0x120089</Data>
    <Data Name="AccessList">%%1538, %%1541, %%4416, %%4419, %%4423, </Data>
    <Data Name="AccessReason">-</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>5145</EventID>
    <TimeCreated SystemTime="2020-07-11 17:16:42.5921031"/>
    <Computer>fs02.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-4230534742-2542757381-3142984815-1111</Data>
    <Data Name="SubjectUserName">admmig</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x3023704</Data>
    <Data Name="ObjectType">File</Data>
    <Data Name="IpAddress">10.23.23.9</Data>
    <Data Name="IpPort">60601</Data>
    <Data Name="ShareName">\\*\C$</Data>
    <Data Name="ShareLocalPath">\??\C:\</Data>
    <Data Name="RelativeTargetName">Users\admmig\Desktop</Data>
    <Data Name="AccessMask">0x100081</Data>
...[+1123 chars]
```

========================================================================================
## 17. ID5142-5143-Mimispool print share created and modified.evtx
- GT=**YES** | diff=easy test_set=A | DISAGREEING MODEL: **gpt**
- GT malicious_events: Event 5142 (network share added) for the `print$` share — and Event 5143 (network share permissions modified) on the same `print$`. T1574.002 DLL Side-Loading + T1547.012 Print Processors / PrintNightmare (CVE-2021-1675/-34527) abuse: the `
- opus → **YES**: The events show modification of the print$ share (C:\Windows\system32\spool\drivers) on a file server, with the share flags changed from 0x0 to 0x300, consistent with PrintNightmare-style driver/spooler abuse targeting the printer driver share. The pairing of a share-access (5142) immediately followed by a share-modification (5143) alteri
- gpt  → **NO**: The events show FS03$ creating and modifying the \\*\print$ share at C:\Windows\system32\spool\drivers with printer driver-related metadata. There are no processes, commands, registry changes, or suspicious network indicators in the provided logs, so this appears to be routine share activity rather than attack behavior.

### Artifact (1781 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>5142</EventID>
    <TimeCreated SystemTime="2021-10-27 10:21:55.2994312"/>
    <Computer>FS03.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">FS03$</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x3E7</Data>
    <Data Name="ShareName">\\*\print$</Data>
    <Data Name="ShareLocalPath">C:\Windows\system32\spool\drivers</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>5143</EventID>
    <TimeCreated SystemTime="2021-10-27 10:21:55.3150537"/>
    <Computer>FS03.offsec.lan</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">FS03$</Data>
    <Data Name="SubjectDomainName">OFFSEC</Data>
    <Data Name="SubjectLogonId">0x3E7</Data>
    <Data Name="ObjectType">Directory</Data>
    <Data Name="ShareName">\\*\print$</Data>
    <Data Name="ShareLocalPath">C:\Windows\system32\spool\drivers</Data>
    <Data Name="OldRemark">Printer Drivers</Data>
    <Data Name="NewRemark">Printer Drivers</Data>
    <Data Name="OldMaxUsers">0xFFFFFFFF</Data>
    <Data Name="NewMaxUsers">0xFFFFFFFF</Data>
    <Data Name="OldShareFlags">0x0</Data>
    <Data Name="NewShareFlags">0x300</Data>
    <Data Name="OldSD">O:BAG:BAD:(A;;0x1200a9;;;WD)(A;;FA;;;BA)</Data>
    <Data Name="NewSD">O:BAG:BAD:(A;;0x1200a9;;;WD)(A;;FA;;;BA)</Data>
  </EventData>
</Event>
```

========================================================================================
## 18. ID800-4103-4104-Domain group discovery via PowerShell.evtx
- GT=**YES** | diff=easy test_set=A | DISAGREEING MODEL: **gpt**
- GT malicious_events: Event 4104 (ScriptBlock logging): Get-ADGroup -Filter * | Get-ADGroupMember pipeline iterates every domain group and dumps members. T1069.002 Permission Groups Discovery: Domain Groups via the AD PowerShell module.
- opus → **YES**: The user OFFSEC\admmig ran Get-ADGroupMember to enumerate the membership of the privileged 'Administrators' group, returning high-value targets including Domain Admins, Enterprise Admins, and the Administrator account. This Active Directory reconnaissance of privileged group membership is a common precursor to privilege escalation and lat
- gpt  → **NO**: The logs show OFFSEC\admmig using PowerShell to run Get-ADGroupMember -Identity 'Administrators' and display the resulting group members. This is administrative group enumeration, but the events do not show follow-on modification, privilege escalation, persistence, or execution behavior indicating an attack.

### Artifact (10534 chars):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="PowerShell"/>
    <EventID>800</EventID>
    <TimeCreated SystemTime="2021-10-31 14:37:10.2460017"/>
    <Computer>jump01.offsec.lan</Computer>
    <Channel>Windows PowerShell</Channel>
  </System>
  <EventData>
    <Data>	DetailSequence=1
	DetailTotal=1

	SequenceNumber=343

	UserId=OFFSEC\admmig
	HostName=ConsoleHost
	HostVersion=5.1.14393.4350
	HostId=32afa6ab-c13e-4c81-91ed-8488f7e303ea
	HostApplication=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
	EngineVersion=5.1.14393.4350
	RunspaceId=be9cbd71-6464-43fd-94f7-af1594871f07
	PipelineId=84
	ScriptName=
	CommandLine=, CommandInvocation(PSConsoleHostReadline): "PSConsoleHostReadline"
</Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PowerShell"/>
    <EventID>4103</EventID>
    <TimeCreated SystemTime="2021-10-31 14:37:10.2466508"/>
    <Computer>jump01.offsec.lan</Computer>
    <Channel>Microsoft-Windows-PowerShell/Operational</Channel>
  </System>
  <EventData>
    <Data Name="ContextInfo">        Severity = Informational,         Host Name = ConsoleHost,         Host Version = 5.1.14393.4350,         Host ID = 32afa6ab-c13e-4c81-91ed-8488f7e303ea,         Host Application = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe,         Engine Version = 5.1.14393.4350,         Runspace ID = be9cbd71-6464-43fd-94f7-af1594871f07,         Pipeline ID = 84,         Command Name = PSConsoleHostReadline,         Command Type = Function,         Script Name = ,         Command Path = ,         Sequence Number = 344,         User = OFFSEC\admmig,         Connected User = ,         Shell ID = Microsoft.PowerShell, </Data>
    <Data Name="UserData"></Data>
    <Data Name="Payload">CommandInvocation(PSConsoleHostReadline): "PSConsoleHostReadline", </Data>
  </EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PowerShell"/>
    <EventID>4104</EventID>
    <TimeCreated SystemTime="2021-10-31 14:37:10.2474351"/>
    <Computer>jump01.offsec.lan</Computer>
    <Channel>Microsoft-Windows-PowerShell/Operational</Channel>
  </System>
  <EventData>
    <Data Name="MessageNumber">1</Data>
    <Data Name="MessageTotal">1</Data>
    <Data Name="ScriptBlockText">Get-ADGroupMember -Identity 'Administrators'</Data>
    <Data Name="ScriptBlockId">3a0c2649-0e3c-4282-8200-8037e1b4ccbe</Data>
    <Data Name="Path"></Data>
  </
...[+7934 chars]
```