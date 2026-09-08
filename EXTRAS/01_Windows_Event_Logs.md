## Windows Event Logs — Purpose & Blue Team Use

### Two Primary Use Cases

#### 1. System Troubleshooting (IT/Admin)
- OS writes messages to logs by default
- Diagnose issues on endpoints and servers
- Understand what led to a problem
- Essential for systems with little user interaction (servers)

#### 2. Security Investigation (Blue Team)
- Correlate log entries from **multiple sources**
- Statistical analysis across different servers
- Identify seemingly unrelated events that form an attack pattern
- Feed into SIEM for automated correlation and alerting

---

### The SIEM Connection

```
Multiple endpoints → generate event logs
    ↓
Logs forwarded to SIEM (Splunk, Elastic, etc.)
    ↓
SIEM correlates events across all sources
    ↓
Patterns emerge that individual logs wouldn't reveal
    ↓
Alerts generated → SOC analyst investigates
```

---

### Why Correlation Matters

**Single log (limited view):**
```
Server A: Failed login at 03:00
Server B: New admin account created at 03:05
Server C: Scheduled task created at 03:07
```

**Correlated view (full picture):**
```
03:00 — Brute force → 03:05 — Persistence via new account → 03:07 — Persistence via scheduled task
= Active attack in progress
```

> Individual logs = puzzle pieces.
> Correlation = the full picture.
> SIEM = the tool that assembles the pieces automatically.

---

### Key Takeaway
> Event logs serve both operational and security purposes.
> For blue teamers, the real power is in **cross-source correlation** — not individual log review.
> This is exactly why SIEM exists and why feeding Windows Event Logs into it is essential.

## Windows Event Logs — Fundamentals

### Log File Format
- Binary format: `.evt` (legacy) or `.evtx` (current)
- Location: `C:\Windows\System32\winevt\Logs`
- Not readable as text — requires Event Viewer, wevtutil, or PowerShell

---

### Windows Event Log Categories

| Log Type | Contains |
|----------|---------|
| **System** | OS events — hardware changes, drivers, system changes |
| **Security** | Logon/logoff, audit policy events — key for security investigation |
| **Application** | App errors, events, warnings |
| **Directory Service** | Active Directory changes (domain controllers) |
| **File Replication Service** | Group Policy and logon script sharing to DCs |
| **DNS Event Logs** | Domain events, DNS mapping |
| **Custom Logs** | Application-specific custom data storage |

---

### Five Event Types

| Type | Description | Example |
|------|-------------|---------|
| **Error** | Significant problem — loss of data/functionality | Service fails to load at startup |
| **Warning** | Possible future problem — not immediately critical | Low disk space |
| **Information** | Successful operation of app/driver/service | Network driver loaded successfully |
| **Success Audit** | Successful audited security access | User successfully logged on |
| **Failure Audit** | Failed audited security access | User failed to access network drive |

---

### Three Ways to Access Event Logs

```
1. Event Viewer      → GUI — eventvwr.msc
2. wevtutil.exe      → Command-line tool
3. Get-WinEvent      → PowerShell cmdlet
```

---

### Event Viewer Interface

<img width="1200" height="682" alt="Event viewer" src="https://github.com/user-attachments/assets/6af6189d-8f61-453e-981b-37cda1850e40" />

```
Left pane:    Hierarchical tree of log providers
Middle pane:  Events for selected provider (top) + event details (bottom)
Right pane:   Actions panel
```

**Open Event Viewer:**
```
Right-click Windows icon → Event Viewer
OR
Run: eventvwr.msc
```

**PowerShell Operational logs:**

<img width="644" height="581" alt="operational-properties" src="https://github.com/user-attachments/assets/92d7c572-f500-4b1b-91ab-b58494992267" />

```
Applications and Services Logs → Microsoft → Windows → PowerShell → Operational
```

---

### Event Columns in Middle Pane

| Column | Description |
|--------|-------------|
| **Level** | Event type (Error, Warning, Information, etc.) |
| **Date and Time** | When event was logged |
| **Source** | Software that generated the event |
| **Event ID** | Numerical ID — maps to specific operation (not unique across log sources) |
| **Task Category** | Event category for filtering |

> Event ID 4103 in PowerShell log ≠ Event ID 4103 in Security log.
> Event IDs are source-specific.

---

### Event Detail Tabs

| Tab | Shows |
|-----|-------|
| **General** | Rendered human-readable event data |
| **Details → Friendly view** | Structured key-value pairs |
| **Details → XML view** | Raw XML format |

---

### Key Actions Pane Features

| Action | Purpose |
|--------|---------|
| **Open Saved Log** | Analyze logs from remote/offline machines |
| **Create Custom View** | Filter by log, source, event ID across multiple logs |
| **Filter Current Log** | Filter current log only by level, event ID, time |
| **Clear Log** | Remove all events — legitimate use: maintenance; malicious use: cover tracks |

---

### Log Rotation
- Set max log size in Properties
- Actions when full: Overwrite oldest, Archive, Do not overwrite
- Critical decision: how long to retain logs before overwriting

> Clearing logs = common attacker anti-forensics technique.
> Monitor for Event ID 1102 (Security log cleared) and 104 (System log cleared).

---

## wevtutil.exe — Windows Event Log CLI Tool

### What is wevtutil?
Command-line tool for querying, exporting, archiving, and clearing Windows Event Logs.
Useful for scripting and automating log analysis.

```cmd
wevtutil.exe /?
```

---

### Commands Reference

| Short | Long | Purpose |
|-------|------|---------|
| `el` | `enum-logs` | List all log names |
| `gl` | `get-log` | Get log configuration info |
| `sl` | `set-log` | Modify log configuration |
| `ep` | `enum-publishers` | List event publishers |
| `gp` | `get-publisher` | Get publisher configuration |
| `im` | `install-manifest` | Install event publishers from manifest |
| `um` | `uninstall-manifest` | Uninstall event publishers |
| `qe` | `query-events` | **Query events from log or file** |
| `gli` | `get-log-info` | Get log status info |
| `epl` | `export-log` | Export a log |
| `al` | `archive-log` | Archive an exported log |
| `cl` | `clear-log` | Clear a log |

---

### Common Options

| Option | Purpose |
|--------|---------|
| `/r:VALUE` | Run on remote computer |
| `/u:VALUE` | Specify username (domain\user) |
| `/p:VALUE` | Password for user |
| `/a:[Default\|Negotiate\|Kerberos\|NTLM]` | Authentication type for remote |
| `/uni:[true\|false]` | Display output in Unicode |

---

### Get Help for Specific Command
```cmd
wevtutil COMMAND /?

# Example
wevtutil qe /?
```

---

### Common Usage Examples

```cmd
# List all available logs
wevtutil el

# Get info about Security log
wevtutil gl Security

# Query last 10 events from Security log
wevtutil qe Security /c:10 /rd:true /f:text

# Query by Event ID (e.g. 4624 - successful logon)
wevtutil qe Security /q:"*[System[EventID=4624]]" /f:text

# Export Security log
wevtutil epl Security C:\Backup\security.evtx

# Clear a log (use with caution)
wevtutil cl Security

# Query events from saved log file
wevtutil qe C:\logs\security.evtx /lf:true /f:text
```

---

### Key Flags for qe (query-events)

| Flag | Purpose |
|------|---------|
| `/c:N` | Max number of events to return |
| `/rd:true` | Read events newest first (reverse direction) |
| `/f:text` | Output format (text, xml) |
| `/q:"XPath"` | XPath filter query |
| `/lf:true` | Read from log file (not live log) |

---

### Docs
🔗 https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil

---

## Get-WinEvent — PowerShell Event Log Cmdlet

### What is Get-WinEvent?
PowerShell cmdlet for querying event logs and event tracing files.
Works on local and remote computers.
Replaces the older `Get-EventLog` cmdlet.

🔗 https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent

---

### Common Commands

```powershell
# List all available logs
Get-WinEvent -ListLog *

# List all event log providers + their associated logs
Get-WinEvent -ListProvider *

# Get events from a specific log
Get-WinEvent -LogName Application

# Get events from remote computer
Get-WinEvent -LogName Security -ComputerName RemotePC
```

---

### Filtering — Three Methods

#### Method 1: Where-Object (simple but slow for large logs)
```powershell
Get-WinEvent -LogName Application | Where-Object { $_.ProviderName -Match 'WLMS' }
```

#### Method 2: FilterHashtable (recommended — most efficient)
```powershell
Get-WinEvent -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = 'WLMS'
}
```

#### Method 3: XPath query
```powershell
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]]"
```

---

### FilterHashtable Syntax

```powershell
@{ <name> = <value>; [<name> = <value>] ... }
```

**Rules:**
- Start with `@`
- Enclose in `{ }`
- Separate key/value with `=`
- Use `;` between pairs OR new lines (no semicolon needed with new lines)

**Filterable fields:**

| Key | Example |
|-----|---------|
| `LogName` | `'Security'` |
| `ProviderName` | `'Microsoft-Windows-Security-Auditing'` |
| `Id` | `4624` |
| `Level` | `2` (Error), `3` (Warning), `4` (Info) |
| `StartTime` | `'2024-01-01'` |
| `EndTime` | `'2024-01-31'` |
| `Keywords` | `-9218868437227405312` (Audit Failure) |

---

### Practical Examples

```powershell
# Get successful logon events (Event ID 4624)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = 4624
}

# Get events in a time range
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    StartTime = '2024-01-01'
    EndTime   = '2024-01-07'
    Id        = 4625
}

# Get last 20 Security events
Get-WinEvent -LogName Security -MaxEvents 20

# Format output as table
Get-WinEvent -LogName Security -MaxEvents 10 | Format-Table TimeCreated, Id, Message -AutoSize

# Get from saved .evtx file
Get-WinEvent -Path C:\logs\security.evtx

# Count events matching filter
(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625}).Count
```

---

### Key Properties of Event Objects

| Property | Description |
|----------|-------------|
| `Id` | Event ID |
| `TimeCreated` | Timestamp |
| `LevelDisplayName` | Error/Warning/Information |
| `ProviderName` | Source of the event |
| `Message` | Full event message |
| `MachineName` | Computer that generated it |

---

### Why FilterHashtable Over Where-Object

```
Where-Object:     Get ALL events → filter in PowerShell pipeline (slow)
FilterHashtable:  Filter at source → only return matching events (fast)

For large logs (Security log with 100,000+ events):
→ Always use FilterHashtable
```

---

## XPath Queries for Windows Event Logs

### What is XPath?
W3C standard for addressing parts of XML documents.
Windows Event Logs support a subset of XPath 1.0.
Works with both `wevtutil.exe` and `Get-WinEvent`.

---

### XPath Query Structure

```
* or Event                 ← starting point
    └── System             ← XML section
         └── Element=Value ← filter condition
```

**Build from XML View in Event Viewer:**
```
Event Viewer → select event → Details tab → XML View
→ Use XML structure to build your XPath query
```

---

### XPath Query Examples

#### Filter by Event ID
```powershell
# Get-WinEvent
Get-WinEvent -LogName Application -FilterXPath '*/System/EventID=100'

# wevtutil
wevtutil.exe qe Application /q:*/System[EventID=100] /f:text /c:1
```

#### Filter by Provider Name (using attribute)
```powershell
Get-WinEvent -LogName Application -FilterXPath '*/System/Provider[@Name="WLMS"]'
```

#### Combine Two Conditions (AND)
```powershell
Get-WinEvent -LogName Application -FilterXPath '*/System/EventID=101 and */System/Provider[@Name="WLMS"]'
```

#### Filter EventData fields
```powershell
# Filter by TargetUserName in EventData
Get-WinEvent -LogName Security -FilterXPath '*/EventData/Data[@Name="TargetUserName"]="System"' -MaxEvents 1
```

#### Filter by Level and Time (last 24 hours)
```xpath
*[System[(Level <= 3) and TimeCreated[timediff(@SystemTime) <= 86400000]]]
```

---

### XPath Syntax Rules

| Rule | Detail |
|------|--------|
| Start with | `*` or `Event` |
| Section separator | `/` |
| Attribute filter | `[@Name="value"]` |
| Combine conditions | `and` |
| EventData fields | `*/EventData/Data[@Name="fieldname"]="value"` |

---

### Building XPath Step by Step

```
Goal: Find Event ID 4624 where TargetUserName = "admin"

Step 1: Start       →  *
Step 2: Add System  →  */System/
Step 3: Add EventID →  */System/EventID=4624
Step 4: Add EventData condition:
        */EventData/Data[@Name="TargetUserName"]="admin"
Step 5: Combine:
        */System/EventID=4624 and */EventData/Data[@Name="TargetUserName"]="admin"
```

```powershell
Get-WinEvent -LogName Security -FilterXPath '*/System/EventID=4624 and */EventData/Data[@Name="TargetUserName"]="admin"'
```

---

### wevtutil Additional Flags Used with XPath

| Flag | Purpose |
|------|---------|
| `/f:text` | Output as plain text (not XML) |
| `/c:1` | Return only 1 event |
| `/q:` | XPath query string |

---

### Quick Reference

```powershell
# Event ID filter
'*/System/EventID=4624'

# Provider filter
'*/System/Provider[@Name="Microsoft-Windows-Security-Auditing"]'

# EventData field filter
'*/EventData/Data[@Name="TargetUserName"]="john"'

# Combined
'*/System/EventID=4625 and */EventData/Data[@Name="TargetUserName"]="admin"'
```

🔗 XPath Reference: https://docs.microsoft.com/en-us/previous-versions/dotnet/netframework-4.0/ms256115

---

## Windows Event Log — Key Event IDs & Resources

### Important Event IDs to Monitor

| Event ID | Log | Description |
|----------|-----|-------------|
| **4624** | Security | Successful logon |
| **4625** | Security | Failed logon |
| **4634** | Security | Logoff |
| **4648** | Security | Logon with explicit credentials |
| **4688** | Security | New process created (with command line if enabled) |
| **4698** | Security | Scheduled task created |
| **4702** | Security | Scheduled task updated |
| **4720** | Security | User account created |
| **4726** | Security | User account deleted |
| **4732** | Security | User added to privileged group |
| **4756** | Security | User added to universal security group |
| **1102** | Security | Security audit log cleared |
| **104** | System | System log cleared |
| **7045** | System | New service installed |
| **2006/2033** | — | Firewall rule deleted |

---

### Features to Enable (Not on by Default)

#### PowerShell Logging
```
Local Computer Policy
→ Computer Configuration
→ Administrative Templates
→ Windows Components
→ Windows PowerShell
```

**PowerShell Event IDs:**
| ID | Description |
|----|-------------|
| 4103 | Module logging — pipeline execution details |
| 4104 | Script block logging — full script content |
| 4105 | Script start |
| 4106 | Script stop |

#### Audit Process Creation (Event ID 4688)
```
Local Computer Policy
→ Computer Configuration
→ Administrative Templates
→ System
→ Audit Process Creation
```
Enables command-line auditing — shows exactly what commands were run.

---

### Key Resources

| Resource | Link |
|----------|------|
| Windows Logging Cheat Sheet | [malwarearchaeology.com](https://www.malwarearchaeology.com/cheat-sheets) |
| NSA — Spotting the Adversary | [web.archive.org](https://web.archive.org/web/20190115215749/https://apps.nsa.gov/iaarchive/customcf/openAttachment.cfm?FilePath=/iad/library/ia-guidance/security-configuration/applications/assets/public/upload/Spotting-the-Adversary-with-Windows-Event-Log-Monitoring.pdf&WpKes=aF6woL7fQp3dJiqyJL2LenrLxuHC7ztGtVNK3x) |
| MITRE ATT&CK | [attack.mitre.org](https://attack.mitre.org/) |
| Account Manipulation T1098 | [attack.mitre.org/techniques/T1098](https://attack.mitre.org/techniques/T1098/) |
| Events to Monitor (AD) | [docs.microsoft.com](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor) |
| Win10 Security Auditing Reference | [microsoft.com](https://www.microsoft.com/en-us/download/confirmation.aspx?id=52630) |
| PowerShell Logging | [docs.microsoft.com](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows) |
| FireEye PS Logging | [fireeye.com](https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html) |

---

### MITRE ATT&CK for Event ID Mapping

Each ATT&CK technique page includes:
- **Detection tips** — which event IDs to monitor
- **Mitigation tips** — how to prevent the technique
- **Procedure examples** — real-world usage by threat groups

**Workflow:**
```
Receive alert/IOC
    ↓
Map to MITRE ATT&CK technique
    ↓
Check detection section for relevant Event IDs
    ↓
Query logs with wevtutil/Get-WinEvent/SIEM
    ↓
Correlate with other events → build attack timeline
```

---

### Detection Quick Reference

| Attacker Action | Event ID to Hunt |
|----------------|-----------------|
| New service installed | 7045 (System) |
| Firewall rule deleted | 2006/2033 |
| Audit log cleared | 1102 (Security), 104 (System) |
| New scheduled task | 4698 (Security) |
| User added to admin group | 4732 (Security) |
| Process execution | 4688 (Security — must enable) |
| PowerShell execution | 4104 (PS Script Block) |
| Credential access | 4624/4625 (Security) |
