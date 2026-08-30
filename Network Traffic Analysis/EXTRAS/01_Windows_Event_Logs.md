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
