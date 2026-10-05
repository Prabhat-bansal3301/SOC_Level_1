# Sysmon (System Monitor)

**Core idea:** Sysmon is a Windows Sysinternals service/driver giving far more detailed endpoint logging than default Windows Event Logs — process creation, network connections, file/registry changes — feeding into SIEM for anomaly detection.

## Overview

- Resident across reboots, starts early in boot process
- Logs stored at: `Applications and Services Logs/Microsoft/Windows/Sysmon/Operational`
- Best practice: forward events to a SIEM; viewable locally via Event Viewer too

## Config Files

- Requires a config file to define what/how to log
- 29 total Event ID types available
- Two common philosophies:
  - **Exclude-based** (e.g. SwiftOnSecurity) — filters out known-normal activity, reduces noise
  - **Include-based** (e.g. ION-Storm) — proactively flags specific behaviors
- No universal right answer — depends on SOC team preference and tuning

## Key Event IDs

| ID | Name | What it catches |
|---|---|---|
| 1 | Process Creation | New processes — suspicious binaries, typo-squatted names |
| 3 | Network Connection | Remote connections — suspicious binaries, known-bad ports |
| 7 | Image Loaded | DLLs loaded by processes — DLL injection/hijacking (high system load, use carefully) |
| 8 | CreateRemoteThread | Code injection into other processes |
| 11 | File Created | New/overwritten files — ransomware notes, dropped payloads |
| 12/13/14 | Registry Event | Registry changes — persistence, credential abuse |
| 15 | FileCreateStreamHash | Files in alternate data streams — malware hiding technique |
| 22 | DNS Event | DNS queries — exclude known-trusted domains, hunt the rest |

## Example Rules

**Event ID 1 — exclude known-benign process:**

    <ProcessCreate onmatch="exclude">
        <CommandLine condition="is">C:\Windows\system32\svchost.exe -k appmodel -p -s camsvc</CommandLine>
    </ProcessCreate>

**Event ID 3 — flag nmap.exe or Metasploit's default port:**

    <NetworkConnect onmatch="include">
        <Image condition="image">nmap.exe</Image>
        <DestinationPort name="Alert,Metasploit" condition="is">4444</DestinationPort>
    </NetworkConnect>

- Port 4444 = classic Metasploit default — same port flagged as C2 in the earlier perimeter-logs investigation

**Event ID 7 — DLLs loaded from Temp:**

    <ImageLoad onmatch="include">
        <ImageLoaded condition="contains">\Temp\</ImageLoaded>
    </ImageLoad>

**Event ID 8 — Cobalt Strike beacon pattern, or orphaned injection:**

    <CreateRemoteThread onmatch="include">
        <StartAddress name="Alert,Cobalt Strike" condition="end with">0B80</StartAddress>
        <SourceImage condition="contains">\</SourceImage>
    </CreateRemoteThread>

**Event ID 11 — ransomware note filename:**

    <FileCreate onmatch="include">
        <TargetFilename name="Alert,Ransomware" condition="contains">HELP_TO_SAVE_FILES</TargetFilename>
    </FileCreate>

**Event ID 12/13/14 — common persistence location:**

    <RegistryEvent onmatch="include">
        <TargetObject name="T1484" condition="contains">Windows\System\Scripts</TargetObject>
    </RegistryEvent>

**Event ID 15 — `.hta` in alternate data stream:**

    <FileCreateStreamHash onmatch="include">
        <TargetFilename condition="end with">.hta</TargetFilename>
    </FileCreateStreamHash>

**Event ID 22 — exclude trusted-domain DNS noise:**

    <DnsQuery onmatch="exclude">
        <QueryName condition="end with">.microsoft.com</QueryName>
    </DnsQuery>

## Why This Connects to Earlier Notes

- Event ID 3's `LogonId`-adjacent network data is exactly what the earlier Splunk subsearch note joined Sysmon EventID=1 against Security EventID=4624
- Port 4444 flagged here is the same port that showed up as C2 beaconing in the Initech perimeter-logs walkthrough — a recurring real-world indicator, not a coincidence

---

# Installing & Starting Sysmon

**Core idea:** Sysmon alone logs minimal detail — the config file is what makes it useful. Install binary + apply config = the actual working setup.

## Installation

- Download binary from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- Or get the full [Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)
- Or bulk-download via PowerShell:

        Download-SysInternalsTools C:\Sysinternals

## Config File

- Needed for granular control + detailed event tracing
- This room uses: [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) and the ION-Storm config
- Covered in the previous note: exclude-based (SwiftOnSecurity) vs. include-based (ION-Storm) philosophy

## Starting Sysmon

Run from an **Administrator** PowerShell/Command Prompt:

    Sysmon.exe -accepteula -i ..\Configurations\swift.xml

- `-accepteula` — accepts the EULA non-interactively
- `-i` — installs with the specified config file

Example output:

    Loading configuration file with schema version 4.10
    Sysmon schema version: 4.40
    Configuration file validated.
    Sysmon installed.
    SysmonDrv installed.
    Starting SysmonDrv.
    SysmonDrv started.
    Starting Sysmon...

## Viewing Events

- Event Viewer path: `Applications and Services Logs/Microsoft/Windows/Sysmon/Operational`

## Changing Config Later

- Swap configs anytime via uninstall/update + new config file
- Check `Sysmon.exe -?` / help menu for exact syntax

---

# Hunting with Sysmon: Best Practices & Filtering

**Core idea:** A well-tuned config does most of the filtering work before you even query — leaving you to focus on meaningful events instead of noise. CLI filtering (PowerShell) gives far more control than the Event Viewer GUI.

## Best Practices

- **Exclude > Include** — prioritize excluding known-normal events; reduces risk of accidentally missing something by over-filtering with includes
- **CLI > GUI** — `Get-WinEvent` or `wevutil.exe` give far more granular filtering than Event Viewer; CLI matters less once Sysmon feeds a SIEM
- **Know your environment first** — rules are only as good as your understanding of what "normal" actually looks like in your network

## Filtering via Event Viewer

- Limited control out of the box
- Main options: filter by Event ID, keywords, or raw XML (tedious, doesn't scale)
- Access via: **Actions → Filter Current Log**

## Filtering via PowerShell (Preferred)

Uses `Get-WinEvent` with XPath queries.

| Filter type | Syntax |
|---|---|
| By Event ID | `*/System/EventID=<ID>` |
| By XML attribute name | `*/EventData/Data[@Name="<Attribute>"]` |
| By event data value | `*/EventData/Data=<Data>` |

### Example: Hunt for Network Connections on Port 4444 (Metasploit default)

    Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=4444'

Run against a practice log:

    Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Metasploit.evtx -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=4444'

Output:

    ProviderName: Microsoft-Windows-Sysmon
    TimeCreated          Id  LevelDisplayName  Message
    1/5/2021 2:21:32 AM   3   Information       Network connection detected:...

- Combines Event ID 3 (Network Connection) + `DestinationPort` attribute + value `4444` in one query
- Same port 4444 flagged as suspicious in the earlier Sysmon config note and the Initech perimeter-logs C2 investigation — recurring indicator across this whole repo

## Reference
Deeper `Get-WinEvent`/`wevutil.exe` usage: [Windows Event Log room](https://tryhackme.com/room/windowseventlogs)

---

# Hunting Metasploit with Sysmon

**Core idea:** Meterpreter/Metasploit sessions leave a network fingerprint — default callback ports. Hunting for connections on those ports, then pivoting to the process behind them, is the core technique.

## What to Look For

- Metasploit default port: **4444** (also commonly 5555)
- Any connection to a known or unknown IP on these ports warrants investigation
- Also check for suspicious process creation alongside the connection
- Same method generalizes to other RATs/C2 beacons, not just Metasploit specifically

## Investigation Steps

1. Find the suspicious network connection (port 4444/5555)
2. Pull packet captures from that date for more context on the adversary
3. Check for suspicious processes created around the same time

## References

- [MITRE ATT&CK Software](https://attack.mitre.org/software/) — technique/tool details
- [Malware Common Ports Spreadsheet](https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo) — covered further in the Hunting Malware task

## Sysmon Config Rule (ION-Storm style)

    <RuleGroup name="" groupRelation="or">
        <NetworkConnect onmatch="include">
            <DestinationPort condition="is">4444</DestinationPort>
            <DestinationPort condition="is">5555</DestinationPort>
        </NetworkConnect>
    </RuleGroup>

- Uses Event ID 3, filters on `DestinationPort`
- Matching events include `ProcessID` and `Image` — your pivot points for further investigation

## Hunting via PowerShell

    Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=4444'

Example run:

    Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Metasploit.evtx -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=4444'

Output:

    ProviderName: Microsoft-Windows-Sysmon
    TimeCreated          Id  LevelDisplayName  Message
    1/5/2021 2:21:32 AM   3   Information       Network connection detected:...

### Query Breakdown
- `EventID=3` — network connection event
- `Data[@Name="DestinationPort"]` — targets the DestinationPort attribute
- `Data=4444` — the specific port value to match

Same filter structure as the config rule above — the config does it continuously at the agent level, this does it on-demand against a saved log.

---

# Hunting Mimikatz with Sysmon

**Core idea:** Mimikatz is mainly known for dumping LSASS memory (credentials). AV usually catches its known signature, but obfuscation/droppers can bypass that — so hunting its *behavior* (LSASS access) is more reliable than hunting its filename alone.

## References
[MITRE ATT&CK T1055](https://attack.mitre.org/techniques/T1055/) (Process Injection) and [S0002](https://attack.mitre.org/software/S0002/) (Mimikatz)

## Method 1: File Creation Detection (Weak)

- Just looks for files named `mimikatz`
- Simple, catches things that slipped past AV, but easily evaded by renaming the binary
- Not the preferred technique — behavioral detection (below) is stronger

Config:

    <RuleGroup name="" groupRelation="or">
        <FileCreate onmatch="include">
            <TargetFileName condition="contains">mimikatz</TargetFileName>
        </FileCreate>
    </RuleGroup>

## Method 2: Abnormal LSASS Behavior (Preferred)

- Uses Event ID 10 (`ProcessAccess`)
- Any process accessing `lsass.exe` other than `svchost.exe` is suspicious
- Sysmon provides the source process's file path — direct investigation lead

**Step 1 — include all LSASS access:**

    <RuleGroup name="" groupRelation="or">
        <ProcessAccess onmatch="include">
            <TargetImage condition="image">lsass.exe</TargetImage>
        </ProcessAccess>
    </RuleGroup>

- Problem: floods with legitimate `svchost.exe` noise

**Step 2 — exclude svchost.exe source, keep LSASS target:**

    <RuleGroup name="" groupRelation="or">
        <ProcessAccess onmatch="exclude">
            <SourceImage condition="image">svchost.exe</SourceImage>
        </ProcessAccess>
        <ProcessAccess onmatch="include">
            <TargetImage condition="image">lsass.exe</TargetImage>
        </ProcessAccess>
    </RuleGroup>

- Dramatically cuts noise, leaves mostly anomalies
- Reusable pattern: exclude the known-noisy source first, then include the sensitive target — applicable across many Sysmon hunts, not just this one

## Hunting via PowerShell

    Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=10 and */EventData/Data[@Name="TargetImage"] and */EventData/Data="C:\Windows\system32\lsass.exe"'

Example run:

    Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Mimikatz.evtx -FilterXPath '*/System/EventID=10 and */EventData/Data[@Name="TargetImage"] and */EventData/Data="C:\Windows\system32\lsass.exe"'

Output:

    ProviderName: Microsoft-Windows-Sysmon
    TimeCreated          Id  LevelDisplayName  Message
    1/5/2021 3:22:52 AM  10   Information       Process accessed:...

- A well-tuned config does most of the filtering at the source — the PowerShell query only needs light additional filtering on top

---

# Hunting RATs & Backdoors with Sysmon

**Core idea:** Same port-hunting technique as Metasploit hunting, applied to RATs/backdoors. The real lesson here is about config risk: exclusion rules can create blind spots attackers actively exploit.

## RATs vs. Other Payloads

- RAT = Remote Access Trojan — remote access payload with built-in AV/detection evasion
- Typically client-server model with an admin interface
- Examples: Xeexe, Quasar
- Different from something like MSFVenom-generated payloads in terms of evasion tooling

## Methodology: Hypothesis-Based Hunting

1. Identify the malware/threat you're hunting for
2. Identify how to modify the config to detect it
3. (This task covers one method: detecting open back-connect ports)

## Config Example (ION-Storm style)

    <RuleGroup name="" groupRelation="or">
        <NetworkConnect onmatch="include">
            <DestinationPort condition="is">1034</DestinationPort>
            <DestinationPort condition="is">1604</DestinationPort>
        </NetworkConnect>
        <NetworkConnect onmatch="exclude">
            <Image condition="image">OneDrive.exe</Image>
        </NetworkConnect>
    </RuleGroup>

- Includes known-suspicious ports (1034, 1604)
- Excludes known-noisy legitimate traffic (OneDrive)

## Critical Warning: Blind Exclusions Are Dangerous

- The ION-Storm config excludes **port 53** (DNS) by default
- Attackers increasingly use port 53 for malware/C2 — using this config as-is **blindly misses that traffic**
- Direct real-world case: a custom RAT operating on port **8080** wouldn't be caught by the 1034/1604-only include rule above unless 8080 is explicitly added
- Lesson: never deploy a downloaded config without understanding exactly what each exclude/include rule does — connects directly to the earlier note's "exclude > include" best practice, but exclusions still need active review, not blind trust

## Hunting via PowerShell

    Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=<Port>'

Example — hunting port 8080:

    Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Rats.evtx -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=8080'

Output:

    ProviderName: Microsoft-Windows-Sysmon
    TimeCreated          Id  LevelDisplayName  Message
    1/5/2021 4:44:35 AM   3   Information       Network connection detected:...
    1/5/2021 4:44:31 AM   3   Information       Network connection detected:...
    1/5/2021 4:44:27 AM   3   Information       Network connection detected:...
    1/5/2021 4:44:24 AM   3   Information       Network connection detected:...
    1/5/2021 4:44:20 AM   3   Information       Network connection detected:...

- Multiple hits in quick succession at this port — consistent with a RAT maintaining an active C2 connection, same beaconing pattern flagged throughout earlier notes

---

# Hunting Persistence with Sysmon

**Core idea:** Persistence survives reboots by planting itself where Windows automatically runs things — startup folders and registry Run keys. Both are covered by File Creation and Registry Modification events.

## Startup Folder Persistence

[MITRE ATT&CK T1547](https://attack.mitre.org/techniques/T1547/)

Config (SwiftOnSecurity):

    <RuleGroup name="" groupRelation="or">
        <FileCreate onmatch="include">
            <TargetFilename name="T1023" condition="contains">\Start Menu</TargetFilename>
            <TargetFilename name="T1165" condition="contains">\Startup\</TargetFilename>
        </FileCreate>
    </RuleGroup>

- Flags any file placed in `\Startup\` or `\Start Menu`
- Example finding: `persist.exe` dropped in Startup folder
- Real attackers rarely name files this obviously — but **any** change to these locations warrants investigation regardless of filename
- Can filter directly by **Rule Name `T1023`** to skip past noise

## Registry Run Key Persistence

[MITRE ATT&CK T1112](https://attack.mitre.org/techniques/T1112/)

Config (SwiftOnSecurity):

    <RuleGroup name="" groupRelation="or">
        <RegistryEvent onmatch="include">
            <TargetObject name="T1060,RunKey" condition="contains">CurrentVersion\Run</TargetObject>
            <TargetObject name="T1484" condition="contains">Group Policy\Scripts</TargetObject>
            <TargetObject name="T1060" condition="contains">CurrentVersion\Windows\Run</TargetObject>
        </RegistryEvent>
    </RuleGroup>

- Flags modifications to `CurrentVersion\Run`, `CurrentVersion\Windows\Run`, and Group Policy script locations
- Example finding: `malicious.exe` added at `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Persistence`
- Corresponding binary location: `%windir%\System32\malicious.exe`
- Can filter by **Rule Name `T1060`** to isolate this pattern

## Investigation Steps

1. Confirm the anomaly (file in startup location, or new registry Run key)
2. Check the file's actual location and binary (`%windir%\System32\...`, etc.)
3. Check the registry key itself where the value was added
4. Both leads converge on the same artifact — the planted binary

## Why This Matters

Both techniques exploit legitimate Windows auto-run mechanisms, not a vulnerability — which is exactly why they're hard to prevent outright and why *detection* (not just prevention) is the realistic defense here.

---

# Hunting Evasion Techniques with Sysmon

**Core idea:** Malware hides itself (Alternate Data Streams) or injects into legitimate processes (remote threads) to dodge detection. Sysmon has dedicated event IDs for both.

## Evasion Technique Categories (Overview)

Alternate Data Streams, Injections (thread hijacking, PE injection, DLL injection), Masquerading, Packing/Compression, Recompiling, Obfuscation, Anti-Reversing. This note focuses on ADS and DLL/thread injection.

References: [MITRE T1564](https://attack.mitre.org/techniques/T1564/) (Hide Artifacts), [MITRE T1055](https://attack.mitre.org/techniques/T1055/) (Process Injection)

## Alternate Data Streams (ADS)

- Malware hides files by saving them in an NTFS stream separate from `$DATA`, evading normal inspection
- Detected via Event ID 15 (`FileCreateStreamHash`) — hashes/logs NTFS streams

Config (SwiftOnSecurity):

    <RuleGroup name="" groupRelation="or">
        <FileCreateStreamHash onmatch="include">
            <TargetFilename condition="contains">Downloads</TargetFilename>
            <TargetFilename condition="contains">Temp\7z</TargetFilename>
            <TargetFilename condition="ends with">.hta</TargetFilename>
            <TargetFilename condition="ends with">.bat</TargetFilename>
        </FileCreateStreamHash>
    </RuleGroup>

- Targets high-risk locations (Downloads, Temp\7z) and high-risk extensions (.hta, .bat)

## Remote Thread Injection

- Uses Windows API `CreateRemoteThread`, often paired with `OpenThread`/`ResumeThread`
- Underlies DLL injection, thread hijacking, process hollowing
- Detected via Event ID 8 (`CreateRemoteThread`)

Config (SwiftOnSecurity):

    <RuleGroup name="" groupRelation="or">
        <CreateRemoteThread onmatch="exclude">
            <SourceImage condition="is">C:\Windows\system32\svchost.exe</SourceImage>
            <TargetImage condition="is">C:\Program Files (x86)\Google\Chrome\Application\chrome.exe</TargetImage>
        </CreateRemoteThread>
    </RuleGroup>

- Exclude-only rule, no specific include attributes — deliberately broad to catch anything not explicitly known-safe
- Excludes two common legitimate sources of remote threads (svchost → normal OS behavior, chrome → browser's own internal thread use)

## Hunting via PowerShell

Remote thread creation:

    Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=8'

Example:

    Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Detecting_RemoteThreads.evtx -FilterXPath '*/System/EventID=8'

Output:

    ProviderName: Microsoft-Windows-Sysmon
    TimeCreated          Id  LevelDisplayName  Message
    7/3/2019 8:39:30 PM   8   Information      CreateRemoteThread detected:...
    (x5, same timestamp)

- Only `EventID` filtering needed — the config's exclude rule already did the heavy lifting upstream
- Multiple hits at the exact same timestamp is itself notable — suggests automated/scripted injection rather than a single manual action
