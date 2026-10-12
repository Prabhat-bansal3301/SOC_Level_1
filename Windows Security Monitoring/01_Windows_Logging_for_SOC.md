# Windows Event Logging: Overview

Windows logs nearly everything an OS does, but the logs are stored in binary and take real knowledge to read.

## Why Logging Matters for a SOC

| Use | How logs help |
|---|---|
| Incident Response | Show when and how the attack occurred |
| Threat Hunting | Searchable evidence of malicious activity |
| Alerting and Triage | Building block of every alert and detection rule |

- Every recorded event is a "log": time, action details, and the user behind it

## Where Logs Live

    C:\Windows\System32\winevt\Logs

- Stored in binary `.evtx` format, so you can't read them in a text editor
- One EVTX file per log category:
  - **Application:** events from user-mode apps (IIS, MS SQL)
  - **Security:** logon attempts, process activity, user management

## Reading Logs: Event Viewer

Open it with either:
- Windows Search: "Event Viewer"
- `Win + R`, type `eventvwr`, press Enter

| Part | What it is |
|---|---|
| 1. Log Sources | One item in the left panel per EVTX file |
| 2. Log List | One row per event; sortable by Keywords, Date and Time, Event ID |
| 3. Log Details | Full content in plaintext or XML (Details tab) |
| 4. Filters Menu | "Filter Current Log" and "Find" buttons |

Log list columns:
- **Keywords:** success or failure for some events
- **Date and Time:** system time, **not UTC**
- **Event ID:** unique number per event type (e.g. failed login is always `4625`)

## What Is Logged

- Over [500 event IDs](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/) for Security logs alone, many thousands in total
- Not all events are logged by default
- Not all events are properly documented
- So focus on the most useful IDs for daily SOC work

## Detection Tips

- System time vs UTC: when correlating with other sources (firewall, SIEM), convert timestamps first, or the timeline will be off
- Event IDs are the fastest search handle: memorize the common ones (`4624` logon, `4625` failed logon)
- Default logging gaps are a blind spot: confirm what's actually enabled before trusting "no events found"
- Same blind-spot lesson as the Sysmon notes: Sysmon adds the process and network detail default Windows logs lack

---

# Windows Security Events: 4624 and 4625

The Security log is the most valuable Windows log enabled by default, and Successful Logon (4624) and Failed Logon (4625) are the two to learn first.

## Event Comparison

| Event ID | Name | Use | Logged on | Limitation |
|---|---|---|---|---|
| 4624 | Successful Logon | Detect suspicious RDP/network logins, find the attack starting point | The machine being accessed | Noisy: hundreds per minute on busy servers |
| 4625 | Failed Logon | Detect brute force, password spraying, vulnerability scanning | The machine being accessed | Inconsistent: caveats can mislead your reading |

## Fields to Check First

The field image wasn't included, so this list is from general knowledge:

- Logon Type
- Account Name
- Workstation Name
- Source Network Address
- Logon ID

Full field list: [Event ID Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)

## Logon Types

Only 3 and 10 are in the lesson. The rest are from general knowledge:

| Type | Meaning | Note |
|---|---|---|
| 2 | Interactive | Local keyboard logon |
| 3 | Network | Also RDP when NLA is enabled |
| 4 | Batch | Scheduled tasks |
| 5 | Service | Service startup |
| 7 | Unlock | Workstation unlocked |
| 10 | RemoteInteractive | RDP without NLA |
| 11 | CachedInteractive | Cached domain credentials |

## Workflow 1: Detect RDP Brute Force


1. Open Security logs, filter for Event ID `4625`
2. Look for Logon Type `3` or `10`
   - Type 3: most modern systems (NLA enabled by default)
   - Type 10: older or misconfigured systems (no NLA)
3. Every hit deserves attention; main red flags:

| Red flag | Indicates |
|---|---|
| Many different usernames (`admin`, `helpdesk`, `cctv`) | Password spraying |
| Many failures on one account, usually `Administrator` | Brute force |
| Workstation Name not matching corporate pattern (`kali` vs `THM-PC-06`) | Attacker machine |
| Unexpected source IP (e.g. a printer hitting a Windows Server) | Rogue or compromised device |

## Workflow 2: Analyse RDP Logons

<img width="1900" height="742" alt="Structure of 4624" src="https://github.com/user-attachments/assets/2188ac23-56d4-45ef-ba4c-97e363095a9c" />

1. Open Security logs, filter for Event ID `4624`
2. Look for Logon Type `10` (RDP)
3. With NLA on, every type 10 is preceded by a type 3 `4624`
   - The real Workstation Name is in the preceding type 3 event
4. Red flags: a preceding brute force, or a suspicious source IP/hostname
5. If you assume the login was malicious, pivot on the **Logon ID** (e.g. `0x5D6AC`)
   - Unique session identifier
   - Save it: it links everything the session did afterward

## Detection Tips

- Spraying vs brute force: many users with few tries each is spraying, one user with many tries is brute force
- Brute force that ends in a `4624` from the same source IP means it worked, so escalate
- Logon ID is the join key, the same idea as the Splunk subsearch note (`LogonId` linking Sysmon Event 1 to Security 4624)
- Count failures per source in Splunk (field names may differ in your data):

        index=windowslogs EventID=4625 | stats count by IpAddress, TargetUserName | sort - count

---

# User Management Events (4720, 4722, 4725, 4723/4724, 4732...)

Account creation, password resets, and group changes leave a full history of any user account, and attackers use all three for persistence and recovery sabotage.

## Event IDs

| Event ID | Description | Malicious use |
|---|---|---|
| 4720 / 4722 / 4738 | Account created / enabled / changed | Backdoor account, or re-enabling an old one to avoid notice |
| 4725 / 4726 | Account disabled / deleted | Disabling privileged SOC accounts to slow defenders |
| 4723 / 4724 | User changed password / password was reset | Reset a password, then log in as that user |
| 4732 / 4733 | Member added to / removed from a security group | Adding a backdoor account to `Administrators` |

## Event Structure

| Part | Meaning | Notes |
|---|---|---|
| Subject | Who did the action | Has a **Logon ID**, so you can link back to the 4624 logon |
| Object | The target (named `New Account`, `Member`, or `Target Account` depending on the ID) | Always means the target |
| Details | What changed | Target group for 4732/4733; user attributes for 4720 |

## Example Chain (Same Attacker Session)

<img width="1538" height="735" alt="Structure of User Management Events" src="https://github.com/user-attachments/assets/0d8eea98-0cab-4ad0-baea-8b6a97ec132e" />


- All three events share Logon ID `0x2C7896`, so one session did everything
- Create-then-add-to-Administrators within about 26 seconds is the classic backdoor admin pattern
- The 4724 an hour later with the same Logon ID means the session stayed open
- In the 4732 event, `Account Name` shows `-` but the `Security ID` still identifies `itsupport`, so read the Security ID field

## Hunt: Backdoored Users

1. Open Security logs, filter for Event IDs `4720` and `4732`
2. Review every event manually
3. Red flags:
   - No one in IT can confirm the action
   - Done outside working hours or on weekends
   - Subject name is unknown or unexpected (e.g. `adm.old.2008` creating users)
   - Target name breaks the naming pattern (`backup` instead of `thm_svc_backup`)
4. If malicious, pivot on the Logon ID:
   - Copy it from the 4720 / 4732 event
   - Find the 4624 login with the same Logon ID
   - Continue with the 4624 / 4625 workflows

## Real-World Pattern

- Ransomware actors reset all accounts to one password to slow recovery
- Other attackers created a new admin account for persistence
- Unknown accounts like `svc_sysrestore` get ignored ("probably Windows stuff"), which is how backdoors survive; verify any unknown account against IT records

## Detection Tips

- Alert on every 4732 into `Administrators`, since legitimate adds are rare
- Not in the lesson (general knowledge): domain environments also use `4728` / `4756` for global / universal group adds
- Logon ID is the join key again, same as the Splunk subsearch note
- Splunk starting point (field names may differ in your data):

        index=windowslogs EventID IN (4720, 4732, 4724) | table _time EventID SubjectUserName SubjectLogonId TargetUserName

---

# Process Monitoring: Security 4688 vs Sysmon Event ID 1

Authentication logs show who got breached; process monitoring shows how, since almost every attack has to launch some process on the endpoint.

## Two Ways to Log Process Creation

| Event | Source | Purpose | Limitation |
|---|---|---|---|
| 4688 | Security log | Logs each new process with command line and parent details | Disabled by default; must be enabled via policy |
| 1 | Sysmon | Replaces 4688, adds process hash, signature, more fields | External tool, not installed by default |

- Sysmon is the better pick: richer fields, more flexible, free from Microsoft Sysinternals
- 4688 is the basic, noisy option
- Sysmon logs: Event Viewer → Applications & Services → Microsoft → Windows → Sysmon → Operational
- Earlier Sysmon notes cover install and config

## Sysmon Event ID 1 Field Groups

| Group | Contains | Use |
|---|---|---|
| Process Info | PID, path (Image), command line | What launched and how |
| Parent Info | Parent process context | Build the process tree / attack chain |
| Binary Info | Hash, signature, PE metadata | Reputation checks, advanced analysis |
| User Context | User running it, **Logon ID** | Link to Security logs |

## Workflow: Analyse a Process Launch

1. Open Sysmon logs, filter Event ID `1`
2. Check process and binary info. Red flags:
   - Image in an uncommon directory like `C:\Temp` or `C:\Users\Public`
   - Odd name like `aa.exe` or `jqyvpqldou.exe`
   - Hash (MD5/SHA256) flagged as malware on VirusTotal
3. Check parent info. Red flags:
   - Parent matches any red flag from step 2
   - Parent is unexpected (e.g. Notepad launching CMD commands)
4. Still unsure? Walk up the process tree:
   - Find the earlier event where `ProcessId` equals your event's `ParentProcessId`
   - Repeat steps 2 and 3 on it
5. Trace the full chain: filter all Security and Sysmon events with the same **Logon ID**

## Detection Tips

- Process names and paths connect to the core Windows process baseline notes: `svchost.exe` outside `System32`, or `lsass.exe` with the wrong parent, is the same check done here
- Office or browser apps spawning `cmd.exe` or `powershell.exe` is a classic initial-access pattern 
- Command-line field is where encoded or download-and-run commands show up
- Logon ID is the join key again: process → logon → source IP
- Splunk starting point (field names may differ in your data):

        index=windowslogs EventID=1 | table _time Image CommandLine ParentImage User LogonId

---

# Sysmon Events Beyond Process Creation: 11, 13, 3, 22

Event ID 1 gives process context; these four events show what the process did next: files dropped, registry changed, network contacted.

## Event IDs

| Event ID | Name | Security log alternative | Purpose |
|---|---|---|---|
| 11 | File Create | 4656 (file changes), disabled by default | Files dropped by malware |
| 13 | Registry Value Set | 4657 (registry changes), disabled by default | Registry changes, e.g. persistence |
| 3 | Network Connection | None direct; needs firewall config | Traffic from untrusted processes or to malicious destinations |
| 22 | DNS Query | None direct; needs DNS config | Lookups of suspicious domains |

- Sysmon is configurable: you choose what to log and skip
- Config used here: Florian's (a popular community config), but you can change it

## Event Structure

- All Sysmon events share the same process-related fields
- Critical fields like **Logon ID** and **parent process info** are missing from these events
- Fix: take the `ProcessId`, find the matching Event ID 1, and get the full context there

## Workflow: Analyse Process Activities

1. Copy `ProcessId` from the Event ID 1
2. Search other Sysmon events with the same `ProcessId`
3. Network red flags (Events 3 / 22):
   - Connection to external IPs on port 80 or non-standard ports like `4444`
   - Connection to known malicious IPs (check VirusTotal)
   - DNS queries to suspicious domains (`*.top`, `*.click`, or random-looking like `hpdaykfpadvsl.com`)
4. File and registry red flags (Events 11 / 13):
   - Files dropped in staging directories like `C:\Temp` or `C:\Users\Public`
   - Dropped file is a script (`.bat`, `.ps1`) or executable (`.exe`, `.com`)
   - Files or registry keys used for persistence

## Why These Events Matter

- Network logs show where data was exfiltrated to
- Registry logs show which system configuration the attacker changed
- Together with Event ID 1 they let you rebuild the full attack chain

## Detection Tips

- Port `4444` shows up again, same Metasploit default flagged in the Sysmon hunting and perimeter notes
- The persistence registry keys (`Run` keys) from the Sysmon persistence note are exactly what Event ID 13 catches
- Random-looking domains often mean DGA (domain generation algorithm) malware, a general-knowledge note, not in the lesson
- Pivot key is `ProcessId` here, versus `Logon ID` in the Security log notes; use both
- Splunk starting point (field names may differ in your data):

        index=windowslogs ProcessId=<id> EventID IN (3, 11, 13, 22) | table _time EventID Image TargetFilename DestinationIp QueryName
