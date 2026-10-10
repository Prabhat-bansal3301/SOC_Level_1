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
