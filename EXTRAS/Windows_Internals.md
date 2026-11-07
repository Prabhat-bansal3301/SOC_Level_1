# Windows Processes: Components and Attack Surface

A process represents the running execution of a program. An application can have one or more processes, and most Windows functionality runs as an application with a matching process.

## What a Process Has

Per Microsoft docs, each process provides the resources needed to run a program:

- Virtual address space
- Executable code
- Open handles to system objects
- Security context
- Unique process identifier
- Environment variables
- Priority class
- Minimum and maximum working set sizes
- At least one thread of execution

## Key Components (High Level)

| Component | Purpose |
|---|---|
| Private Virtual Address Space | Virtual memory addresses allocated to the process |
| Executable Program | Code and data stored in that address space |
| Open Handles | Handles to system resources the process can access |
| Security Context | Access token: user, security groups, privileges |
| Process ID (PID) | Unique numerical identifier |
| Threads | Sections of the process scheduled for execution |

## Process Layout in Memory

| Component | Purpose |
|---|---|
| Code | Code the process executes |
| Global Variables | Stored variables |
| Process Heap | Heap where data is stored |
| Process Resources | Further resources of the process |
| Environment Block | Data structure holding process information |

- The source's memory diagram wasn't included, so this table is the text version only

## Process Details in Task Manager

| Field | Purpose | Example |
|---|---|---|
| Name | Usually inherited from the application | `conhost.exe` |
| PID | Unique numerical ID | `7408` |
| Status | How it is running (running, suspended...) | Running |
| User name | Who started it; hints at privilege | `SYSTEM` |

- These are the fields an end user sees and an attacker manipulates
- Better tools for observing processes: Process Hacker 2, Process Explorer, Procmon
- Task Manager's limits (no parent-child view) are in the earlier Task Manager note

## Examples of Default Processes

| Process | Role |
|---|---|
| `MsMpEng` | Microsoft Defender |
| `wininit` | Windows Initialization Process (see correction below) |
| `lsass` | Credential and security policy handling |

## Attack Techniques Against Processes

Attackers target processes to evade detection and hide malware as legitimate ones.

| Technique | MITRE ID |
|---|---|
| [Process Injection](https://attack.mitre.org/techniques/T1055/) | T1055 |
| [Process Hollowing](https://attack.mitre.org/techniques/T1055/012/) | T1055.012 |
| Process Masquerading | listed as T1055.013 in the source (see correction below) |

- Links are from general knowledge; the source gave IDs only
- Injection: code is placed into another running process
- Hollowing: a legitimate process is started suspended, its memory is replaced with malicious code, then it resumes (general knowledge)
- Masquerading: malware takes a legitimate-looking name (see the `svchost.exe` and `scvhost.exe` examples in the core Windows process notes)

## Corrections to Check Before Publishing

- **`wininit` is not "keyboard and mouse".** It is the Windows Initialization Process that launches `services.exe` and `lsass.exe` in Session 0 (see the wininit note)
- **`T1055.013` is Process Doppelgänging**, not masquerading. Masquerading is [T1036](https://attack.mitre.org/techniques/T1036/) (general knowledge, worth confirming on the MITRE site)
- `lsass` is better described as enforcing the security policy, verifying logons, and creating access tokens; credential storage is only part of it
