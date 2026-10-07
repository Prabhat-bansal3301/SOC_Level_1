# Task Manager for Process Analysis

**Core idea:** Task Manager is a built-in, always-available GUI for inspecting running processes — good for quick triage, but missing key context (parent-child relationships) that real investigation needs.

## Basics

- Open via: right-click Taskbar → Task Manager
- Default tab: **Processes** — groups into Apps, Background processes, Windows processes (a third category not always visible)
- Default columns are minimal (Name, Status, CPU, Memory) — right-click column header to add more

## Useful Columns

| Column | What it shows |
|---|---|
| Type | Apps / Background process / Windows process |
| Publisher | Program/file author |
| PID | Unique process identifier assigned per-launch |
| Process name | Actual file name (e.g. `Taskmgr.exe`) |
| Command line | Full command used to launch the process |
| CPU | Processing power used |
| Memory | Physical working memory used |

## Details Tab — Deeper Analysis

- Sort by PID ascending for easier review
- Add **Image path name** and **Command line** columns — these quickly expose outliers
- Example: `svchost.exe` (PID 384) should have a legitimate Windows image path/command line — if either looks off, it warrants deeper investigation

## Key Limitation: No Parent-Child View

- Task Manager doesn't show which process spawned which
- Example problem: `svchost.exe` (PID 384) should be spawned by `services.exe` — but if `services.exe` has PID 632 (higher than 384), that's a contradiction, since a child process can't start before its parent
- This mismatch is only visible because Task Manager **can't show parent PID directly** — you have to infer it from PID ordering, which is unreliable
- For real parent-child visibility: use **Process Hacker** or **Process Explorer** instead

## Command-Line Equivalents

- `tasklist` (CMD)
- `Get-Process` (PowerShell)
- `ps` (PowerShell alias)
- `wmic` (legacy, still usable)

**Why these matter:** native tools are what you have when you can't bring external tooling into an environment — worth being fluent in these, not just GUI tools, for exactly that scenario.

---

# The System Process (PID 4)

**Core idea:** System is a special kernel-mode process with fixed, predictable attributes — any deviation from its known baseline is a strong indicator of malicious masquerading.

## What It Is

- Official definition (Windows Internals, 6th Ed.): home for kernel-mode system threads — threads with normal thread attributes (hardware context, priority) but running only in kernel mode, executing code in `Ntoskrnl.exe` or loaded device drivers
- No user-mode process address space — dynamic storage comes from OS memory heaps (paged/nonpaged pool), not a normal process heap
- Background: [user mode vs. kernel mode](https://docs.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/user-mode-and-kernel-mode)

## Key Fact: PID Is Always 4

- Unlike other processes (randomly assigned PIDs), System is **always PID 4**
- A process named "System" with a different PID is an immediate red flag

## Normal Baseline

**Via Process Explorer:**

| Attribute | Value |
|---|---|
| Image Path | N/A |
| Parent Process | None |
| Number of Instances | One |
| User Account | Local System |
| Start Time | At boot time |

**Via Process Hacker (more detail):**

| Attribute | Value |
|---|---|
| Image Path | `C:\Windows\system32\ntoskrnl.exe` (NT OS Kernel) |
| Parent Process | System Idle Process (0) |
| Signature | Verified Microsoft Windows |

- Two tools show slightly different info — Process Hacker gives the fuller picture (actual image path, verified signature), while Process Explorer shows it as having no image path at all

## Unusual Behavior (Red Flags)

- Parent process other than **System Idle Process (0)**
- Multiple instances of System running (should only ever be one)
- Any PID other than **4**
- Not running in **Session 0**

## Why This Matters

- This is the baseline every future "is this process legitimate" check in this series will compare against
- Malware commonly names itself "System" or similar to blend in — checking these four attributes against the known-good baseline is a fast, reliable way to catch the impersonation
