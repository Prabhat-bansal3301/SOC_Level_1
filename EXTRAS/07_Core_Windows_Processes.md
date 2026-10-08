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

---
# smss.exe (Session Manager Subsystem)

The first user-mode process started by the kernel, responsible for creating new sessions and launching the core Windows subsystem processes.

## What It Does

- Starts the kernel and user modes of the Windows subsystem: `win32k.sys` (kernel), `winsrv.dll` (user), `csrss.exe` (user)
- Reference: [NT Architecture](https://en.wikipedia.org/wiki/Architecture_of_Windows_NT), [Session Manager Subsystem](https://en.wikipedia.org/wiki/Session_Manager_Subsystem)
- Creates environment variables and virtual memory paging files
- Launches any other subsystem listed in the `Required` value of:

        HKLM\System\CurrentControlSet\Control\Session Manager\Subsystems

## Session Startup

| Session | Purpose | Processes started |
|---|---|---|
| Session 0 | Isolated session for the OS | `csrss.exe`, `wininit.exe` |
| Session 1 | User session | `csrss.exe`, `winlogon.exe` |

- The master `smss.exe` creates a child instance for each new session
- The child copies itself into the new session, does its setup, then self-terminates
- That's why only the master instance should remain running

## Normal Baseline

| Attribute | Value |
|---|---|
| Image Path | `%SystemRoot%\System32\smss.exe` |
| Parent Process | System (PID 4) |
| Instances | One master, plus a short-lived child per new session |
| User Account | Local System |
| Start Time | Within seconds of boot (master instance) |

## Red Flags

- Parent process other than System (4)
- Image path outside `C:\Windows\System32`
- More than one running instance (children should exit after creating the session)
- Running user is not SYSTEM
- Unexpected entries in the registry `Subsystems` key

## Detection Tips

- Multiple long-running `smss.exe` processes means something is impersonating it, since real children exit
- The `Subsystems\Required` registry value is a persistence location, so unexpected entries there deserve a check

---

# csrss.exe (Client Server Runtime Process)

The user-mode side of the Windows subsystem. It is critical to system operation, and terminating it causes system failure.

## What It Does

- Handles the Win32 console window
- Handles process and thread creation and deletion
- Makes the Windows API available to other processes
- Maps drive letters
- Handles the Windows shutdown process
- Each instance loads `csrsrv.dll`, `basesrv.dll`, `winsrv.dll` (plus others)
- Started by `smss.exe` at boot: Session 0 and Session 1 each get their own instance (see previous note)

## Normal Baseline

| Attribute | Value |
|---|---|
| Image Path | `%SystemRoot%\System32\csrss.exe` |
| Parent Process | None visible (created by an `smss.exe` instance that then self-terminates) |
| Instances | Two or more (one per session, usually Session 0 and 1) |
| User Account | Local System |
| Start Time | Within seconds of boot for Session 0 and 1; later instances start when new sessions are created |

- Example PIDs: Session 0 = 392, Session 1 = 512 (PIDs vary per boot)

## Red Flags

- A real, living parent process (the parent `smss.exe` should already be gone)
- Image path outside `C:\Windows\System32`
- Subtle misspellings of the name (e.g. `csrs.exe`, `cssrs.exe`) hiding in plain sight
- Running user is not SYSTEM

## Detection Tips

- A missing parent is normal here, which is the opposite of most processes
- Misspelling is the most common masquerade, so read process names character by character
- Check the path first; a wrong path is the fastest tell

---

# wininit.exe (Windows Initialization Process)

A critical background process that launches the core service and security processes in Session 0.

## What It Does

Launches these in Session 0:

| Process | Role |
|---|---|
| `services.exe` | Service Control Manager |
| `lsass.exe` | Local Security Authority |
| `lsaiso.exe` | Credential Guard / KeyGuard (only present if Credential Guard is enabled) |

- Started by an `smss.exe` instance at boot (see the smss.exe note)
- Missing `lsaiso.exe` is normal when Credential Guard is off

## Normal Baseline

| Attribute | Value |
|---|---|
| Image Path | `%SystemRoot%\System32\wininit.exe` |
| Parent Process | None visible (created by an `smss.exe` instance that self-terminates) |
| Instances | One |
| User Account | Local System |
| Start Time | Within seconds of boot |

## Red Flags

- A real, living parent process (`smss.exe` should already be gone)
- Image path outside `C:\Windows\System32`
- Subtle misspellings of the name
- More than one instance
- Not running as SYSTEM

## Detection Tips

- Same orphan-parent pattern as `csrss.exe`, so a visible parent is the first thing to check
- Only one instance should exist, so a second `wininit.exe` is a clear sign of a fake
- `lsass.exe` is the Mimikatz target covered in the Sysmon notes, so a fake parent chain above it matters

---

# services.exe (Service Control Manager)

Handles system services: loading them, interacting with them, and starting or stopping them.

## What It Does

- Maintains a service database, queried with the built-in `sc.exe`:

        sc <server> [command] [service name] <option1> <option2>...

- Service info is stored in the registry:

        HKLM\System\CurrentControlSet\Services

- Loads auto-start device drivers into memory
- After a successful user logon, sets the Last Known Good control set:

        HKLM\System\Select\LastKnownGood

  (copied from `CurrentControlSet`)
- Reference: [Service Control Manager](https://en.wikipedia.org/wiki/Service_Control_Manager)

## Child Processes

Parent of several key processes, including:

- `svchost.exe`
- `spoolsv.exe`
- `msmpeng.exe`
- `dllhost.exe`

## Normal Baseline

| Attribute | Value |
|---|---|
| Image Path | `%SystemRoot%\System32\services.exe` |
| Parent Process | `wininit.exe` |
| Instances | One |
| User Account | Local System |
| Start Time | Within seconds of boot |

## Red Flags

- Parent process other than `wininit.exe`
- Image path outside `C:\Windows\System32`
- Subtle misspellings of the name
- More than one instance
- Not running as SYSTEM

## Detection Tips

- Unlike `csrss.exe` and `wininit.exe`, this one has a real, visible parent: `wininit.exe`
- The `Services` registry key is a persistence location, since attackers register malicious services there
- Malicious services often show up as unexpected children of `services.exe`

---

# svchost.exe (Service Host)

Hosts and manages Windows services. Heavily targeted for masquerading because many legitimate instances always run, giving malware plenty of cover.

## What It Does

- Services run inside it as DLLs
- The DLL is stored in the registry under the service's `Parameters` subkey, in `ServiceDLL`:

        HKLM\SYSTEM\CurrentControlSet\Services\<SERVICE NAME>\Parameters

- Example: the `Dcomlaunch` and `LSM` services each have their own `ServiceDLL` value
- In Process Hacker: right-click the `svchost.exe` process to view its details

## The `-k` Parameter

- A legitimate `svchost.exe` is launched with `-k <group name>` in its command line
- Example: `-k DcomLaunch`
- `-k` groups similar services into a shared process, to reduce resource use
- Windows 10 v1703+ on machines with more than 3.5 GB RAM: each service runs in its own process instead of being grouped
- Reference: [Svchost.exe](https://en.wikipedia.org/wiki/Svchost.exe)

## Normal Baseline

| Attribute | Value |
|---|---|
| Image Path | `%SystemRoot%\System32\svchost.exe` |
| Parent Process | `services.exe` |
| Instances | Many |
| User Account | Varies: SYSTEM, Network Service, Local Service (some Windows 10 instances run as the logged-in user) |
| Start Time | Mostly within seconds of boot; more can start later |

## How Attackers Abuse It

- Name malware `svchost.exe` to hide among the legitimate instances
- Misspell it slightly, e.g. `scvhost.exe`
- Install or call a malicious service DLL
- Extra reading: [Hexacorn blog on svchost.exe abuse](https://www.hexacorn.com/blog/2015/12/18/the-typographical-and-homomorphic-abuse-of-svchost-exe-and-other-popular-file-names/)

## Red Flags

- Parent process other than `services.exe`
- Image path outside `C:\Windows\System32`
- Subtle misspellings of the name
- No `-k` parameter in the command line

## Detection Tips

- Many instances is normal here, so count alone proves nothing; check parent, path, and `-k` on each one
- Always read the name character by character
- Suspicious instance: check its `ServiceDLL` in the registry, since the malicious part may be the DLL and not the process
- Sysmon Event ID 7 (image loaded) can help spot unexpected DLLs loaded into it
