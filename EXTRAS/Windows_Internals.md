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

---

# Threads

A thread is an executable unit used by a process, and the OS schedules it based on device factors. Simply put, a thread controls the execution of a process.

## Scheduling Factors

- CPU and memory specifications
- Priority
- Logical factors, and others

## Shared vs Unique

| | Shared with the parent process | Unique to each thread |
|---|---|---|
| Examples | Code, global variables, other process resources | Stack, thread local storage, stack argument, context structure |

## Per-Thread Components

| Component | Purpose |
|---|---|
| Stack | Data specific to the thread (exceptions, procedure calls, etc.) |
| Thread Local Storage | Pointers for allocating storage to a unique data environment |
| Stack Argument | Unique value assigned to each thread |
| Context Structure | Machine register values, maintained by the kernel |

- Context structure holds the CPU register values, so the kernel can pause a thread and resume it later (general knowledge)
- "Stack Argument" is not a standard Windows term; it is probably the argument passed to the thread function at creation (general knowledge, worth confirming)

## Why Attackers Target Threads

- Threads control execution, so abusing them gives code execution
- Used on their own, or chained with other API calls inside bigger techniques

| Technique | Idea | Windows API (general knowledge) |
|---|---|---|
| Remote thread injection | Start a new thread in another process that runs attacker code | `CreateRemoteThread` |
| Thread hijacking | Pause a thread, change its registers to point at attacker code, resume it | `SuspendThread`, `GetThreadContext`, `SetThreadContext`, `ResumeThread` |

- Thread hijacking works because of the context structure: changing the saved registers changes where the thread runs next
- Both are Process Injection techniques ([T1055](https://attack.mitre.org/techniques/T1055/)), covered in the previous note
- Sysmon Event ID 8 (`CreateRemoteThread`) from the Sysmon notes logs the first one

---

# Virtual Memory

Virtual memory lets Windows components use memory as if it were physical memory, without applications colliding with each other. User mode vs kernel mode is covered in a later note.

## How It Works

- Each process gets a [private virtual address space](https://docs.microsoft.com/en-us/windows/win32/memory/virtual-address-space)
- The **memory manager** translates virtual addresses to physical addresses
- Processes never write to physical memory directly, so they are less likely to damage each other or the system
- Apps can use more virtual memory than the physical RAM available
- The memory manager solves this by **paging**: moving virtual memory to disk (the page file)

## 32-bit vs 64-bit

| | 32-bit (x86) | 64-bit |
|---|---|---|
| Theoretical max address space | 4 GB | 256 TB |
| Lower half (processes) | `0x00000000` to `0x7FFFFFFF` | Same 50/50 split as 32-bit |
| Upper half (OS) | `0x80000000` to `0xFFFFFFFF` | Same 50/50 split as 32-bit |

- On 32-bit, an app can normally use only the lower 2 GB
- The split can be changed for apps that need more:
  - `increaseUserVA` setting, which gives user processes a larger share
  - [AWE (Address Windowing Extensions)](https://docs.microsoft.com/en-us/windows/win32/memory/address-windowing-extensions)
- On 64-bit, the address space is so large that most cases no longer need these workarounds
- The source's address layout diagrams weren't included, so the tables above are the text version

## Why Attackers Care

General knowledge, not in the source:

- The source says this concept "can be leveraged to aid in abusing Windows internals"
- Process injection writes into **another process's** virtual address space
- The same virtual address points to different memory in different processes
- The memory manager's page protections (read, write, execute) decide what code can run where
- Links to the earlier notes: injection (T1055) and `CreateRemoteThread` both work by placing code into a target's address space

## Notes to Check Before Publishing

- The "256 TB" figure is the theoretical 64-bit total. In practice 64-bit Windows splits it into 128 TB for user space and 128 TB for kernel space (general knowledge)
- The source says "pages or transfers"; I wrote **paging**, the standard term
- The 64-bit "same ratio" statement means the same half/half split

---
# DLLs (Dynamic-Link Libraries)

Per Microsoft docs, a DLL is a library containing code and data that more than one program can use at the same time. DLLs are a core part of how applications run on Windows.

## Why Windows Uses DLLs

- Modular code and code reuse
- Efficient memory use
- Less disk space
- Faster loading and running of the OS and programs

## Why Attackers Care

When a program loads a DLL, the DLL becomes a **dependency**. Attackers target the DLL instead of the application to control part of its execution.

| Technique | MITRE ID | Idea (general knowledge) |
|---|---|---|
| DLL Hijacking | [T1574.001](https://attack.mitre.org/techniques/T1574/001/) | App loads a malicious DLL because of the search order |
| DLL Side-Loading | [T1574.002](https://attack.mitre.org/techniques/T1574/002/) | A legitimate app loads an attacker's DLL placed next to it |
| DLL Injection | [T1055.001](https://attack.mitre.org/techniques/T1055/001/) | Force a running process to load a DLL |

- The source gave IDs only; links and one-line ideas are mine

## Creating a DLL

A DLL is built like any other project, with slight syntax changes (Visual C++ Win32 DLL project).

    #include "stdafx.h"
    #define EXPORTING_DLL
    #include "sampleDLL.h"
    BOOL APIENTRY DllMain( HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved )
    {
        return TRUE;
    }

    void HelloWorld()
    {
        MessageBox( NULL, TEXT("Hello World"), TEXT("In a DLL"), MB_OK);
    }

| Part | Role |
|---|---|
| `DllMain` | Entry point, called when the DLL is loaded or unloaded |
| `HelloWorld()` | The exported function other programs can call |

- `DllMain` runs automatically on load, so attackers like to put code there (general knowledge)

### Header File

Defines which functions are imported and exported.

    #ifndef INDLL_H
        #define INDLL_H
        #ifdef EXPORTING_DLL
            extern __declspec(dllexport) void HelloWorld();
        #else
            extern __declspec(dllimport) void HelloWorld();
        #endif
    #endif

- `EXPORTING_DLL` is defined inside the DLL project, so it **exports** the function
- Programs that include the header without that define **import** it

## Using a DLL in an Application

| | Load-time dynamic linking | Run-time dynamic linking |
|---|---|---|
| How | App calls the DLL function directly | App loads the DLL itself while running |
| Needs | Header (`.h`) and import library (`.lib`) | `LoadLibrary` or `LoadLibraryEx`, then `GetProcAddress` |
| Library loaded | When the app starts | When the code asks for it |

### Load-Time Example

    #include "stdafx.h"
    #include "sampleDLL.h"
    int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
    {
        HelloWorld();
        return 0;
    }

### Run-Time Example

    typedef VOID (*DLLPROC) (LPTSTR);
    HINSTANCE hinstDLL;
    DLLPROC HelloWorld;
    BOOL fFreeDLL;

    hinstDLL = LoadLibrary("sampleDLL.dll");
    if (hinstDLL != NULL)
    {
        HelloWorld = (DLLPROC) GetProcAddress(hinstDLL, "HelloWorld");
        if (HelloWorld != NULL)
            (HelloWorld);
        fFreeDLL = FreeLibrary(hinstDLL);
    }

Steps:
1. `LoadLibrary` loads the DLL
2. `GetProcAddress` finds the exported function by name
3. Call the function
4. `FreeLibrary` unloads the DLL

## Malware Preference

- Malicious code uses run-time linking more than load-time
- Source reason: a malicious program may need to move files between memory regions, and moving a single DLL is easier than satisfying other file requirements
- Other reasons (general knowledge):
  - No suspicious functions in the import table for static analysis to see
  - Function names can be hidden or built at run time
  - The DLL can be chosen or swapped while running

## Corrections to Check Before Publishing

- The run-time example's `(HelloWorld);` only names the function and **doesn't call it**. A call needs `(HelloWorld)();`
- The `DLLPROC` typedef takes a `LPTSTR` argument, but `HelloWorld()` takes none, so the types don't match. It looks adapted from a Microsoft example that passed a string
