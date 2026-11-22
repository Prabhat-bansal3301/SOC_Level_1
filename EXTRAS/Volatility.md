# Volatility: Memory Forensics Basics

Volatility is the most widely used framework for extracting digital artifacts from volatile memory (RAM) samples. It works **independently of the system under investigation**, so you get full insight into the runtime state with complete separation from the live machine.

## How It Works

- Built from multiple **plugins** working together on a memory dump
- Workflow:
  1. Identify the image type (several ways, covered later)
  2. Pick the plugins
  3. Run plugins against the dump to analyse it

## Volatility 2 vs 3

| | Volatility 2 | Volatility 3 |
|---|---|---|
| Language | Python 2 | Python 3 |
| Status | Older; common in blog posts | Recommended; latest |
| Syntax | Old | **Changed completely** |

- Repository: [Volatility 3](https://github.com/volatilityfoundation/volatility3)
- Blog posts and articles often show Volatility 2 syntax, which won't work in Volatility 3

## Acquiring a Memory Dump

### Bare-Metal Hosts

| Tool | Notes |
|---|---|
| FTK Imager | Disk and memory imaging |
| Redline | Can use its own agent and session structure |
| DumpIt.exe | Simple one-click dump |
| win32dd.exe / win64dd.exe | 32-bit / 64-bit dumpers |
| Memoryze | Memory acquisition and analysis |
| FastDump | Memory dump utility |

- Extraction can take a **considerable amount of time**, so plan for it if time is limited
- Most tools output a **`.raw`** file (Redline is an exception)

### Lab (Virtual) Machines

Collect the hypervisor's virtual memory file from the host drive:

| Hypervisor | File |
|---|---|
| VMware | `.vmem` |
| Hyper-V | `.bin` |
| Parallels | `.mem` |
| VirtualBox | `.sav` (**partial** memory file only) |

## Caution

- Be careful when extracting or moving memory, from both bare-metal and lab machines

## Notes (general knowledge, not in the source)

| Topic | Detail |
|---|---|
| Order of volatility | RAM is lost on power-off, so capture it **before** shutting a machine down |
| Evidence handling | Hash the dump after capture (see the file hash note) |
| Typical contents | Running processes, network connections, loaded DLLs, command history, malware that runs only in memory |
| Link to earlier notes | Fileless malware and process injection (see the sandbox and process notes) often show up **only** in memory |

---

# Volatility 3: Plugins and Identifying the Image

Volatility 3 changed the plugin structure drastically. Profiles are gone, and plugin names now include the operating system.

## Volatility 2 vs 3

| | Volatility 2 | Volatility 3 |
|---|---|---|
| OS profile | Needed: exact to the OS and build, hard to find, wrong choices give false positives | **Scrapped**: host and build identified automatically |
| Plugin naming | Plain name, same for all OSes (e.g. `pslist`) | **OS prefix + name** (e.g. `windows.info`, `linux.info`) |
| Plugin count | Large | Shorter list (still in active development), but enough for analysis |
| Identify the image | `imageinfo` plugin | `windows.info` / `linux.info` / `mac.info` |

## Plugin Naming

Each OS has drastically different memory structures, and with no profiles to tell them apart, the OS must be named first.

| Prefix | OS |
|---|---|
| `windows.` | Windows |
| `linux.` | Linux |
| `mac.` | macOS |

- Third-party plugins exist too; only a small portion of plugins is covered
- Use the help menu to see the available plugins:

        python3 vol.py -h

## Identifying the Host From a Dump

- You may get a memory file with no context about the machine
- **Volatility 3:** use the `info` plugin for the OS:

        python3 vol.py -f <file> windows.info

  (same for `linux.info` and `mac.info`)
- Shows information about the host taken from the memory dump

### `imageinfo` (Volatility 2 Only)

- Takes a dump and assigns a list of the **best possible OS profiles**
- Needed only in Volatility 2, since profiles are deprecated in Volatility 3
- **Not always correct**; results vary by dump, so test several profiles from its list
- Volatility 2 ships with all Windows profiles from XP to 10 (per the source)

## Quick Reference

| Task | Volatility 3 command |
|---|---|
| Identify the OS and build | `python3 vol.py -f <file> windows.info` |
| List plugins | `python3 vol.py -h` |
| Use a Linux dump | `python3 vol.py -f <file> linux.info` |

## Notes (general knowledge, not in the source)

- Most Volatility 3 plugins follow the same pattern: `python3 vol.py -f <file> windows.pslist`, `windows.netscan`, and others come in the next notes
- Volatility 3 builds symbol tables for the dump instead of profiles; Linux and Mac may need symbol files downloaded
- Match the tutorial's syntax to your version: Volatility 2 commands use `-f <file> --profile=<name> <plugin>`

---

# Volatility 3: Process, Network, and DLL Plugins

Five plugins list processes, network connections, and DLLs. Each uses a different technique, so each has different strengths against attacker evasion.

## Plugins at a Glance

| Plugin | Lists | Technique | Strength | Weakness |
|---|---|---|---|---|
| `windows.pslist` | Processes | Walks the **doubly-linked list** of processes (like Task Manager) | Shows current and terminated processes, with exit times | Misses processes that unlink themselves |
| `windows.psscan` | Processes | Scans memory for `_EPROCESS` structures | Finds **unlinked (hidden)** processes | Can give false positives |
| `windows.pstree` | Processes | Same method as `pslist`, arranged by parent PID | Shows the parent-child story | No extra evasion detection |
| `windows.netstat` | Network connections | Finds memory structures with network connections | Shows connections at capture time | Unstable on old Windows builds |
| `windows.dlllist` | DLLs per process | Lists DLLs loaded by processes | Filter to a specific DLL tied to a malware type | Needs prior analysis to know what to look for |

Syntax for all:

    python3 vol.py -f <file> windows.<plugin>

## pslist

    python3 vol.py -f <file> windows.pslist

- Equivalent to the process list in Task Manager
- Includes **terminated** processes and their exit times

## psscan

    python3 vol.py -f <file> windows.psscan

- Rootkits hide by **unlinking** their process from the list, so `pslist` no longer shows it
- `psscan` finds processes by matching `_EPROCESS` data structures instead of the list
- Trade-off: can produce false positives (e.g. leftover structures from ended processes)
- **Compare `pslist` and `psscan`**: a process in `psscan` only is a hiding candidate (general knowledge, not in the source)

## pstree

    python3 vol.py -f <file> windows.pstree

- Lists processes by parent process ID, using the same method as `pslist`
- Gives the full story of what was happening at extraction time
- Use the core Windows process baselines (parents, paths, instance counts) from the earlier notes to spot oddities

## netstat

    python3 vol.py -f <file> windows.netstat

- Attempts to identify all memory structures with a network connection
- In the current Volatility 3, it can be **very unstable**, particularly on old Windows builds
- Workaround: extract a **PCAP** from the memory file with `bulk_extractor` and analyse it in Wireshark or TShark (see the TShark notes)
- Useful when Volatility can't identify connections by itself
- The source links `bulk_extractor` on tools.kali.org

## dlllist

    python3 vol.py -f <file> windows.dlllist

- Lists all DLLs associated with processes at extraction time
- Most useful **after** further analysis: filter to a specific DLL that indicates the malware you suspect
- Ties to DLL hijacking, side-loading, and injection (see the DLL note)

## Suggested Order

| Step | Plugin | Question |
|---|---|---|
| 1 | `pslist` | What was running? |
| 2 | `psscan` | Is anything hidden from the list? |
| 3 | `pstree` | Do the parent-child relationships make sense? |
| 4 | `netstat` | What was it talking to? |
| 5 | `dlllist` | What did suspicious processes load? |

---

# Volatility 3: Hunting Malware With `malfind` and `yarascan`

Volatility has many plugins for hunting malware and anomalies in memory. Before using these two, you should understand evasion and malware techniques (e.g. process injection) and how to hunt them (see the process and Sysmon notes).

## Plugins at a Glance

| Plugin | Purpose | Finds |
|---|---|---|
| `windows.malfind` | Hunt **code injection** | Injected processes, PIDs, offsets, hex/ASCII/disassembly of the infected area |
| `windows.yarascan` | Match memory against **YARA rules** | Strings, patterns, and compound rules |

## malfind

    python3 vol.py -f <file> windows.malfind

One of the most useful plugins for code injection. It reports:
- Injected processes and their PIDs
- Offset address
- **Hex, ASCII, and disassembly** views of the infected area

### How It Works

- Scans process memory (the source says "heap") for regions that have:
  - The executable bit set: **RWE** (read-write-execute) or **RX** (read-execute)
  - **and/or** no memory-mapped file on disk (a sign of **fileless** malware)

### Reading the Output

| What you see | Meaning |
|---|---|
| `MZ` header at the start of the region | Windows executable (PE) injected into the process |
| Shellcode instead | Needs further analysis |

- The injected area looks different depending on what `malfind` finds
- Links to the earlier notes: process injection (T1055), remote threads, and fileless malware

## yarascan

    python3 vol.py -f <file> windows.yarascan

- Searches memory for strings, patterns, and compound rules from a rule set
- Two ways to supply rules:
  - A **YARA file** as an argument
  - Rules written directly in the command line

## Examples (general knowledge, not in the source)

| Goal | Command |
|---|---|
| Rules from a file | `python3 vol.py -f mem.raw windows.yarascan --yara-file rules.yar` |
| Quick inline rule | `python3 vol.py -f mem.raw windows.yarascan --yara-rules "mimikatz"` |

- Check `python3 vol.py windows.yarascan -h` for the exact options on your version

## Suggested Workflow

| Step | Plugin | Question |
|---|---|---|
| 1 | `pslist` / `psscan` | Which processes exist, any hidden? |
| 2 | `malfind` | Is code injected into any of them? |
| 3 | `yarascan` | Does a known malware signature match? |
| 4 | `dlllist` / `netstat` | What did it load and connect to? |

---

# Volatility 3: Hunting Rootkits (Hooks and Drivers)

Advanced adversaries, usually rootkits, use nasty evasion that needs analysis of drivers, mutexes, and hooked functions. Prior experience with hooking and driver manipulation helps. These plugins are best used **after** you have an initial lead, not as a first step.

## Hooking Methods

Five methods exist; this note focuses on SSDT because it is common and easiest with base Volatility plugins.

| Hook type | Full name (general knowledge) |
|---|---|
| SSDT | System Service Descriptor Table |
| IRP | I/O Request Packet |
| IAT | Import Address Table |
| EAT | Export Address Table |
| Inline | Code at the start of a function is overwritten |

### SSDT Hooking

- The Windows kernel uses the SSDT to look up system functions
- An adversary modifies table pointers so they point to a location the rootkit controls
- Legitimate software can hook too, so **you** decide what is malicious

        python3 vol.py -f <file> windows.ssdt

- Output can be **hundreds of entries**: analyse further or compare against a baseline
- Run it after investigating the initial compromise, as part of a lead

## Drivers

Adversaries use malicious driver files for evasion. Two plugins list them:

| Plugin | What it does | Limit |
|---|---|---|
| `windows.modules` | Lists **loaded** kernel modules | Misses malware that is idle or hidden |
| `windows.driverscan` | Scans for drivers present at extraction time | Often returns no output |

    python3 vol.py -f <file> windows.modules
    python3 vol.py -f <file> windows.driverscan

- `modules` is most useful once you have indicators to filter by
- `driverscan` can catch drivers `modules` missed or that were hidden
- Review `modules` **before** `driverscan`
- If `modules` finds nothing, try `driverscan`

### Compared With Process Plugins

| Walks a list | Scans memory |
|---|---|
| `pslist`, `modules` | `psscan`, `driverscan` |

- Same idea as before: the list view can be fooled, the scan view finds hidden items but may add false positives

## Other Plugins

| Plugin | Notes |
|---|---|
| `modscan` | Scans for kernel modules (like `driverscan` for modules) |
| `driverirp` | Drivers' IRP handlers (general knowledge) |
| `callbacks` | Kernel callbacks |
| `idt` | Interrupt Descriptor Table |
| `apihooks` | API hooks |
| `moddump` | Dumps a kernel module |
| `handles` | Open handles |

- Some are **Volatility 2 only** or third-party
- To get the most out of Volatility you may need third-party or custom plugins

## Suggested Order

| Step | Question | Plugin |
|---|---|---|
| 1 | Anything hidden or injected? | `psscan`, `malfind` |
| 2 | Are syscalls hooked? | `ssdt` |
| 3 | Any odd kernel modules? | `modules` |
| 4 | Any hidden drivers? | `driverscan` |

