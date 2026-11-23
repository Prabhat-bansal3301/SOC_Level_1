# Boogeyman 2 – Phishing Macro to Persistence (Email Analysis and Memory Forensics)

**Scenario:** a user (Maxine) fell for a phishing email with a Word attachment. The investigation has two parts: analyse the email and its attachment, then use a **memory dump** of the victim's workstation (`WKSTN-2961.raw`) to see what the malware did after it ran.

**Evidence location:** `/home/ubuntu/Desktop/Artefacts/` (the email and the memory image).

## Tools Used

| Tool | Used for |
|---|---|
| **Evolution Mail** | Opening the phishing email and saving its attachment |
| **[olevba](https://github.com/decalage2/oletools/wiki/olevba)** (part of oletools) | Extracting and analysing **VBA macros** from Office documents without opening them |
| **[Volatility 3](https://www.volatilityfoundation.org/)** | Memory forensics (processes, network connections, files, memory dumps) |
| **`strings` + `grep`** | Searching raw memory and process dumps for readable text |
| **MD5 hashing (`md5sum`)** | Fingerprinting the malicious attachment |

## Glossary

| Term | Meaning |
|---|---|
| **Macro / VBA** | Small programs embedded in Office documents (Visual Basic for Applications). Attackers use [malicious macros](https://www.ired.team/offensive-security/initial-access/phishing-with-ms-office/t1137-office-vba-macros) to run code when a user opens and enables content |
| **Dropper** | A first-stage program whose job is to download or write another payload |
| **Process tree** | Which process started which. Each process has a **PID** and a **PPID** (parent PID) |
| **C2 (Command and Control)** | The attacker's server that the malware connects to for instructions |
| **Persistence** | A way for malware to survive reboots or logoffs. Here it is a **scheduled task** |
| **`netscan`** | A Volatility plugin that lists network connections and sockets found in memory |
| **`filescan`** | A Volatility plugin that scans memory for file objects, so you can locate files by name |
| **Process memory dump** | All memory belonging to one process, saved to disk so you can search it |

## Attack Flow

```text
Phishing email with a Word document (.doc) attachment
        |
        v
Victim opens it, the VBA macro runs
        |
        v
Macro downloads a file disguised as an image from the attacker's domain
        |
        v
It is saved as a JavaScript file (update.js)
        |
        v
A built-in Windows script host runs update.js
        |
        v
updater.exe appears in memory, connects to the C2 server
        |
        v
Persistence: a scheduled task (schtasks) is created
```

## Part 1: Email and Macro Analysis

| Step | Action | What you learn |
|---|---|---|
| 1 | Open the email in Evolution Mail | Sender address, recipient, and the name of the suspicious Word attachment |
| 2 | Save the attachment and hash it (`md5sum <file>.doc`) | The file's fingerprint, to share as an IOC and look up on VirusTotal |
| 3 | Run `olevba <filename>.doc` | Shows whether macros exist and prints their code, with suspicious keywords highlighted |

**What olevba revealed (three key items):**

| # | Finding | Why it matters |
|---|---|---|
| 1 | A **URL pointing to an image file** | Attackers disguise the payload as a harmless picture so downloads look normal |
| 2 | The file is **saved as `update.js`** | It's really a JavaScript file with the wrong extension in its source |
| 3 | It is **run with a native Windows binary** | A built-in script host launches it, a **LOLBin** technique that avoids dropping an obvious `.exe` |

**Note:** the room's output names the exact binary. Copy the value from your own olevba output when you write the final answer.

**Why olevba is useful:** it reads the macro code straight from the file, so you never have to open the document or enable macros. It also flags suspicious keywords such as auto-execute functions, shell calls and downloads.

## Part 2: Memory Forensics with Volatility

**Memory file:** `WKSTN-2961.raw`

| Step | Command | Purpose |
|---|---|---|
| 1 | `vol -f WKSTN-2961.raw windows.pslist` | Lists processes. Look for a name that matches the clue from the macro (`updater.exe` stands out) |
| 2 | `vol -f WKSTN-2961.raw windows.pstree` | Shows each process's **PID and parent PID**, so you can trace where `updater.exe` came from |
| 3 | `strings WKSTN-2961.raw \| grep 'boogeymanisback'` | Searches the whole memory image for the attacker's **domain keyword** to find the full URL |
| 4 | `vol -f WKSTN-2961.raw windows.netscan` | Finds **established connections**, which reveals the C2 IP and port |
| 5 | `vol -f WKSTN-2961.raw windows.filescan \| grep <file name without .doc>` | Locates the **original Word document** on disk (its full path) |
| 6 | `mkdir memdump` then `vol -f WKSTN-2961.raw -o memdump/ windows.memmap --dump --pid <PID of updater.exe>` | Dumps everything in that process's memory into the `memdump` folder |
| 7 | `strings memdump/<dump file> \| grep -i 'powershell.exe\|cmd.exe'` | Looks inside the process for command interpreter use. Shows a **scheduled task** being created |
| 8 | `strings WKSTN-2961.raw \| grep schtasks` | Pulls out the full `schtasks` command, which shows how **persistence** was set up |

### How each step builds on the last
- **Macro (email) → process name:** the file name `update.js` pointed to `updater.exe` in the process list
- **Process tree → origin:** parent and child relationships show how the malware launched
- **Domain keyword → URL:** the domain from the macro lets you search the whole image for the exact download link
- **Netscan → C2:** the process's established connection gives the attacker's server
- **Filescan → file location:** finds where the original document was saved on the victim's machine
- **Process dump → behavior:** searching the process memory for `powershell.exe` and `cmd.exe` reveals commands it ran, which led to the scheduled task
- **Keyword search → persistence:** Volatility has no plugin for scheduled tasks here, so searching for the known keyword `schtasks` filled the gap

## Findings Summary

| Item | Finding |
|---|---|
| Initial access | Phishing email with a malicious Word document |
| Execution | VBA macro that downloads a file disguised as an image |
| Dropped file | `update.js`, run by a built-in Windows binary |
| Malicious process in memory | `updater.exe` |
| C2 | An IP and port found with `windows.netscan` |
| Persistence | Scheduled task created with `schtasks` |
| Original document location | Found with `windows.filescan` |

## MITRE ATT&CK Mapping

| Stage | Technique | ID |
|---|---|---|
| Initial access | Phishing: Spearphishing Attachment | T1566.001 |
| Execution | User Execution: Malicious File | T1204.002 |
| Execution | Command and Scripting Interpreter: Visual Basic and JavaScript | T1059.005, T1059.007 |
| Defense evasion | Masquerading (script disguised as an image) | T1036 |
| Command and control | Ingress Tool Transfer | T1105 |
| Persistence | Scheduled Task | T1053.005 |

## Key Takeaways
- **Check Office attachments with `olevba` before opening them.** It shows macros and flags risky keywords safely
- **Use clues from one stage to search the next:** file names, domains and keywords from the email become search terms in memory
- **`pslist` and `pstree` together:** the list finds suspects, the tree shows their parents
- **`strings <memory image> | grep <keyword>`** works on the whole image, and is great when no plugin covers what you need
- **Dump a suspicious process** with `windows.memmap --dump --pid` and search it for `powershell.exe`, `cmd.exe`, URLs and commands
- **`windows.netscan`** finds the C2, and **`windows.filescan`** finds files by name
- **Disguised files are common:** a script named like an image, or a program named `updater.exe`, is built to look harmless
- **Tip:** Windows stores many strings in memory as **UTF-16**. If a normal `strings` search misses something, try `strings -el <file>` (little-endian 16-bit)
- **Defences:** block macros from the internet, filter Office attachments, restrict script hosts like `wscript.exe`, and alert on new scheduled tasks
