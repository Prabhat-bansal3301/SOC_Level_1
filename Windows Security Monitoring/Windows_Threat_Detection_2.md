# Discovery (Situational Awareness)

After getting in, attackers don't know what they've landed on. Discovery is how they learn the host's purpose, the user's privileges, and the network, and it maps to the MITRE **Discovery** tactic.

## Why Attackers Do It

- Phishing sends thousands of attachments but breaches only a few systems the attacker has never seen
- They need to know: "Who am I?" and "Where am I?"
- Goals: find the host's value, find security tools that could stop the attack

## Discovery Commands

| Purpose | Why attackers want it | CMD / PowerShell commands |
|---|---|---|
| Files and folders | Host purpose, victim's job or interests | `type <file>`, `Get-Content <file>`, `dir <folder>`, `Get-ChildItem <folder>` |
| Users and groups | Who uses the host, with which privileges | `whoami`, `net user`, `net localgroup`, `query user`, `Get-LocalUser` |
| System and apps | Vulnerabilities, apps to steal data from | `tasklist /v`, `systeminfo`, `wmic product get name,version`, `Get-Service` |
| Network settings | Is the host part of a corporate network | `ipconfig /all`, `netstat -ano`, `netsh advfirewall show allprofiles` |
| Active antivirus | How risky it is to continue without being blocked | `Get-WmiObject -Namespace "root\SecurityCenter2" -Query "SELECT * FROM AntivirusProduct"` |

## Discovery Process

1. Phishing attachment is launched (see the phishing notes)
2. It runs basic discovery commands automatically
3. Malware may delete itself if:
   - A specific antivirus is installed
   - The victim isn't from a targeted company or country
4. Otherwise it connects back to the attacker, giving full control
5. Human attackers then type more Discovery commands as needed

## Detection Tips

- Sysmon Event ID 1: many of these tools in a short window from the same parent (`whoami`, `net user`, `ipconfig`, `systeminfo`)
- One of these commands is normal for admins; a burst from one process tree is the signal
- Suspicious parents: `powershell.exe` or `cmd.exe` launched by `explorer.exe`, an Office app, or a script
- PowerShell discovery commands typed in a console won't appear in Event ID 1, so also check the history file (see the PowerShell note)
- The AV query hits `root\SecurityCenter2`: unusual outside security tools, worth alerting on
- Same pivot as earlier notes: `ProcessId` for the tree, Logon ID for the session
- Splunk starting point (field names may differ in your data):

        index=windowslogs EventID=1 (Image="*\\whoami.exe" OR Image="*\\net.exe" OR Image="*\\ipconfig.exe" OR Image="*\\systeminfo.exe" OR Image="*\\tasklist.exe") | stats count by ParentImage, User | sort - count

---

# Detecting Discovery: CMD and GUI

Discovery via the command line is the easiest and most common method, because the commands (`whoami`, `ipconfig`) exist on every Windows machine. Most of them are logged as new processes, so a process tree exposes them.

## Discovery via CMD

- Built-in commands, nothing to download
- Real-world attack example: see the article linked in the lesson (link not in the paste)
- Most commands show up as new processes (Sysmon Event ID 1)

Process tree from a phishing binary:

    C:\Users\victim\Downloads\invoice.pdf.exe
    ├── C:\Windows\System32\cmd.exe
    │   ├── ipconfig                          // network settings
    │   ├── whoami /priv                      // user permissions
    │   ├── dir                               // list current directory
    │   ├── net user                          // list local users
    │   ├── tasklist /v                       // running processes
    │   └── wmic computersystem get model     // laptop model
    └── C:\Windows\...\powershell.exe
        ├── Get-Service                       // active services
        └── Get-MpPreference                  // MS Defender settings

- Red flag: a downloaded double-extension binary spawning `cmd.exe` and `powershell.exe`, which then run a burst of discovery commands
- `Get-MpPreference` checks Defender settings, so the attacker is probing for security tools

## Discovery via GUI

- Happens when attackers log in interactively (e.g. after an RDP breach)
- They can use the same tools you do: Apps & Programs, System Settings, Disk Management, Event Viewer
- No typical `whoami` commands, so the tree looks different
- They often still use CMD out of habit

Process tree after an interactive login:

    C:\Windows\System32\explorer.exe
    ├── cmd.exe                                    // CMD still possible
    ├── mmc.exe compmgmt.msc                       // Computer Management
    ├── control.exe netconnections                 // network adapters
    ├── SystemSettings.exe [...]                   // settings panel
    ├── notepad.exe C:\...\secrets.txt             // read a text file
    └── taskmgr.exe                                // Task Manager

## CMD vs GUI Trees

| | CMD discovery | GUI discovery |
|---|---|---|
| Typical parent | Malware binary → `cmd.exe` / `powershell.exe` | `explorer.exe` |
| Typical access | Phishing, malware launch | Interactive login (RDP) |
| Signal | Burst of discovery commands | Admin tools opened by a user session |

## How to Detect

1. Find a discovery command, or better, a **sequence** in a short time
   - Sysmon Event ID 1
   - New rows in the PowerShell history file
2. Find where the commands came from
   - `ipconfig` alone is normal (IT staff, legitimate tools); don't raise alarms over one
3. Build the process tree from Sysmon:
   - Filter for Event ID 1
   - Correlate `ProcessId` with `ParentProcessId`
4. If unsure what a command does, look it up

## Detection Tips

- Judge the **parent**, not the command: `ipconfig` under `invoice.pdf.exe` is bad, under an IT tool is fine
- Several different discovery commands within seconds is the strongest signal
- For GUI cases, `notepad.exe` opening a file named `secrets.txt` or similar is the tell; pair it with the logon (type 10 RDP) and Logon ID
- Same process-tree method as the process monitoring note
- Splunk starting point to find the children of a suspicious parent (field names may differ in your data):

        index=windowslogs EventID=1 ParentProcessId=<id> | table _time Image CommandLine ParentImage
