# Command and Control (C2)

C2 is how attackers send commands to an infected host and keep control of it. It maps to the MITRE [Command and Control](https://attack.mitre.org/tactics/TA0011/) tactic.

## Attack Without C2

- Attackers can type commands directly in an RDP session after an RDP breach
- This stops working once RDP is closed or secured
- So most attackers set up a C2 right after the breach anyway

Screenshot flow:

| Step | What happens |
|---|---|
| 1 | Attacker breaches the server via RDP |
| 2 | Attacker uses RDP like a normal user |
| 3 | Attacker sees the results in the GUI |

- The screenshot shows an Administrator Command Prompt running `dir`, plus Computer Management and Local Security Policy open
- That matches the GUI discovery process tree from the earlier Discovery note

## Simplest C2

- For phishing or USB infections, attackers can't reuse RDP
- They need a process that connects back and waits for commands 24/7
- Simplest case: the phishing attachment itself is that process
- Example C2 framework: [Cobalt Strike](https://www.cobaltstrike.com/)

Screenshot flow:

| Step | What happens |
|---|---|
| 1 | Attacker sends a phishing attachment |
| 2 | Victim opens it, and it connects to the C2 |
| 3 | Attacker controls victims from the C2 panel |

What the Cobalt Strike screenshot shows:
- Top table lists each infected host ("beacon"): external IP, internal IP, user, computer, PID, and time since last check-in
- Bottom console: operator ran `shell dir c:\`
- Log lines: `Tasked beacon to run: dir c:\`, then `host called home`, then the output comes back
- So the operator types a command, the beacon runs it, and the result returns on the next check-in
- Two beacons from the same internal host show one machine can carry more than one implant

## Advanced C2

- The attachment doesn't connect back immediately
- It downloads extra C2 malware, hides it in a folder like `C:\Temp`, and runs it as a new, stealthy process
- Why: the attack survives if the victim deletes the original attachment
- Examples:
  - [Recent ransomware cases](https://umbrella.cisco.com/blog/cybersecurity-threat-spotlight-ransomware-trojans-loaders)
  - [APT29 phishing campaign](https://cloud.google.com/blog/topics/threat-intelligence/tracking-apt29-phishing-campaigns#:~:text=Mandiant%20also%20identified%20APT29%20utilizing)

## Simple vs Advanced

| | Simplest C2 | Advanced C2 |
|---|---|---|
| Who connects back | The phishing attachment | A separate malware dropped later |
| Survives deleting the attachment | No | Yes |
| Where it lives | Original file location | Hidden folder like `C:\Temp` |
| Process | The attachment | New stealthy process |

## Detection Tips

- Ties to Ingress Tool Transfer: the download step (Event ID 1, 11, 22) is how the second-stage C2 arrives
- Sysmon Event ID 3: repeated outbound connections from one process to the same external IP
- Regular intervals (a check-in every N seconds or minutes) means beaconing, same pattern as the perimeter-log and Sysmon notes
- Non-standard ports like `4444` are a classic C2 sign, but C2 can also use ports 80 and 443
- A process running from `C:\Temp`, `ProgramData`, or `Downloads` that makes network connections is suspicious
- `ProcessId` links the connection to the process; the process tree shows how it started
- Splunk starting point (field names may differ in your data):

        index=windowslogs EventID=3 | stats count by Image, DestinationIp, DestinationPort | sort - count

---

# Persistence: Backdoored Users

Persistence is maintaining reliable, long-term access that survives reboots and password changes. MITRE tactic: [Persistence](https://attack.mitre.org/tactics/TA0003/).

## Persistence Lifespan

- Data stealers: breach, collect, exfiltrate, exit, all within minutes
- Most other attacks: need access for days or months after Initial Access

## Persisting via RDP

An exposed service (weak RDP, vulnerable mail server, misconfigured web app) lets attackers return until it's fixed. They often add a second method:

- Hidden vulnerability or backdoor in the breached service, e.g. a [web shell](https://attack.mitre.org/techniques/T1505/003/)
- New user ([T1136](https://attack.mitre.org/techniques/T1136/)), made administrator ([T1098](https://attack.mitre.org/techniques/T1098/007/)), used for later RDP logins

## Managing Users on Windows

- GUI: search "Computer Management" or run `lusrmgr.msc`
- Command line:

        # 1. Create the "mr.backd00r" user
        CMD C:\> net user "mr.backd00r" "p@ssw0rd!" /add
        PS  C:\> New-LocalUser "mr.backd00r" -Password [...]

        # 2. Add the user to Administrators
        CMD C:\> net localgroup Administrators "mr.backd00r" /add
        PS  C:\> Add-LocalGroupMember "Administrators" -Member "mr.backd00r"

## Detection Events

| Event ID | Stage | What it means |
|---|---|---|
| 4720 | Account created | Possible backdoor account |
| 4732 | Added to a security group | Privilege grant (`Administrators`, `Remote Desktop Users`) |
| 4724 | Password reset | Old or unused account taken over |

### Why a New User Needs a Group

- Default users can't log in via RDP and have no admin rights
- So attackers add the account to `Administrators` or `Remote Desktop Users`

### Password Reset Variant

- Advanced attackers reset an old or unused account instead of creating a new one
- Quieter: no new account appears in the user list

## Investigation Questions (4720)

Don't rely on suspicious names like "hacker". Ask:

1. Who created the account? Can they confirm it?
2. What is the creator's login source IP and time? Is it expected?
3. What other suspicious events are in the creator's session?

## Screenshot Walkthrough

All three events share the same subject and **Logon ID `0x2C7896`**, meaning one session did everything:

| Time | Event | What happened |
|---|---|---|
| 2:35:14 PM | 4720 | `THM-PC\Administrator` created `itsupport` |
| 2:35:40 PM | 4732 | `itsupport` added to `BUILTIN\Administrators` |
| 3:35:37 PM | 4724 | `Administrator` reset the password of `j.adams` |

- Create-then-admin within about 26 seconds is the classic backdoor pattern
- In the 4732 event, `Account Name` shows `-`, so read the `Security ID` (`THM-PC\itsupport`)
- Same events as the earlier User Management note (4720 / 4732 / 4724), now framed as persistence

## Detection Tips

- Pivot on the Logon ID: find the 4624 logon, then the source IP
- Sysmon Event ID 1: `net.exe` or `net1.exe` with `user ... /add` or `localgroup Administrators ... /add`, and PowerShell `New-LocalUser` / `Add-LocalGroupMember`
- Check the parent process: a backdoor command launched by a phishing binary or a web server process is the strongest signal
- Alert on every 4732 into `Administrators` or `Remote Desktop Users`
- Splunk starting point (field names may differ in your data):

        index=windowslogs EventID IN (4720, 4732, 4724) | table _time EventID SubjectUserName SubjectLogonId TargetUserName

# Malware Persistence: Services and Scheduled Tasks

Backdoored users only work when the attacker can log in remotely. After phishing or USB infections, the malware itself must keep running and reconnect to the C2 after a reboot. Hundreds of Windows persistence methods exist; start with the two most common.

## Methods Compared

| Method | Attack example | Logging |
|---|---|---|
| Windows Service (runs after startup) | `sc create "BadService" binpath= "C:\malware.exe" start= auto` | `sc.exe` launch: Sysmon 1; service creation: Security 4697 |
| Scheduled Task (runs after startup) | `schtasks /create /tn "BadTask" /tr "C:\malware.exe" /sc onstart /ru System` | `schtasks.exe` launch: Sysmon 1; task creation: Security 4698 |

- The space after `binpath=` and `start=` is required by `sc.exe` syntax

## Detecting Malicious Services

- View with `services.msc` or by searching "Services"
- Creating or modifying one needs admin rights and `sc.exe`
- Attackers use this often ([MITRE examples](https://attack.mitre.org/techniques/T1543/003/), general knowledge link)

Three detection options:

1. Sysmon Event ID 1: the `sc.exe create` command
2. Security Event ID `4697` or System Event ID `7045`: service creation
3. Suspicious process with a `services.exe` parent

### Screenshot: Security Event 4697

| Field | Value |
|---|---|
| Subject | `THM-PC\user`, Logon ID `0x35A11` |
| Service Name | `BadService` |
| Service File Name | `C:\malware.exe` |
| Service Type | `0x10` |
| Service Start Type | `2` (auto start) |
| Service Account | `LocalSystem` |

- Process tree: `services.exe` → `svchost.exe` (only in some cases) → `C:\malware.exe`
- It appears in the Services window as `BadService`
- Red flags: file name outside `System32` (here `C:\`), runs as `LocalSystem`, auto start, unfamiliar name

## Detecting Malicious Scheduled Tasks

- Heavily used by Windows and apps (update checks, hourly backups)
- GUI: `taskschd.msc` or "Task Scheduler"; CLI: `schtasks.exe`
- Easy to configure and hide, so the **most common** persistence method
- Real cases: [APT28](https://quointelligence.eu/2020/09/apt28-zebrocy-malware-campaign-nato-theme/#:~:text=Next%2C%20the%20malware%20creates%20a%20new%20scheduled%20task), [APT41](https://cloud.google.com/blog/topics/threat-intelligence/apt41-us-state-governments/#:~:text=APT41%20has%20leveraged%20the%20following%20Windows%20scheduled%20tasks%20for%20persistence)

Three detection options:

1. Sysmon Event ID 1: the `schtasks.exe /create` command
2. Security Event ID `4698`: task creation
3. Suspicious process with a `svchost.exe [...] -s Schedule` parent

### Screenshot: Security Event 4698

| Field | Value |
|---|---|
| Subject | `THM-PC\user`, Logon ID `0x35A11` |
| Task Name | `\BadTask` |
| Command | `C:\malware.exe` |

- Process tree: `services.exe` → `svchost.exe -k netsvcs -p -s Schedule` → `C:\malware.exe`
- In Task Scheduler it shows as `BadTask`, trigger "At system startup"
- Hiding in plain sight: legitimate tasks sit right beside it (`npcapwatchdog`, Microsoft Edge tasks)

## Services vs Tasks

| | Service | Scheduled Task |
|---|---|---|
| Create command | `sc create` | `schtasks /create` |
| Security event | 4697 (also System 7045) | 4698 |
| Parent of malware | `services.exe` | `svchost.exe -s Schedule` |
| Management tool | `services.msc` | `taskschd.msc` |
| Popularity with attackers | Common | Most common |

## Detection Tips

- Both screenshots share Logon ID `0x35A11`: pivot to the 4624 logon for source IP, then trace the session
- Judge the **binary path**: anything in `C:\`, `Temp`, `ProgramData`, `Users\Public` is suspicious
- Judge the **parent**: a service or task that launches a user-writable binary is the strongest signal
- Same method as the core Windows process notes: `svchost.exe` should have `services.exe` as parent, so a child of it deserves a look at the command line
- Splunk starting points (field names may differ in your data):

        index=windowslogs EventID=1 (Image="*\\sc.exe" CommandLine="*create*") OR (Image="*\\schtasks.exe" CommandLine="*/create*") | table _time Image CommandLine ParentImage User

        index=windowslogs EventID IN (4697, 4698) | table _time EventID SubjectUserName SubjectLogonId

---

# Per-User Persistence: Startup Folder and Run Keys

Services and scheduled tasks run at boot and need admin rights. Startup folder and Run keys run only when a specific user logs in, and are used by both legitimate tools and malware. Both share one MITRE technique: [T1547.001](https://attack.mitre.org/techniques/T1547/001/).

## Methods Compared

| Method | Attack example | Logging |
|---|---|---|
| Startup Folder | `copy C:\malware.exe "%AppData%\Microsoft\Windows\Start Menu\Programs\Startup\malware.exe"` | New startup item: Sysmon Event ID 11 |
| Run Key | `reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v BadKey /t REG_SZ /d "C:\malware.exe"` | New registry value: Sysmon Event ID 13 |

## Startup Folder

- Meant as an easy way for inexperienced users to run a program at login: drop the program or shortcut in the folder
- Paths:

        C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\
        C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp      (all users)

- Legitimate programs rarely use it, so the folder is usually **empty**; anything in it is worth a look
- Real malware example: Lumma Stealer (link not in the paste)
- Detect: Sysmon Event ID 11 (file created) inside the Startup folder

### Screenshot: Sysmon Event 11

| Field | Value |
|---|---|
| User | `THM-PC\bob` |
| ProcessId | `5928` |
| Image | `C:\Users\bob\Downloads\invoice.pdf.exe` |
| TargetFilename | `C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\malware.exe` |

- The **Image** is the process that dropped the file: a double-extension phishing binary in `Downloads`
- That makes the chain: phishing attachment → copies itself into Startup
- Process tree at login: `explorer.exe` → `%AppData%\...\Startup\malware.exe`

## Run Keys

- Same idea as the Startup folder, but the entry is a **registry value** pointing to the program

        HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
        HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run      (all users)

- View with `regedit.exe` or "Registry Editor"
- Detect: Sysmon Event ID 13 (registry value set) on the Run keys

### Screenshot: Sysmon Event 13

| Field | Value |
|---|---|
| User | `THM-PC\bob` |
| ProcessId | `5932` |
| Image | `C:\Users\bob\Downloads\invoice.pdf.exe` |
| TargetObject | `HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Run\BadRunKey` |
| Details | `C:\malware.exe` |

- Registry Editor shows `BadRunKey` → `C:\malware.exe` beside legitimate entries (`1Password`, `OpenVPN-GUI`, Microsoft Edge)
- Note: Sysmon logs the HKCU path as `HKU\<SID>`, so search for that form
- Process tree at login: `explorer.exe` → `C:\malware.exe`

## Startup Folder vs Run Key

| | Startup Folder | Run Key |
|---|---|---|
| What's added | A file | A registry value |
| Sysmon event | 11 | 13 |
| Parent at login | `explorer.exe` | `explorer.exe` |
| Normally | Empty | Has legitimate entries |
| Hiding spot | Hard: usually empty | Easy: blends with real entries |

## Detection Tips

- Both screenshots show the **same Image** (`invoice.pdf.exe`): the dropper did both, so check what else that process did by `ProcessId`
- Judge the **path in Details**: `C:\malware.exe`, `Temp`, `ProgramData`, `Users\Public` stand out against `Program Files`
- `explorer.exe` as parent blends in with normal user activity, so work from the **creation event** back to the dropper
- User-level persistence runs without admin rights, so it fits phishing infections
- Same event IDs as the earlier Sysmon persistence note (11, 13), now with real investigation context
- Splunk starting points (field names may differ in your data):

        index=windowslogs EventID=11 TargetFilename="*\\Start Menu\\Programs\\Startup\\*" | table _time Image TargetFilename User

        index=windowslogs EventID=13 TargetObject="*\\CurrentVersion\\Run\\*" | table _time Image TargetObject Details User

---

# Need for Persistence, Threat Detection Recap, and Ransomware

Attackers stay on a host because the host is worth more over time than as a one-off data grab. Complex attacks like Active Directory compromise and ransomware all start from one simple breach.

## Why Attackers Want Persistence

| Reason | Real example |
|---|---|
| Add the host to a botnet for further attacks | Kraken Botnet: crypto miner, data stealer, and C2 in one |
| Spy on the victim in a state-sponsored campaign | Volt Typhoon: undetected in the US electric grid for nearly a year |
| Use the victim as an entry point into a network that could take months to breach | A case where attackers spent 29 days breaching a full network |

- Your paste was scrambled here: the bullet list was split in half by the "Threat Detection Recap" text, so I rebuilt it
- No links came with these examples, so none are included

## Active Directory and Ransomware

- The third reason matters most: a Windows network usually means a large Active Directory
- AD brings its own attacks, detections, and threats; the main one is **ransomware**
- Example: McLaren hospitals, 743,000 patients affected
- Typical sequence: servers encrypted, data stolen, ransom notes printed on every office printer
- Goal for defenders: stop the attack right after Initial Access, before [Impact](https://attack.mitre.org/tactics/TA0040/)

## Ransom Note (Screenshot: INC Ransom)

<img width="1600" height="1160" alt="Alleged Mclaren ransom note" src="https://github.com/user-attachments/assets/4cdea062-fab6-4665-8a9a-8620e665ff39" />


| Note feature | What it tells you |
|---|---|
| "Stolen **and** encrypted" | Double extortion: restoring from backup doesn't solve the leak threat |
| Leak site | Data theft happened earlier; check exfiltration logs |
| "Business only" tone | Financially motivated, not state-sponsored |


| Tactic | Covered (highlighted) | Matching notes |
|---|---|---|
| Initial Access | Exploit Public-Facing Application, External Remote Services, Phishing (4/4), Replication Through Removable Media | Exposed RDP, phishing, USB |
| Execution | Command and Scripting Interpreter (7/7), Scheduled Task/Job (2/2) | PowerShell, LNK payloads |
| Persistence | Account Manipulation (3/3), Boot or Logon Autostart Execution (10/10), Create Account (2/2), Create or Modify System Process (1/1), External Remote Services, Scheduled Task/Job (2/2) | Backdoored users, services, tasks, Run keys, Startup folder |
| Credential Access | Brute Force (4/4), Credentials from Password Stores (3/3), Steal Web Session Cookie, Unsecured Credentials (4/4) | RDP brute force, data stealers |
| Discovery | Account, File and Directory, Network Service, Process, Software (1/1), System Information, System Owner/User | Discovery commands |
| Collection | Archive Collected Data (3/3), Automated Collection, Browser Session Hijacking, Data from Local System | Collection, stealers |
| Command and Control | Application Layer Protocol (5/5), Ingress Tool Transfer | C2, tool transfer |
| Exfiltration | Exfiltration Over C2 Channel, Exfiltration Over Web Service (4/4) | Exfiltration to cloud, Telegram, GitHub |
| Impact | Data Encrypted for Impact, Financial Theft | Ransomware (next topic) |


## Detection Tips

- Ransomware is the end of a chain, not the start: earlier stages (phishing, RDP breach, persistence, exfiltration) are where you catch it
- Persistence found on a host raises the severity: the attacker planned to stay
- Check for exfiltration before encryption: the leak-site threat in the note means data likely left first (see the exfiltration notes)
- Use the matrix as a checklist: for any incident, mark which tactics you have evidence for and which you haven't looked at yet
