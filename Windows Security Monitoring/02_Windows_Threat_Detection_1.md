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
