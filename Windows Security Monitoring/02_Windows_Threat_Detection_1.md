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
