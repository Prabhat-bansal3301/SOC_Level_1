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
