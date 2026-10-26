# Linux Log Format and Basics

Linux servers get attacked too, and the number of Linux-targeted intrusions is growing. SOC analysts need to know how Linux logging works.

## Scope

- "Linux" here means Debian, Ubuntu, CentOS, RHEL
- Focus is servers without a GUI; desktop logging is not covered

## Linux vs Windows Logging

| | Linux | Windows |
|---|---|---|
| Format | Plain text files | Binary `.evtx` |
| Reading | Any text editor, `cat`, `grep` | Event Viewer or PowerShell |
| Event codes | None | Event IDs (4624, 4625...) |
| Structure | Less structured, no strict format | Structured fields |
| Location | Mostly `/var/log` | `C:\Windows\System32\winevt\Logs` |

- No event IDs means you search by keywords, so filtering skill matters more

## Syslog

`/var/log/syslog` is an aggregated stream of system events.

    cat /var/log/syslog | head

Example lines:

    2025-08-13T13:57:49.388941+00:00 thm-vm systemd-timesyncd[268]: Initial clock synchronization to Wed 2025-08-13 13:57:49.387835 UTC.
    2025-08-13T14:05:01.999677+00:00 thm-vm CRON[1027]: (root) CMD (command -v debian-sa1 > /dev/null && debian-sa1 1 1)

Line anatomy:

| Part | Example | Meaning |
|---|---|---|
| Timestamp | `2025-08-13T14:05:01.999677+00:00` | ISO format with timezone offset (UTC here) |
| Hostname | `thm-vm` | Machine that logged it |
| Process[PID] | `CRON[1027]` | Program and its process ID |
| Message | `(root) CMD (...)` | What happened |

- Timestamps carry a timezone offset, unlike Windows Event Viewer's system time

## Filtering Logs

Thousands of events, few useful ones. Narrow down with `grep`.

    cat /var/log/syslog | grep CRON       # only cron jobs
    cat /var/log/syslog | grep -v CRON    # exclude cron jobs

Example output:

    2025-08-13T14:17:01.025846+00:00 thm-vm CRON[1042]: (root) CMD (cd / && run-parts --report /etc/cron.hourly)
    2025-08-13T14:30:01.014532+00:00 thm-vm CRON[1048]: (root) CMD (date > mycrondebug.log)

- `grep -v` = invert match, drops noise (same exclude idea as the Sysmon config notes)
- The last line writes `date` into `mycrondebug.log`, which looks like a custom, non-system job; it is the type of entry to check

## Discovering Logs

Not sure where logins are logged? List the folder, then grep for keywords.

    ls -l /var/log
    grep -R -E "auth|login|session" /var/log

Key files seen:

| File | Content |
|---|---|
| `auth.log` | Authentication events (logins, sudo, SSH) |
| `syslog` | General system events |
| `kern.log` | Kernel messages |
| `dpkg.log` | Package install/remove history |
| `apt/` | Package manager logs |
| `audit/` | Audit logs (auditd) |
| `journal/` | systemd journal (binary) |

- Permissions matter: `auth.log`, `syslog`, `kern.log` are owned by `syslog`, group `adm`, mode `rw-r-----`, so you need root or the `adm` group to read them
- `grep -R` searches recursively through every file in the folder

## Logging Caveats

- Linux lets you change log format, verbosity, and storage location easily
- Distributions customize logging, so your system may look different, or a log may not exist
- Never assume a file exists; list the folder first

## Detection Tips

- `auth.log` is the first stop for logins and brute force, the Linux counterpart of Windows 4624/4625
- Debian/Ubuntu use `auth.log`; RHEL/CentOS use `/var/log/secure` instead (general knowledge, not in the lesson)
- Cron entries matter for persistence, covered in the Windows persistence notes as scheduled tasks; Linux equivalent is cron
- `dpkg.log` and `apt/` show when software was installed, useful for spotting attacker tools
- Some logs are **binary** (`journal/`): read with `journalctl`, not `cat` (general knowledge)
- Attackers can edit or delete plain text logs, so forward logs to a SIEM
- Handy filter combinations:

        grep "Failed password" /var/log/auth.log
        grep -i "session opened" /var/log/auth.log
        grep -v CRON /var/log/syslog | less

---

# Linux Authentication Logs (auth.log)

The first log to check on a Linux server: `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL-based). Despite the name, it also holds user management events and sudo commands.

## Log Format

Each line: **event time → hostname → service → message**

- Plain, unstructured text, so you filter by keyword (no event IDs like Windows)

## Login and Logout Events

Every successful logon and logoff is logged. Filter with:

    cat /var/log/auth.log | grep -E 'session opened|session closed'

| Login type | PAM tag | Example |
|---|---|---|
| Local (keyboard) | `login:session` | `session opened for user bob(uid=1001) by bob(uid=0)` |
| SSH | `sshd:session` | `session opened for user alice(uid=1002)` |
| SMB (Samba) | `samba:session` | `session opened for user alice(uid=1002)` |
| Cron job | `cron:session` | `session opened for user root(uid=0) by root(uid=0)` |
| Sudo | `sudo:session` | `session opened for user root(uid=0) by carol(uid=1003)` |

- Local sample: Bob's session ran 16:04 to 19:23 (opened, then closed)
- Sudo sample: Carol ran `sudo su` to become root
- In `sudo:session`, the name after `by` is the real person who escalated (`carol`)
- In `login` and `sshd` lines, `by ...(uid=0)` is just the root login process, so don't read it as the actor

## SSH-Specific Events

SSH logs to the same file but in a different format:

    cat /var/log/auth.log | grep "sshd" | grep -E 'Accepted|Failed'

Format: `<result> <auth-method> for <user> from <ip>`

    Failed password for root from 222.124.17.227 port 50293 ssh2
    Failed password for admin from 138.204.127.54 port 52670 ssh2
    Accepted publickey for bob from 10.19.92.18 port 55050 ssh2: <key>

| Part | Value in sample | Meaning |
|---|---|---|
| Result | `Failed` / `Accepted` | Outcome |
| Method | `password` / `publickey` | How they authenticated |
| User | `root`, `admin`, `bob` | Targeted account |
| Source | `222.124.17.227` | Where it came from |

- Failures against `root` and `admin` from external IPs are typical brute force targets
- Bob's `Accepted publickey` from a private IP (`10.19.92.18`) is normal-looking internal access

## User Management Events

Search for the command names:

    cat /var/log/auth.log | grep -E '(passwd|useradd|usermod|userdel)\['

| Time | Event | Meaning |
|---|---|---|
| 2023-02-01 | `password for 'ubuntu' changed by 'root'` | Password change |
| 2025-08-07 22:11:11 | `delete user 'oldbackdoor'` | User deleted |
| 22:11:29 | `new user: name=backdoor, UID=1002...shell=/bin/sh` | User created |
| 22:11:54 | `add 'backdoor' to group 'sudo'` (and shadow group `sudo`) | Privilege granted |

- The sample reads as a backdoor sequence: remove an old backdoor, create a new one, give it sudo within about 25 seconds
- The first line is from 2023, so it's an old, unrelated event mixed into the output
- Same create-then-grant-admin pattern as Windows `4720` then `4732`

## Commands Run With Sudo

    cat /var/log/auth.log | grep -E 'COMMAND='

    sudo: ubuntu : TTY=pts/0 ; [...] COMMAND=/usr/bin/systemctl stop edr
    sudo: ubuntu : TTY=pts/0 ; [...] COMMAND=/usr/bin/ufw status numbered
    sudo: ubuntu : TTY=pts/0 ; [...] COMMAND=/usr/bin/su

| Command | Attacker intent |
|---|---|
| `systemctl stop edr` | Disable security tooling (defense evasion) |
| `ufw status numbered` | Read firewall rules |
| `su` | Switch to root |

- Which events appear depends on system configuration and installed packages
- Stopping the EDR is the biggest red flag in this sequence

## Quick Reference

| Goal | Filter |
|---|---|
| Logins and logouts | `grep -E 'session opened\|session closed'` |
| SSH successes and failures | `grep sshd \| grep -E 'Accepted\|Failed'` |
| User changes | `grep -E '(passwd\|useradd\|usermod\|userdel)\['` |
| Sudo commands | `grep 'COMMAND='` |

## Detection Tips

- Count failed SSH logins per source IP:

        grep "Failed password" /var/log/auth.log | grep -oE 'from [0-9.]+' | sort | uniq -c | sort -nr

- Brute force that ends in `Accepted` from the same IP means it worked, so escalate
- Check `Accepted password` from external IPs more closely than `publickey`
- New user plus `sudo` group add outside change windows is a persistence signal
- Sudo `COMMAND=` lines are your Linux process-creation log for privileged actions
- Attackers with root can edit `auth.log`, so forward logs to a SIEM
- Windows equivalents: `4625` failed logon, `4624` successful logon, `4720` user created, `4732` group add

---

# Linux Generic, App-Specific, and Bash History Logs

Linux scatters events across `/var/log`, and different tools fill different gaps. Most of these logs are noisy, so know which ones are worth your time.

## Generic System Logs

Content and format differ by OS.

| File | Content | Distro |
|---|---|---|
| `/var/log/kern.log` | Kernel messages and errors | Most |
| `/var/log/syslog` (or `/var/log/messages`) | Consolidated stream of system events | Debian/Ubuntu (`syslog`), RHEL (`messages`) |
| `/var/log/dpkg.log`, `/var/log/apt/` | Package manager logs | Debian-based |
| `/var/log/dnf.log`, `/var/log/yum.log` | Package manager logs | RHEL-based |

- Valuable in DFIR, but rarely used in the daily SOC routine: noisy and hard to parse
- Package logs show when software was installed, useful for spotting attacker tools

## App-Specific Logs

To monitor a specific program, use its own logs:

| Log type | What it answers |
|---|---|
| Database | Which queries were run |
| Mail | Phishing investigations |
| Container | Anomalies in containers |
| Web server | Which pages were opened, when, and by whom |

### Nginx Web Access Log

    cat /var/log/nginx/access.log

    10.0.1.12 - - [11/08/2025:14:32:10 +0000] "GET / HTTP/1.1" 200 3022
    10.0.1.12 - - [11/08/2025:14:32:14 +0000] "GET /login HTTP/1.1" 200 1056
    10.0.1.12 - - [11/08/2025:14:33:09 +0000] "POST /login HTTP/1.1" 302 112
    10.0.4.99 - - [11/08/2025:17:11:20 +0000] "GET /images/logo.png HTTP/1.1" 200 5432
    10.0.5.21 - - [11/08/2025:17:56:23 +0000] "GET /admin HTTP/1.1" 403 104

One line per web request:

| Field | Example | Meaning |
|---|---|---|
| Client IP | `10.0.1.12` | Who made the request |
| Timestamp | `[11/08/2025:14:32:10 +0000]` | When (with timezone offset) |
| Request | `"GET /login HTTP/1.1"` | Method, path, protocol |
| Status | `200`, `302`, `403` | Server response |
| Size | `3022` | Response bytes |

Reading the sample:
- `10.0.1.12`: normal flow, home page, login page, login `POST` returning `302` (redirect after login)
- `10.0.4.99`: harmless static file request
- `10.0.5.21`: `GET /admin` returned `403`, so someone tried a restricted page and was blocked
- The `403` is worth a look: repeated hits like this suggest probing
- This sample omits referrer and User-Agent, which many real configs include

## Bash History

Records each command run after pressing Enter.

| Command | Purpose |
|---|---|
| `cat ~/.bash_history` | Read past sessions' commands |
| `history` | Current and past session commands, numbered |

- Commands sit in memory during the session
- They're written to `~/.bash_history` **only at logout**
- One file per user (`/home/ubuntu/.bash_history`)

Sample:

    echo "hello" > world.txt
    nano /etc/ssh/sshd_config
    sudo su

- Editing `sshd_config` then `sudo su` is the kind of sequence to review: SSH settings and root access

### Why SOC Rarely Uses It

- Doesn't track non-interactive commands (OS, cron jobs, web servers)
- Written at logout, so a live or killed session may leave nothing
- Easy for attackers to avoid:

| Evasion | Example | Why it works |
|---|---|---|
| Leading space | ` echo "You will never see me in logs!"` | Bash skips these when `HISTCONTROL` includes `ignorespace` (set by default on Ubuntu; general knowledge) |
| Hide commands in a script | `nano legit.sh && ./legit.sh` | History records the script launch, not what's inside it |
| Switch shell | `sh` | `/bin/sh` doesn't save Bash history |

More evasion (general knowledge, not in the lesson):
- `unset HISTFILE` or `HISTFILE=/dev/null` stops saving
- `history -c` clears the in-memory history
- Deleting or truncating `~/.bash_history`

## Detection Tips

- Parallels to the Windows notes:
  - Bash history is similar to the PowerShell history file: interactive only, no output, easy to dodge
  - Process creation logging (Sysmon Event ID 1) is the stronger source; on Linux that means `auditd` (`execve` events), covered in the web shell notes
- A missing or empty `.bash_history` for an active user is suspicious
- Check **every** user's file, including `root` (`/root/.bash_history`)
- Combine sources: `auth.log` sudo `COMMAND=` lines show privileged commands that history may miss
- Web logs: look for bursts of `403` / `404` from one IP (probing) and `POST /login` bursts (brute force)
- Quick filters:

        grep ' 403 ' /var/log/nginx/access.log
        awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -nr | head

---

# Linux Runtime Monitoring and System Calls

By default, Linux logs no process creation, file changes, or network events (collectively **runtime events**), so questions like "Which programs did Bob launch today?" or "Who deleted my home folder?" can't be answered. Windows has the same gap, which is why [Sysmon](https://tryhackme.com/room/windowsloggingforsoc) is added there; Linux needs an extra tool too.

## Runtime Events

| Question | Needs |
|---|---|
| Which programs did Bob launch today? | Process creation logs |
| Who deleted my home folder, and when? | File change logs |
| What did this host connect to? | Network event logs |

- Existing sources don't cover this: `auth.log` only shows sudo and logins, and Bash history is interactive-only and easy to evade (see previous notes)

## System Calls (Syscalls)

- A system call is how a program asks the OS for a service: open a file, create a process, access the camera
- Linux has [300+ syscalls](https://man7.org/linux/man-pages/man2/syscalls.2.html)
- Example: `execve` executes a program
- The lesson's flowchart image didn't come through; the flow, in general terms: program → system call → kernel → hardware/resource

| Syscall | Runtime event it reveals |
|---|---|
| `execve` | A program was launched |
| `openat` | A file was opened (general knowledge) |
| `unlink` | A file was deleted (general knowledge) |
| `connect` | A network connection was started (general knowledge) |

- `execve` is from the lesson; the other three are common syscalls added as general knowledge
- `execve` is the Linux counterpart of Sysmon Event ID 1; the file and network ones match Event IDs 11 and 3

## Why This Matters for Detection

- All modern EDRs and logging tools monitor syscalls and turn them into readable logs
- Attackers have almost no way around syscalls, since every action goes through them
- So the job is: **pick which syscalls to log and monitor**

| | Windows | Linux |
|---|---|---|
| Default runtime logging | None | None |
| Extra tool | Sysmon | `auditd` and similar (general knowledge: covered next in this series) |
| Process creation | Event ID 1 | `execve` |

## Detection Tips

- The web shell notes already used `auditd` (`ausearch -k web_shell`, `execve` events): it's one tool built on this idea
- Logging every syscall is far too noisy; a good config logs only high-value ones (`execve`, file changes in sensitive paths, network connects), same "tune your config" lesson as Sysmon
- Without runtime logging, a Linux investigation is mostly guesswork: confirm it's enabled before an incident, not during

---

# Auditd (Audit Daemon)

Auditd is the built-in Linux auditing tool that SOC teams use for runtime monitoring. It watches system calls and logs process, file, and network events that Linux doesn't log by default.

## Rules

- Rules live in `/etc/audit/rules.d/` and define which system calls to monitor and which filters to apply
- The lesson's rules screenshot didn't come through. It showed four rules:
  - One detecting `wget`
  - Two detecting file operations
  - One detecting network connections made by `python3`
- Rule syntax below is from general knowledge, as an illustration of the idea:

        -a always,exit -F arch=b64 -S execve -F exe=/usr/bin/wget -k proc_wget
        -w /etc/ssh/sshd_config -p wa -k file_sshconf

- `-k` sets the **key**, a tag you search by later (`proc_wget`, `file_sshconf`)

### Balance Matters

- Logging every process, file, and network event produces gigabytes per day
- More logs don't mean better detection: an attack buried in terabytes of noise is still invisible
- SOC teams log the highest-risk events only (same tuning lesson as the Sysmon config notes)

## Reading the Logs

- Raw logs: `/var/log/audit/audit.log` (live view)
- Easier: `ausearch`, which formats output and supports filters

        ausearch -i -k <key>

- `-i` turns numeric IDs into readable names
- `-k` filters by the rule's key

## Example 1: Process Execution (`proc_wget`)

    ausearch -i -k proc_wget

    type=PROCTITLE ... proctitle=wget https://files.tryhackme.thm/report.zip
    type=CWD       ... cwd=/root
    type=EXECVE    ... argc=2 a0=wget a1=https://files.tryhackme.thm/report.zip
    type=SYSCALL   ... syscall=execve [...] ppid=3752 pid=3888 auid=ubuntu uid=root tty=pts1 exe=/usr/bin/wget key=proc_wget

One command produces **four lines**:

| Line type | Shows |
|---|---|
| `PROCTITLE` | The process command line |
| `CWD` | Current working directory |
| `EXECVE` | The arguments passed to the program |
| `SYSCALL` | System call details (below) |

- All four share the same event number (`:2219`), which ties them together as one event

### Key SYSCALL Fields

| Field | Example | Meaning |
|---|---|---|
| `pid` / `ppid` | `3888` / `3752` | Process ID and parent ID; build the process tree |
| `auid` | `ubuntu` | Audit user: the account originally used to log in (keyboard or SSH) |
| `uid` | `root` | The user who ran the command |
| `tty` | `pts1` | Session identifier; separates people on the same server |
| `exe` | `/usr/bin/wget` | Absolute path of the executed binary |
| `key` | `proc_wget` | Tag from the rule, used to filter |

- `auid` vs `uid`: `auid` stays the **original login** even after `sudo` or `su`, while `uid` changes
- Here `auid=ubuntu`, `uid=root` means ubuntu logged in and ran `wget` as root
- That makes `auid` the field that attributes an action to a real person
- Reading the sample: a root-run download of `report.zip` from an external domain, a Linux ingress tool transfer pattern (see the Windows ingress notes)

## Example 2: File Changes (`file_sshconf`)

    ausearch -i -k file_sshconf

    type=PROCTITLE ... proctitle=nano /etc/ssh/sshd_config
    type=CWD       ... cwd=/
    type=PATH      ... item=0 name=/etc/ssh/sshd_config [...]
    type=SYSCALL   ... syscall=openat [...] ppid=3752 pid=3899 auid=ubuntu uid=root tty=pts1 exe=/usr/bin/nano key=file_sshconf

- Auditd caught `nano` opening `/etc/ssh/sshd_config`
- New line type: `PATH` shows the file touched
- Syscall here is `openat` (file), not `execve` (process)
- Same `ppid=3752` and `tty=pts1` as the `wget` event, so both came from one shell session
- Opening a file isn't proof of a change; confirm by comparing the file against a known-good copy (general knowledge)

### What SOC Teams Watch

- SSH configuration files
- Cron job definitions
- System settings
- Other critical files and directories

## Auditd Alternatives

Auditd output is verbose, hard to read, and hard to ingest into a SIEM.

| Tool | Best for |
|---|---|
| Sysmon for Linux | Teams already using Sysmon and XML configs |
| Falco | Open source, modern, ideal for containerized systems |
| Osquery | Broad security use cases |
| EDR products | Most track Linux runtime events |

- All of them work on the same principle: **monitoring system calls**
- Learn syscalls once and each tool is easier; it also explains why an action was logged a certain way, or not logged at all

## Detection Tips

- The pivot fields are the same as other notes: `pid`/`ppid` for the process tree (like Sysmon's `ProcessId`), `auid` for the person (like the Windows Logon ID)
- Rebuild a tree: find the event where `pid` equals your event's `ppid`
- Red flags in `exe` or `proctitle`: tools run from `/tmp`, `/dev/shm`, or a home folder
- Red flags in `cwd`: `/tmp`, `/var/tmp`, `/dev/shm`
- `uid=root` with a different `auid` means someone escalated, so check `auth.log` for the `sudo` line (see the auth.log note)
- Typical high-value keys to build (general knowledge):
  - Downloaders: `wget`, `curl`
  - Persistence: `/etc/crontab`, `/etc/cron.d/`, `~/.ssh/authorized_keys`
  - Account files: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`
  - Network use by scripting tools: `python3`, `nc`
- Count events per key to see what dominates:

        ausearch -i -k proc_wget | grep -c "type=SYSCALL"
