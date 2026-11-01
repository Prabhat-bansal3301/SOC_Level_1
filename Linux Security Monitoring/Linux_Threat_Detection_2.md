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
