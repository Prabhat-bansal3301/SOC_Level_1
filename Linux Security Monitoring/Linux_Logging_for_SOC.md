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
