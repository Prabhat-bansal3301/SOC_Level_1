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
