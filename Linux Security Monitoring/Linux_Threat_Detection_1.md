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
