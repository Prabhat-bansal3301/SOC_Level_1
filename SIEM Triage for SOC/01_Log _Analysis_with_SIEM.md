# SIEM Log Sources, Time Pitfalls, and Normalisation

Organisations send logs from many resources into a SIEM, where analysts use them for analysis and correlation. Think of the organisation as a tree and the resources as its roots: they differ per organisation but form one logical structure.

## Main Log Sources

| Source | Examples | Why it matters |
|---|---|---|
| Host-based | Workstations, servers (web, SQL, DNS) | Nearly every attack involves hosts, so this data is invaluable in an investigation |
| Network-based | Firewalls, routers, IDS/IPS | Shows how devices communicate; roots supporting the branches |
| Web-based | Web application logs | Web vulnerabilities are a common way in, so web events need daily monitoring |

- Correlating different sources gives the complete picture (see the earlier host vs network log note)
- Also collected, but out of scope here:
  - Cloud platforms: AWS, Azure
  - Identity providers: Entra ID
  - Third-party applications

## Time Pitfalls

Time is a common SIEM challenge.

- Logs come from systems in different time zones
- Some use UTC, some local time, some have **no timezone at all**
- Your local time can differ from the SIEM's display time

### Example

| Item | Value |
|---|---|
| Your time zone | UTC-2 |
| SIEM display time zone | UTC+2 (logs normalised to it) |
| Your clock | 5 PM |
| Same event in the SIEM | 9 PM |

- The 4-hour gap is a **time zone difference**, not ingestion delay
- Always check which time zone each source and your SIEM use before reading a timeline

## Log Normalisation

- Log formats vary: JSON, XML, plain text
- Each system uses its own field names and structures
- **Normalisation** converts them into one consistent structure
- Result: searching, filtering, and linking events becomes much easier
- Without it, every log source is a different puzzle

## Examples From Earlier Notes

| Topic | Example |
|---|---|
| Time | Windows Event Viewer shows system time, not UTC; Linux `auth.log` timestamps carry an offset |
| Normalisation | The same source IP appears as `SourceIp` (Sysmon), `IpAddress` (Windows 4624), and `src_ip` (DNS and VPN logs) |

---

# Sysmon and Windows Event Logs in a SIEM (Splunk)

Sysmon is often an additional, sometimes the primary, Windows log source, giving deep visibility into process, network, file, and registry activity. Windows Event Logs add authentication, account, and service events. Together they let you follow one compromised host from the first alert to persistence.

## Sysmon in Splunk

Sysmon helps identify:
- Malicious process execution
- Network connections
- Possible process injection
- Registry changes
- File creation

### Example 1: Encoded PowerShell (Event ID 1)

    index=winenv EventCode=1 *powershell* AND *EncodedCommand*
    | table _time ComputerName ParentUser ParentImage ParentCommandLine Image CommandLine

- Finding on host `WINHOST05`: a malicious `update_config.js` ran from `C:\Users\Public`, which led `cmd.exe` to launch PowerShell with an encoded command
- Parent fields show **what launched PowerShell**, the key part of the process tree

### Example 2: Suspicious Network Connection (Event ID 3)

    index=winenv EventCode=3 ComputerName=WINHOST05
    | table _time ComputerName Image SourceIp SourcePort DestinationIp DestinationPort Protocol

- Finding: `PPn423.exe` running from the **Temp** folder connected to `83.222.191.2` on unusual port **9999**
- Next step: check the IP on TI platforms (see the IP enrichment note)
- The examples' logs are not in the lab Splunk; only the practice task's logs are

## Windows Event Logs

- More than **200** log channels exist, beyond Security, System, and Application

### Security Logs

The most referenced logs. They show:
- Authentication attempts
- Account creation or modification
- File and registry key access
- Process execution
- System restarts or log clearing
- Changes to audit or security policies

Example: a few hours after the first alerts, `WINHOST05` raised a user creation alert, so the attacker was probably still present.

    index=winenv EventCode=4720 OR EventCode=4722
    | table _time EventCode ComputerName Subject_Account_Name Target_Account_Name New_Account_Account_Name Keywords

- `4720` account created, `4722` account enabled
- Finding: a backup user account was created and enabled by `ted-admin`, a persistence mechanism

### System Logs

Record events from the OS and core services. Good for finding persistence or privilege escalation through services.

| Event ID | Meaning |
|---|---|
| 7045 | Service created |
| 7036 | Service started or stopped |

    index=winenv EventCode=7045 OR EventCode=7036 ComputerName=WINHOST05
    | table _time EventCode ComputerName Service_Name Service_Account Service_File_Name Message

- Finding: a service named **"User Updates"** was created and started, running `RNSfnsjdf.exe` from the Temp directory as **SYSTEM**
- The source reads this as a privilege escalation attempt, since the attacker previously only had the `ted-admin` account

## WINHOST05 Attack Timeline

| Step | Source | Finding |
|---|---|---|
| 1. Execution | Sysmon Event 1 | `update_config.js` in `C:\Users\Public`, `cmd.exe` then encoded PowerShell |
| 2. C2 | Sysmon Event 3 | `PPn423.exe` from Temp to `83.222.191.2:9999` |
| 3. Persistence | Security 4720/4722 | New account created and enabled by `ted-admin` |
| 4. Privilege escalation | System 7045/7036 | Service "User Updates" runs `RNSfnsjdf.exe` from Temp as SYSTEM |

- Staging folders (`Public`, `Temp`) and random-looking executable names match the filepath heuristics note

## Detection Tips

- Pivot by host: once one alert names a host, search that host across Sysmon, Security, and System logs
- A service or process that runs from `Temp` or `Public` is suspicious by path alone
- `ParentImage` and `ParentCommandLine` explain how a process started
- In Splunk, `OR` is evaluated before the implicit `AND`, so `(7045 OR 7036) ComputerName=...` filters both codes by host, which is what these queries want

## Practice Scenario

Alert: a suspicious network connection on port **5678** from host **WIN-105**. Logs are in `index=task4`.

Suggested approach:
1. Filter Event ID 3 on the host and port, then table the key fields:

        index=task4 EventCode=3 ComputerName=WIN-105 DestinationPort=5678
        | table _time Image SourceIp DestinationIp DestinationPort

2. Check the `Image` path and name (staging folder? random name?)
3. Check the destination IP on TI platforms
4. Pivot to Event ID 1 for the same process to find its parent and command line
5. Check Security and System logs on the host for new accounts or services

- Field names may differ in your data; check the fields sidebar first

---

# Linux Logs in a SIEM (Splunk)

For Linux systems in a SIEM, two log sources come first: `auth.log` (authentication and privilege use) and `syslog` (general system events). Together they let you spot a breach, see the privilege jump, and find persistence.

## The Two Sources

| Log | Shows | Useful for |
|---|---|---|
| `auth.log` | Logins, sudo usage, and more | Failed logins, unauthorised access, privilege escalation |
| `syslog` | Service restarts, cron jobs, background processes | Timelines, system behaviour over time, persistence |

## Authentication Logs

### Unusual Logins

Alert: an unusual SSH login to the `ubuntu` user. Search successful and failed attempts:

    index=linux source="auth.log" *ubuntu* process=sshd
    | search "Accepted password" OR "Failed password"

- Result: **97 events**, with successful logins at the end
- Reading: failures, then a success = likely **successful brute force**, so escalate to L2
- Same pattern as the Linux SSH detection note (`Failed password` flood, then `Accepted password`)

### Privilege Escalation

Check whether the attacker reached root:

    index=linux source="auth.log" *su*
    | sort + _time

- `sort + _time` puts events in chronological order
- Finding (from the lesson's screenshot): the attacker went from `ubuntu` to the **root** account
- `auth.log` alone can't show **how** the root access was gained; other logs are needed
- The wildcard `*su*` also matches words like "session" and "sudo", so expect extra noise

## System Logs

Capture service activity, restarts, and cron. Useful for persistence or privilege escalation attempts.

### Persistence

Following the same attacker (`ubuntu` to `root`), search cron activity for scripting tools:

    index=linux sourcetype=syslog ("CRON" OR "cron")
    | search ("python" OR "perl" OR "ruby" OR ".sh" OR "bash" OR "nc")

Three events were found:

| Finding | Meaning |
|---|---|
| `pnr5433sw.sh` in `/tmp` runs via cron **every 5 minutes** | Persistence, from a world-writable folder |
| Perl reverse shell to `10.10.101.12:9999` | Attacker callback (see the reverse shell note) |

- The source says "three events" but lists two findings; the third isn't described
- A random-looking script name in `/tmp` matches the filepath heuristics note

## Related Tools

- `auditd` and `osquery` are common in real environments but not covered here
- Earlier notes cover auditd

## Attack Chain Recap

| Step | Source | Evidence |
|---|---|---|
| 1. Initial access | `auth.log` | Brute force on `ubuntu` over SSH |
| 2. Privilege escalation | `auth.log` | Switch to `root` |
| 3. Persistence | `syslog` | Cron job running `/tmp/pnr5433sw.sh`, Perl reverse shell |

## Practice Scenario

Alert: possible persistence through creation of a new **remote-ssh** user on an Ubuntu server. Logs are in `index=task5`.

Suggested approach:
1. Find user creation in `auth.log`:

        index=task5 ("useradd" OR "usermod" OR "new user" OR "adduser")
        | sort + _time

2. Note who created it, when, and whether it was added to the `sudo` group (see the auth.log user management note)
3. Check the creator's earlier logins:

        index=task5 ("Accepted" OR "Failed") process=sshd
        | table _time _raw

4. Search cron and service activity for follow-up persistence:

        index=task5 sourcetype=syslog ("CRON" OR "cron")

5. Build a timeline: login, privilege change, user creation, persistence

- Field and source names may differ; check the fields sidebar first

---

# Web Logs in a SIEM (Splunk)

Web server logs (Apache, Nginx, others) are an important data source. **Access logs** show requests to website resources, and often contain signs of scanning, DDoS attempts, web attacks, and web shells. **Error logs** help explain failures and other issues.

## Brute Force on a WordPress Login

Alert: possible brute force against the login page.

Approach:
- Find the login URL (e.g. `/wp-login.php`)
- Filter for `POST` requests
- Set a threshold, e.g. `count > 25` in 5 minutes
- Group by `clientip` to find the source
- Check `user-agent` for context

Query:

    index=* method=POST uri_path="/wp-login.php"
    | bin _time span=5m
    | stats values(referer_domain) as referer_domain values(status) as status values(useragent) as UserAgent values(uri_path) as uri_path count by clientip _time
    | where count > 25
    | table referer_domain clientip UserAgent uri_path count status

- Finding: `167.172.41.141` made **160 requests** to `wp-login.php`
- The User-Agent shows **Hydra**, a popular brute-force tool

| Query part | Purpose |
|---|---|
| `bin _time span=5m` | Groups events into 5-minute buckets |
| `stats ... count by clientip _time` | Counts requests per IP per bucket |
| `where count > 25` | Keeps only IPs over the threshold |

## Possible Web Shell

Alert: possible web shell activity.

Approach:
- Search requests to script or executable types: `.php`, `.asp`, `.jsp`, `.exe`
- Look for `POST` and `GET` with `status=200`
- Web shells make a few suspicious requests in a short time, so use a threshold like `count > 2`
- Group by domain; review `clientip` and `user-agent` for fingerprints

Query (as given in the source, see the corrections below):

    index=*
    | search status=200 AND uri_path IN(*.php, *.phtm, *.asp, *.aspx, *.jsp, *.exe) AND (method=POST AND method=GET)
    | stats values(status) as status values(useragent) as UserAgent values(method) as method
      values(uri) as uri values(clientip) as clientip count by referer_domain
    | where count > 2
    | table referer_domain count method status clientip UserAgent uri

- Finding: many different URIs, but **`505.php`** stood out as a possible web shell and needs a closer look
- Matches the web shell notes: repeated `GET`/`POST` to one file

## DDoS

Alert: possible DDoS.

Approach:
- Look for status **503** (server overloaded)
- Look for huge request counts in a short time, e.g. more than 100,000 in 10 minutes, per IP
- Review the targeted domain, User-Agent, and URI path for patterns

Query:

    index=* status=503
    | bin _time span=10m
    | stats values(referer_domain) as referer_domain values(status) as status values(useragent) as UserAgent values(uri_path) as uri_path count by clientip _time
    | where count > 100000
    | table _time referer_domain clientip UserAgent uri_path count status

- Finding: the resource was unavailable for the last 10 minutes and received **more than 1.5 million requests**, confirming a possible DDoS
- Same indicators as the earlier DoS log note (high rate, 5xx spike)

## Three Alerts Compared

| Alert | Key filter | Group by | Threshold | Tell |
|---|---|---|---|---|
| Brute force | `POST` to `/wp-login.php` | `clientip`, 5 min | `count > 25` | Many attempts, tool User-Agent (Hydra) |
| Web shell | Script/exe extensions, `status=200` | `referer_domain` | `count > 2` | Odd file name like `505.php` |
| DDoS | `status=503` | `clientip`, 10 min | `count > 100000` | Huge volume, overloaded server |

## Detection Tips

- Thresholds are starting points: tune them to your site's normal traffic
- Replace `index=*` with the real web index; searching every index is slow on a production SIEM
- Pivot on `clientip` across all three alerts: the same IP may appear in several
- After a web shell hit, check the host for the file (see the web shell file system note)
