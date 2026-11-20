# Splunk Incident Handling – Investigating a Website Defacement (imreallynotbatman.com)

**Scenario:** attackers broke into Wayne Enterprises' network, reached the web server and **defaced** `imreallynotbatman.com`. Splunk already holds the logs. The task is to find the root cause and every attacker action, mapping each finding to the **7 phases of the Cyber Kill Chain**. This falls under the **Detection and Analysis** phase of incident handling.

**Important:** phases don't have to be investigated in order. A finding in one phase often leads to another, and OSINT fills the gaps.

## Log Sources (all in `index=botsv1`)

| Sourcetype | Contains |
|---|---|
| `stream:http` | HTTP network traffic (requests, URIs, form data, user agents) |
| `stream:dns` / `stream:icmp` | DNS and ICMP traffic |
| `suricata` | IDS alerts (which rule fired and why). Very important |
| `fortigate_utm` | Fortinet firewall logs |
| `iis` | IIS web server logs |
| `XmlWinEventLog` | Sysmon logs (process creation, hashes). Very important |
| `wineventlog` / `winRegistry` | Windows event and registry logs |
| `nessus:scan` | Vulnerability scan results |

Tip: if you can't find a field in the left panel, click **More fields** or keep scrolling.

## Attack Summary

| Kill Chain Phase | Findings |
|---|---|
| **Reconnaissance** | `40.80.148.42` scanned the server with **Acunetix** |
| **Exploitation** | **Brute force** on the Joomla admin login from `23.22.63.114`, success from `40.80.148.42` |
| **Installation** | `3791.exe` uploaded and executed on the server |
| **Actions on Objective** | Website **defaced** with an image pulled from the attacker's domain |
| **Command & Control** | Dynamic DNS domain `prankglassinebracket.jumpingcrab.com` |
| **Weaponization** | Attacker infrastructure found through OSINT |
| **Delivery** | Secondary malware `MirandaTateScreensaver.scr.exe` |

## 1. Reconnaissance
**Goal:** find who was probing the web server.

| Step | Search | Why |
|---|---|---|
| Find the log sources | `index=botsv1 imreallynotbatman.com` | Shows which sourcetypes mention the domain (suricata, stream:http, fortigate_utm, iis) |
| Look at HTTP traffic | `index=botsv1 imreallynotbatman.com sourcetype=stream:http` | Check the `src_ip` field. Two IPs appear, and `40.80.148.42` has far more events |
| Validate with the IDS | `index=botsv1 imreallynotbatman.com src=40.80.148.42 sourcetype=suricata` | See which Suricata signatures this IP triggered |
| Look for CVE alerts | `index=botsv1 imreallynotbatman.com sourcetype=suricata CVE` | Finds alerts that name the vulnerability being attempted |
| Find the scanner | `... sourcetype=suricata eventtype=suricata_eve_ids_attack signature=*scan*` | Wildcard search on signature names. Shows the Acunetix scan signature |

**Findings:**
- Scanning IP: `40.80.148.42`, tool: **Acunetix**
- Web server IP (from `dest_ip`): `192.168.250.70`
- **CMS:** the `http.url` field is full of **Joomla** paths
- Useful fields to inspect: `http_user_agent`, `uri`, `http_method`

## 2. Exploitation
**Goal:** find out whether the attacker got in.

| Step | Search | Why |
|---|---|---|
| Count requests per IP | `index=botsv1 imreallynotbatman.com sourcetype=stream* \| stats count(src_ip) as Requests by src_ip \| sort - Requests` | Ranks who talks most to the server |
| Inbound traffic to the server | `index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70"` | Three source IPs (one local, two remote) |
| Only POST requests | `... http_method=POST` | Most traffic is POST, which suggests logins |
| Target the login page | `... uri="/joomla/administrator/index.php"` | Joomla's admin login page |
| Read the submitted forms | `... \| table _time uri src_ip dest_ip form_data` | `form_data` holds the username and password sent |
| Keep only login attempts | `... form_data=*username*passwd*` | Filters to real login POSTs |
| Extract the passwords | `... \| rex field=form_data "passwd=(?<creds>\w+)" \| table src_ip creds` | Pulls every password guess into its own column |
| Add user agents | `... \| table _time src_ip uri http_user_agent creds` | Shows the tool used for each attempt |

**Findings:**
- One username (`admin`) with **many different passwords**
- Attempts came **seconds apart**, which means an **automated tool**
- The user agent showed a **Python script** (`23.22.63.114`)
- One attempt used a normal **Mozilla browser** user agent from `40.80.148.42`. That was the **successful login**, typed by hand after the script found the password
- Brute force IP: `23.22.63.114`, access IP: `40.80.148.42`

**Why `rex` is used:** the `form_data` field isn't parsed into separate fields. `rex` applies a regex and extracts the value into a new field (`creds`).

## 3. Installation
**Goal:** find any payload uploaded and run on the server.

| Step | Search | Why |
|---|---|---|
| Find uploaded executables | `index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" *.exe` | Start with one extension |
| Inspect file names | field `part_filename{}` | Shows two uploaded files: an executable (`3791.exe`) and a PHP file |
| Check who sent it | `... "part_filename{}"="3791.exe"` then look at `c_ip` | Ties the file to the attacker's IP |
| Was it executed? | `index=botsv1 "3791.exe"` | Host-based logs (Sysmon, WinEventLog, fortigate_utm) mention it |
| Confirm execution | `index=botsv1 "3791.exe" sourcetype="XmlWinEventLog" EventCode=1` | Sysmon **Event ID 1** = process creation |

**Findings:**
- `3791.exe` was **uploaded and executed** on the server
- Sysmon gives the file's **hash** (check it on VirusTotal) and the **account** that ran it
- Network logs show the *upload*. Host logs (Sysmon) prove *execution*

## 4. Actions on Objective
**Goal:** find what caused the defacement.

| Step | Search | Why |
|---|---|---|
| Inbound to the server | `index=botsv1 dest=192.168.250.70 sourcetype=suricata` | No external IPs listed |
| Outbound from the server | `index=botsv1 src=192.168.250.70 sourcetype=suricata` | **Unusual:** web servers rarely start connections. Three external IPs show up |
| Pivot per destination | `... dest_ip=23.22.63.114` | Shows two PHP files and one **image file** in the URLs |
| Trace the image | `index=botsv1 url="<image path>" dest_ip="192.168.250.70" \| table _time src dest_ip http.hostname url` | Shows it was fetched from the attacker's domain |

**Findings:**
- The server **pulled the defacement image from the attacker's host**
- **Outbound traffic from a web server** is a strong anomaly to hunt for
- Firewall check: `index=botsv1 src=40.80.148.42 sourcetype=fortigate_utm`, then look at the `attack` field. The attacker also triggered a **SQL injection** firewall rule

## 5. Command & Control
**Goal:** find the domain behind the attacker's server.

```
index=botsv1 sourcetype=fortigate_utm "<defacement image name>"
```
- The firewall's `url` field shows the **FQDN**
- Verify in another source: `index=botsv1 sourcetype=stream:http dest_ip=23.22.63.114 "<image name>" src_ip=192.168.250.70`
- The attacker used **Dynamic DNS**: `prankglassinebracket.jumpingcrab.com` resolves to the attacker's IP, which makes it easy to move servers

## 6. Weaponization (OSINT)
The attacker's pre-staged infrastructure was found outside Splunk.

| Platform | Used for |
|---|---|
| **Robtex** | Domain to IP and IP to domain lookups. The IP `23.22.63.114` links to domains that **look like Wayne Enterprise's** |
| **VirusTotal → Relations tab** | Lists domains tied to the IP, including `po1s0n1vy.com` |
| **WHOIS (DomainTools)** | Registration details |
| **AlienVault OTX** | Pointed to the email `lillian.rose@po1s0n1vy.com` |

**Weaponization here means:** lookalike domains, a malware set, and a C2 server prepared before the attack.

## 7. Delivery (OSINT)
Looked for malware tied to the attacker's IP. Reports suggested the group has a **secondary attack vector** in case the first compromise fails.

| Platform | Result |
|---|---|
| **ThreatMiner** | Three files tied to `23.22.63.114`, one malicious |
| **VirusTotal** | File metadata and community notes |
| **Hybrid Analysis** | Behavior report (network activity, DNS, contacted hosts, strings, MITRE ATT&CK mapping, indicators) |

- Malware: `MirandaTateScreensaver.scr.exe`, MD5 `c99131e0169171935c5ac32615ed6261`
- Hybrid Analysis also showed the attacker's **domain and image URL** from the logs, which links the malware to this incident

## IOCs Collected

| Type | Value |
|---|---|
| Scanner / access IP | `40.80.148.42` |
| Brute force IP | `23.22.63.114` |
| Attacker domain | `prankglassinebracket.jumpingcrab.com` |
| Related domain | `po1s0n1vy.com` |
| Attacker email | `Lillian.rose@po1s0n1vy.com` |
| Uploaded file | `3791.exe` |
| Related malware | `MirandaTateScreensaver.scr.exe` (MD5 `c99131e0169171935c5ac32615ed6261`) |
| Scanning tool | Acunetix |

## Key Takeaways
- **Search broad, then narrow:** domain → sourcetype → IP → fields
- **Different logs answer different questions:** `stream:http` for requests and brute force, Suricata for alerts and outbound traffic, Sysmon for execution and hashes, the firewall for domains and SQL injection
- **Brute force pattern:** many POSTs with different passwords from one IP, then a login from another IP
- **Outbound connections from a web server** are a red flag
- **`table`, `stats`, `rex` and `sort`** are the core Splunk commands used here
- **Pivot with OSINT** (Robtex, VirusTotal, OTX, ThreatMiner, Hybrid Analysis) to expand from one IOC to the full infrastructure
- **Network logs show what was sent, host logs show what ran.** You need both to confirm an attack
