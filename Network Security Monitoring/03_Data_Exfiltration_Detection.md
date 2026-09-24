# Data Exfiltration

**Core idea:** Unauthorized transfer of sensitive data out of an organization to an adversary-controlled destination. Deliberate (insider) or via malware/compromised credentials. Detection depends on correlating host, network, and cloud telemetry — not single alerts.

## Why Adversaries Do It

- **Financial gain** — sell stolen data (credit cards, PII) on dark web, use for fraud
- **Espionage** — nation-states target IP, trade secrets, classified data
- **Ransomware/extortion** — steal data, threaten leak unless paid
- **Disruption/sabotage** — reputational/operational damage via leaks
- **Persistence/recon** — stolen data maps the environment for future attacks

## Real-World Threat Actors

| Actor | Technique |
|---|---|
| APT29 (Cozy Bear) | HTTPS over legitimate domains |
| FIN7 | Stolen data embedded in HTTP POST to C2 |
| Lunar Spider (Zloader) | Encrypted C2 channels, staged exfil over 2 months |
| DarkSide Ransomware | Dual extortion — steal before encrypting |
| APT10 (Cloud Hopper) | Cloud-to-cloud transfer via MSP cloud APIs |

- Same underlying phases every time, different disguise
- HTTPS/legitimate-looking traffic is the common thread — blend in, don't stand out

## Common Phases

1. **Discovery/Collection** — locate sensitive files
2. **Staging/Compression** — aggregate, compress, encrypt, or encode (ZIP, RAR, 7z, tar, base64, steganography)
3. **Exfiltration Transport** — network, removable media, cloud, covert channels
4. **C2 Coordination** — orchestrate transfer, confirm receipt

## Techniques and Where to Look

| Category | Examples | Look For |
|---|---|---|
| Network-based | HTTPS uploads (S3/Azure/webmail), FTP/SFTP/SCP, DNS tunneling, ICMP covert channels | Proxy logs (large POSTs), firewall/NGFW flows (high bytes to one IP/ASN), netflow spikes, DNS (long hostnames, TXT queries) |
| Host-based | PowerShell `Invoke-WebRequest`, `rclone`, `awscli`, `curl`/`wget`, archive creation, USB use, ADS/hidden streams | Sysmon/EDR (Process Create, Network Connect, File Create), Windows Security 4663/4656, Linux auditd/shell history, removable-media events |
| Cloud | S3 PutObject/multipart upload, Azure Blob, GCS, Drive/SharePoint external sharing | CloudTrail, Azure Activity, GCP Audit, unusual service-account/IP activity |
| Covert/encoding | DNS tunneling, base64/chunked encoding, steganography, low-and-slow (splitting into many small requests) | DNS logs, proxy logs with many small POSTs, correlating intermittent uploads with suspicious process activity |
| Insider/collaboration | Slack/Teams/Dropbox/Drive/Box uploads or external sharing, compromised accounts | Audit logs (share/download events), mail logs |

## General Indicators of Attack (IoAs)

- Large outbound volume to external IPs/domains
- Unknown/unusual destination domains
- Suspicious process command-lines
- Many file reads followed by an outbound connection
- Multipart/streamed uploads

Correlate across: Proxy/Firewall/Netflow + DNS + Sysmon/EDR (EventID 1/3/11) + mail logs

## L1 Triage Focus
When investigating, prioritize answering:
- **Who** — source host/user
- **Where** — destination
- **How much** — transferred volume
- **What** — process identity/command-line
- Supporting evidence across proxy, DNS, flow, host, cloud logs

---

# DNS Exfiltration & Tunneling

**Core idea:** DNS is almost always allowed outbound and rarely inspected closely — attackers abuse it to smuggle stolen data encoded inside queries/subdomains, bypassing firewalls and proxies that would catch the same data over HTTP.

## DNS Fundamentals (Relevant to Abuse)

- Translates domain names → IPs, supports multiple record types (A, AAAA, TXT, MX, CNAME)
- Nearly every host does DNS lookups constantly — total blocking isn't viable
- Mostly UDP/53 for queries/responses; TCP used for zone transfers or large responses

## Why Attackers Use DNS

- Always-on, routinely allowed outbound
- Looks like normal traffic unless inspected closely
- Payload can be encoded into subdomain labels or TXT responses

## Indicators of Attack (IoAs)

- Many queries to a single external domain, high count vs. baseline
- Long subdomain labels / full query names (>60–100 chars)
- High entropy or Base32/Base64-like patterns (mixed case, digits, `-`, `=`)
- Rare record types (TXT, NULL) or many large TXT responses
- Frequent NXDOMAIN (exfil-by-query without expecting an answer)
- TCP or large UDP fragments for DNS (abnormal for typical lookups)
- Queries at regular intervals — beaconing behavior

## Detecting via Wireshark

Target file: `dns_exfil.pcap`

| Filter | Purpose |
|---|---|
| `dns` | All DNS traffic |

<img width="1233" height="581" alt="5e8dd9a4a45e18443162feab-1759117822714" src="https://github.com/user-attachments/assets/ce89fabf-2f98-4390-8968-22d36fd59ec9" />

| `dns.flags.response == 0` | Queries with no response |

<img width="1265" height="432" alt="no response" src="https://github.com/user-attachments/assets/dd7738cf-bb5e-4570-9ec0-2b47ff604cc4" />


| `dns && frame.len > 70` | Long queries — suspicious subdomain length |

<img width="1151" height="569" alt="long query" src="https://github.com/user-attachments/assets/9eb28b79-8ed4-485c-aadc-308326b155ca" />


| `dns && dns.qry.name contains <domain>` | Isolate the suspect domain |

<img width="1196" height="576" alt="isolate domain" src="https://github.com/user-attachments/assets/786f3316-033c-463a-8c0b-1f84294e6e29" />


Findings from this pcap:
- Multiple internal hosts compromised
- All sending data in chunks via DNS tunneling
- Single external domain receiving all the queries

## Investigating via Splunk

Base query:

    index=data_exfil sourcetype=DNS_logs

Count queries per source IP:

    index="data_exfil" sourcetype="DNS_logs" | stats count by src_ip

  <img width="1907" height="479" alt="Count query" src="https://github.com/user-attachments/assets/14f592c0-0785-4d45-8658-89101b260e3d" />


- Look for one host generating far more DNS requests than normal

Count/sort by query string:

    index="data_exfil" sourcetype="dns_logs" | stats count by query | sort -count

<img width="1920" height="753" alt="sort,count" src="https://github.com/user-attachments/assets/7e742604-31f2-43a2-90a8-4a6c311f7323" />


- Surfaces odd-looking, oversized queries at the top

Filter by query length:

    index="data_exfil" sourcetype="DNS_logs" | where len(query) > 30

<img width="1259" height="891" alt="filter by length" src="https://github.com/user-attachments/assets/29b4f638-10a7-4158-8c41-b2e7284ce0b9" />


- Isolates subdomain-encoded exfil attempts directly

## Confirmed Indicators (This Case)

- Large number of DNS requests with no response
- Abnormally long DNS query length

---

# FTP Exfiltration

**Core idea:** FTP is old, plaintext by default, and still commonly allowed outbound — attackers abuse legitimate or misconfigured FTP servers to move stolen data, often using compromised or throwaway credentials.

## How Adversaries Use FTP

- Legitimate FTP servers (public or misconfigured internal) used to stage/transfer data
- Compromised credentials (service accounts, user creds)
- Non-standard ports or tunneling to blend with other traffic

## Indicators of Attack

- `USER`/`PASS` commands — cleartext credentials, since FTP doesn't encrypt by default
- `STOR` (upload) / `RETR` (download) — repeated or large transfers
- Large data connections to unusual external IPs, especially off-hours
- Data channel on ephemeral ports (PASV mode) paired with large payloads

## Investigating via Wireshark

Target file: `ftp-lab.pcap`

```
 ftp || ftp-data  | Isolate FTP control + data traffic 
```

<img width="1005" height="574" alt="ftp" src="https://github.com/user-attachments/assets/57fc577b-f383-4959-a3f6-fb988a23d530" />

```
ftp.request.command == "USER" || ftp.request.command == "PASS" | Pull login attempts — check for suspicious usernames/weak passwords 
```

<img width="944" height="524" alt="credentials" src="https://github.com/user-attachments/assets/6abc8ec8-94b9-4d97-90f1-d36a281584bd" />

```
ftp contains "STOR" | Find upload commands — right-click → **Follow → TCP Stream** to see transferred content 
```
<img width="1006" height="534" alt="looking for anomalies" src="https://github.com/user-attachments/assets/c786a523-1f8f-4593-afe2-64ae67416855" />

```
ftp contains "csv" | Narrow to filenames with a given extension — spot sensitive file types being moved 
```

<img width="1838" height="684" alt="ftp contains csv" src="https://github.com/user-attachments/assets/52fa601f-17ca-4fc0-bc3c-f2fb81c4dbad" />

```
ftp && frame.len > 90 | Find large-payload packets — follow TCP stream to inspect content
```

<img width="1660" height="673" alt="large payload size" src="https://github.com/user-attachments/assets/d310a004-0c97-44d5-8819-de2cff6f4086" />


## Findings (This Case)

- A **Guest account** connected from a suspicious source
- Transferred sensitive CSV files
- Destination: a suspicious external IP

## Why Cleartext Credentials Matter Here

- `USER`/`PASS` commands appear in plaintext in the pcap — no decryption needed
- Anyone who captures this traffic (or a SOC analyst reviewing it after the fact) can read the exact login used
- This is also why an attacker using a **Guest** account is a red flag on its own — weak/default accounts are the easiest FTP foothold to abuse
  
---

# HTTP Exfiltration

**Core idea:** HTTP blends exfiltration into normal web traffic — traverses firewalls/proxies easily and is easy to obfuscate (encoding, encryption, tunneling). Detection means separating the exfil noise from legitimate web usage, not spotting an obviously malicious protocol.

## How Adversaries Use HTTP

- **POST uploads** — bulk data sent to attacker-controlled hosts/cloud storage in request bodies
- **GET with encoded data** — small chunks in query strings/paths, good for low-and-slow exfil
- **Common services/CDN abuse** — disguised as uploads to popular services or subdomains under reputable domains
- **Custom headers** — data hidden in headers (e.g. `X-Data: <base64>`) to bypass string-based DLP
- **Chunked/multipart transfer** — large payloads split into multiple requests to dodge size thresholds
- **HTTPS/TLS tunneling** — encryption hides the payload; needs TLS inspection, SNI analysis, or metadata-based detection
- **Staging via cloud services** — upload to Dropbox/GitHub/Gist, fetch externally later

Attackers adapt: low-and-slow, encoding/encryption, legitimate-service abuse — all aimed at evading simple detection rules.

## Indicators of Attack

- Unusually large POST requests to external/unexpected hosts
- Requests to low-reputation or rarely-seen domains
- Frequent small requests (beaconing) followed by a large upload
- Chunked/multipart transfers composing a larger file across multiple requests

## Investigating via Splunk

Base query (set time range to **All Time**):

    index="data_exfil" sourcetype="http_logs"

Narrow to POST requests:

    index="data_exfil" sourcetype="http_logs" method=POST

<img width="1903" height="640" alt="post request" src="https://github.com/user-attachments/assets/e54fb68f-772d-44bf-bae7-71cfc8697d00" />


Check average/max/min bytes sent per domain:

    index="data_exfil" sourcetype="http_logs" method=POST
    | stats count avg(bytes_sent) max(bytes_sent) min(bytes_sent) by domain
    | sort - count

<img width="1899" height="603" alt="average" src="https://github.com/user-attachments/assets/99113cc6-7b78-45d4-8484-4976c0a0ef56" />

Isolate large POSTs:

    index="data_exfil" sourcetype="http_logs" method=POST bytes_sent > 600
    | table _time src_ip uri domain dst_ip bytes_sent
    | sort - bytes_sent

<img width="1905" height="311" alt="isolate payload" src="https://github.com/user-attachments/assets/5ff74983-4166-4fbf-8b7b-147b10d2010e" />

- Surfaces one suspicious entry: a large data chunk uploaded to an external destination

## Investigating via Wireshark

Target file: `http_lab.pcap`

| Filter | Purpose |
|---|---|
| `http` | All HTTP traffic |
| `http.request.method == "POST"` | Isolate POST requests |
| `http.request.method == "POST" and frame.len > 500` | Filter by size — still noisy |
| `http.request.method == "POST" and frame.len > 750` | Tighten threshold to cut remaining noise |

- Iterative size-threshold tightening is the actual technique here — start broad, raise the bar until only genuine outliers remain
- This mirrors the Splunk `bytes_sent > 600` filter — same logic, two tools

---

# ICMP Exfiltration

**Core idea:** ICMP is a diagnostics/control protocol (ping, TTL exceeded) — commonly allowed through firewalls and inspected less strictly than TCP/UDP. Attackers exploit this trust gap by encoding stolen data into ICMP payloads instead of TCP/UDP traffic that gets more scrutiny.

## How Adversaries Use ICMP

- **Echo tunneling (type 8 request / type 0 reply)** — encoded (base64/hex) file chunks placed in ICMP payloads, collected/decoded by a remote listener
- **Custom types/codes** — uncommon ICMP types or non-zero codes to dodge signature-based detection
- **Fragmentation** — large payloads split across multiple packets
- **Encryption/obfuscation** — base64 or encryption to disguise payload as random data

## Indicators of Attack

- Persistent ICMP sessions to an external host with no legitimate monitoring reason
- Unusually large ICMP payloads (bigger than typical ping size)
- High-entropy payload data or base64/hex-like patterns
- ICMP bursts with no other legitimate app traffic from the same host
- Unusual ICMP type/code (e.g. timestamp types 13/14, custom codes)
- Regular timing (periodicity) — evenly spaced packets, similar payload sizes
- Multiple fragments from the same src/dst pair needing reassembly

## Investigating via Wireshark

Target file: `icmp_lab.pcap`

| Filter | Purpose |
|---|---|
| `icmp` | All ICMP traffic |
| `icmp.type == 8` | Isolate Echo Requests |
| `icmp.type == 8 and frame.len > 100` | Flag oversized pings |

- Normal ping ≈ 74 bytes total
- Anything over 100 bytes is suspicious — a real ping doesn't need that much payload, so the excess is very likely smuggled data
