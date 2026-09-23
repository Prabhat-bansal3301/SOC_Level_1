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
