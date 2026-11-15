# DNS Enrichment and DNS-Based Attack Techniques

DNS converts names like `tryhackme.com` into IP addresses. Every click or hostname lookup uses it, so DNS records are a rich source of context for an indicator. Tools such as nslookup.io and dnschecker.org show the records.

## DNS Records for Enrichment

| Record | What it shows | What to look for |
|---|---|---|
| A / AAAA | Domain maps to IPv4 / IPv6 addresses | Is the resolved IP tied to known APT infrastructure or a known campaign? |
| TXT | Mail security settings (SPF/DKIM) and tools in use | Legitimate-looking SPF; empty TXT, suspicious SPF, or a faked DKIM signature suggests attacker infrastructure |
| WHOIS / RDAP | Registrar, registration and expiry dates, domain **age** | Very young domain is a red flag |

### A / AAAA Example

- `tryhackme.com` resolves to an Amazon IP: hosted in AWS, or behind a proxy that uses AWS (here, the Vercel CDN)
- Investigate the resolved IP, not just the domain

### TXT Example

- `tryhackme.com` shows Google Workspace and Zapier usage and a legitimate-looking SPF record
- Attack infrastructure often has empty TXT records
- Faked DKIM and odd SPF records are often abused in phishing campaigns

### WHOIS / RDAP

- [WHOIS](https://whois.domaintools.com/) is gradually being replaced by RDAP
- Domain age is the key field:

| Domain | Typical age |
|---|---|
| `tryhackme.com` | Registered nearly 10 years (reassuring) |
| Malicious domains | Often live only a few days |

- Modern attack infrastructure rarely stays online more than a few months: it is taken down or rotated to avoid detection

## Attack Techniques Using DNS

### CDN Abuse

- Attackers route malicious traffic through legitimate CDNs (Cloudflare, Akamai, Fastly) to hide the real origin server
- If an A record points to a CDN range, the IP tells you little: one IP fronts thousands of legitimate and malicious services at once

### Typosquatting

- Look-alike domains rely on visual similarity: `tryhakme[.]com`, `micros0ft[.]net`
- Treat any look-alike of a known brand as high risk
- Exception: companies register obvious typos of their own domain defensively, so a typosquat that resolves to the real brand isn't necessarily malicious

### IDN (Internationalized Domain Name) Attacks

- Domains can use non-ASCII characters, so attackers swap in Cyrillic or Greek letters that look identical to Latin ones
- Example: `tryhаckme[.]com` uses a Cyrillic "а" in place of the Latin "a": looks the same, resolves somewhere else entirely
- When in doubt, convert it to **Punycode** with a tool like [punycoder.com](https://www.punycoder.com/)
- A result starting with `xn--` means the domain contains non-ASCII characters and needs a closer look

## Quick Comparison

| Technique | Looks like | Tell |
|---|---|---|
| CDN abuse | A legitimate CDN IP | Shared IP, so use the domain and URL, not the IP |
| Typosquatting | Brand with a small typo | Spelling, young domain age |
| IDN attack | Exact brand name | `xn--` Punycode form |

## Detection Tips

- Combine signals: a young domain plus empty TXT plus a look-alike name is far stronger than any one alone
- Hunt DNS logs for young domains and for Punycode names (`xn--`):

        index=dns query="xn--*" | stats count by query, src_ip

- Ties to the DNS exfiltration note: long, high-entropy subdomains are a different DNS abuse, so check query length too
- Defang indicators (`tryhakme[.]com`) in tickets, as in the CTI note

---

# IP Enrichment in the SOC

Most SIEM and EDR alerts contain at least one IP address. It could be a compromised home router, a shared CDN edge, or a cloud service used by thousands of tenants. Without enrichment you risk **overreacting** (blocking legitimate infrastructure) or **underreacting** (ignoring a real C2 server).

## Basic Reputation Lookups

The simplest L1 enrichment is to query the IP in two services:

| Service | What it shows |
|---|---|
| [AbuseIPDB](https://www.abuseipdb.com/) | Whether the IP was involved in port scans or brute-force attacks |
| [VirusTotal](https://www.virustotal.com/) | Overall IP reputation and community comments (if any) |

- If the IP is **not** in a CDN range, even **1 detection** marks it as risky
- On a CDN IP, one detection means less, since the IP is shared (see the DNS note on CDN abuse)

## Autonomous Systems (AS)

- An AS is a collection of IP prefixes under one organisation's control
- Each AS has a unique number (ASN)
- [BGP.Tools](https://bgp.tools/) gives the most complete information about an AS and its purpose
- The ASN helps you judge the **likely role** of an IP:

| ASN type | What an alert may mean | Example |
|---|---|---|
| Residential | VPN usage or a compromised consumer device | AS124888 (Vodafone) |
| Server hosting | **Most risky**: often used by adversaries to distribute malware | AS215439 (PLAY2GO) |
| Cloud / CDN | Used by legitimate services and adversaries alike; needs deeper analysis | AS16509 (Amazon AWS) |

## Geolocation (GeoIP)

- Complements the ASN lookup; useful for anomalous logons
- Tools: [ipinfo.io](https://ipinfo.io/), [iplocation.net](https://iplocation.net/)
- Reliable to the **country** level; city-level accuracy is generally unreliable

| Use | Example |
|---|---|
| User logon analysis | A US-based employee logs on from the Netherlands: possible intrusion |
| Network analysis | A European company's traffic to Vietnam is suspicious |

- Ties to the Splunk anomaly note: `iplocation` and per-user country frequency do this at scale

## Putting It Together

| Step | Check | Question |
|---|---|---|
| 1 | AbuseIPDB and VirusTotal | Any reports or detections? |
| 2 | ASN (BGP.Tools) | Residential, hosting, or cloud/CDN? |
| 3 | GeoIP | Does the country make sense for this user or network? |

---

# Exposed Services and TLS Certificate Enrichment

Knowing which services an IP exposes helps from two angles:

| Angle | What exposure tells you |
|---|---|
| Victim's public IP | How the attacker got in: exposed SSH is a likely starting point |
| Attacker's IP | Outdated services or exposed RDP suggest the host was **compromised** and is being used as a jump point |

## Shodan

[Shodan](https://www.shodan.io/) indexes internet-connected devices and shows open ports, running services, and system configurations.

- Paste the **defanged** IP into the search box: `69[.]197[.]185[.]26` (use the normal form `69.197.185.26` when searching)
- What to extract:

| Field | Why it matters |
|---|---|
| Open ports | First fingerprint of exposure. In the example, Nginx and Rsync are both services attackers can target |
| Service banners | Hint at service **versions**; an old version usually means a vulnerable one |

- The lesson's Shodan screenshot wasn't included

## Censys

[Censys](https://platform.censys.io/home) is a good Shodan alternative for blue teams:

- Shows exposed services even on **non-standard ports**
- Offers advanced search; some features need an account
- Example: it found another exposed port, `56003/SSH`, that the first search didn't list
- SSH on a high, odd port on a server also running Nginx and Rsync is worth noting: it may be an admin choice or attacker-installed access (my reading, not in the source)
- Using both tools gives better coverage than either alone

## TLS Certificates

An IP that exposes HTTPS gives you a new indicator: its certificate. Tools:

| Tool | Note |
|---|---|
| [crt.sh](https://crt.sh/) | Certificate transparency search; often unavailable because of high request volume |
| Censys | Alternative for certificate details |
| [SSL Shopper](https://www.sslshopper.com/ssl-checker.html) | Quick certificate checker |

Key fields:

| Field | What to look for |
|---|---|
| Issuer | A **self-signed** certificate is a strong sign the site deserves investigation |
| Validity | **Newly created** or **very long-lived** certificates can indicate malware infrastructure |
| Subject | For self-signed certs, may name the program behind the HTTPS (e.g. pfSense) |

## Putting It Together

| Step | Check | Question |
|---|---|---|
| 1 | Shodan | Which ports and versions are exposed? |
| 2 | Censys | Any services on non-standard ports? |
| 3 | TLS certificate | Self-signed, brand new, or long-lived? |

- Combine with the reputation, ASN, and GeoIP checks from the IP enrichment note

---

# VPN Detection and the IP/Domain Enrichment Workflow

A login that looks normal (same country, same city, same user-agent) can still be an attacker behind a VPN. Services like ProtonVPN and NordVPN make faking any location trivial, so the SOC has to answer one question: **is this a real user, or someone behind a VPN?**

## The Scenario

- Alert: a Microsoft 365 login outside working hours
- Location, city, and user-agent all look normal
- An inexperienced analyst closes it as a false positive, which is exactly what attackers count on
- GeoIP can't be trusted when the IP is a VPN exit

## VPN, Proxy, and Tor Labelling Tools

| Tool | Purpose |
|---|---|
| [IP2Proxy](https://www.ip2proxy.com/) | Labels VPN, proxy, and Tor exit nodes |
| [Spur](https://spur.us/) | Same, with VPN and proxy context |

- Both have a free tier for personal use
- For a SOC, push the company to buy a subscription and **integrate it with the SIEM**
- Example: `185[.]98[.]171[.]238` is a known VPN node, so geolocation of anyone behind it can't be trusted
- The lesson's screenshot wasn't included

## SOC Analyst Workflow

The minimum workflow for IP and domain intel. Some steps can be skipped or reordered depending on the alert.

### 1. Investigate the Domain

| Check | Question |
|---|---|
| Appearance | Does it look legitimate, or like typosquatting? (see the DNS note) |
| Reputation | Is it a known malicious domain? |
| Age | When was it registered? New is suspicious |
| Resolution | Resolve it to an IP, then investigate the IP |

### 2. Investigate the IP

| Check | Question |
|---|---|
| CDN range | Is it a CDN? If yes, no need to investigate further |
| Reputation | VirusTotal, AbuseIPDB, etc. |
| Location | Where is it? Is it a VPN node? Does it match the alert? (e.g. a US-based user shouldn't log in from Asia) |
| AS type | Does the ASN match the alert? (e.g. employees shouldn't log in from cloud hosting) |

## Related Notes in This Series

| Step | Covered in |
|---|---|
| Domain age, records, typosquatting, IDN | DNS enrichment note |
| Reputation, ASN, GeoIP | IP enrichment note |
| Open ports, banners, certificates | Exposed services note |
| VPN labelling | This note |
