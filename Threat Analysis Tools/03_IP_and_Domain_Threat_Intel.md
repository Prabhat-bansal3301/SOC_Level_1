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
