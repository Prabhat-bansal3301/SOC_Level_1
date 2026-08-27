## Wireshark — Nmap Scan Detection

### TCP Flag Filters Reference

```wireshark
tcp.flags == 2              # SYN only
tcp.flags.syn == 1          # SYN set (other bits don't matter)

tcp.flags == 16             # ACK only
tcp.flags.ack == 1          # ACK set

tcp.flags == 18             # SYN + ACK
(tcp.flags.syn==1) and (tcp.flags.ack==1)

tcp.flags == 4              # RST only
tcp.flags.reset == 1        # RST set

tcp.flags == 20             # RST + ACK
(tcp.flags.reset==1) and (tcp.flags.ack==1)

tcp.flags == 1              # FIN only
tcp.flags.fin == 1          # FIN set
```

---

### TCP Connect Scan (`nmap -sT`)

**How it works:** Completes full 3-way handshake.
**Who uses it:** Non-privileged users (only option without root).
**Window size:** > 1024 bytes (expects data).

<img width="1566" height="318" alt="open tcp port" src="https://github.com/user-attachments/assets/b42ad2bb-ab87-4d5e-a5e6-4c1baa408c4a" />

<img width="1567" height="256" alt="closed tcp port" src="https://github.com/user-attachments/assets/1d7c76c9-6a1f-4fdf-90bf-7b71bb5f5c51" />

```
Open port:    SYN → | ← SYN,ACK | ACK →
Closed port:  SYN → | ← RST,ACK
```

**Detection filter:**

<img width="1561" height="415" alt="TCP Connect scan patterns" src="https://github.com/user-attachments/assets/2503a899-da17-4daa-ae62-2681ec35bdb7" />

```wireshark
tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024
```

---

### SYN Scan (`nmap -sS`)

**How it works:** Half-open scan — never completes handshake.
**Who uses it:** Privileged/root users only.
**Window size:** ≤ 1024 bytes (doesn't expect data).

<img width="1568" height="283" alt="Open TCP port (SYN)" src="https://github.com/user-attachments/assets/2f240b12-12ff-438d-8e8a-dc69d8c4d50f" />


<img width="1568" height="259" alt="Closed TCP port (SYN)" src="https://github.com/user-attachments/assets/70b68b7f-5f56-4671-b21d-af12e5ad3700" />

```
Open port:    SYN → | ← SYN,ACK | RST →
Closed port:  SYN → | ← RST,ACK
```

**Detection filter:**

<img width="1568" height="440" alt="TCP SYN scan patterns" src="https://github.com/user-attachments/assets/51220acd-6d4f-4c1e-b18a-9646f860055e" />

```wireshark
tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024
```

---

### UDP Scan (`nmap -sU`)

**How it works:** No handshake — sends UDP packet.
**Open port:** No response (silence = open).
**Closed port:** ICMP Type 3, Code 3 (Destination/Port Unreachable).

<img width="1568" height="275" alt="Closed (port no 69) and open (port no 68) UDP ports" src="https://github.com/user-attachments/assets/1094a1e5-abf6-4c1f-80d8-7525badc0d0a" />


```
Open port:    UDP → (no response)
Closed port:  UDP → | ← ICMP Type 3 Code 3
```

**Detection filter:**

<img width="1568" height="375" alt="UDP scan patterns" src="https://github.com/user-attachments/assets/976155a9-61fa-4510-8392-36d6fe99d4c9" />

```wireshark
icmp.type==3 and icmp.code==3
```

> ICMP error contains encapsulated original UDP request.
> Expand ICMP section in packet details → see original request details.

<img width="1565" height="1089" alt="encapsulated data and the original request" src="https://github.com/user-attachments/assets/011912be-d7ea-4ebc-b5da-022bb7d6db1e" />


---

### Scan Type Comparison

| | TCP Connect | SYN Scan | UDP Scan |
|-|-------------|----------|---------|
| **Command** | `nmap -sT` | `nmap -sS` | `nmap -sU` |
| **Handshake** | Full 3-way | Half (no ACK) | None |
| **Privileges** | Non-root OK | Root required | Root required |
| **Window size** | > 1024 | ≤ 1024 | N/A |
| **Open indicator** | SYN,ACK received | SYN,ACK received | No response |
| **Closed indicator** | RST,ACK | RST,ACK | ICMP Type 3 Code 3 |
| **Stealth** | Low | Medium | Medium |

---

### Quick Detection Summary

```wireshark
# TCP Connect Scan
tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024

# SYN Scan
tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024

# UDP Scan
icmp.type==3 and icmp.code==3

# General port scan (many SYNs, no established connections)
tcp.flags.syn==1 and tcp.flags.ack==0
```

---

## Wireshark — ARP Poisoning / MITM Detection

### ARP Protocol Basics
- Works on **local network only**
- Maps IP addresses to MAC addresses
- **Not secure** — no authentication
- Not routable
- Common packets: request, response, announcement, gratuitous

---

### ARP Wireshark Filters

```wireshark
arp                                    # All ARP traffic
arp.opcode == 1                        # ARP requests only
arp.opcode == 2                        # ARP responses only
arp.dst.hw_mac == 00:00:00:00:00:00   # ARP scanning (broadcast requests)
arp.duplicate-address-detected         # Duplicate IP — possible poisoning
arp.duplicate-address-frame            # Same as above

# ARP flooding from specific MAC
((arp) && (arp.opcode == 1)) && (arp.src.hw_mac == target-mac-address)
```

#### ARP Request

<img width="1568" height="612" alt="ARP Request" src="https://github.com/user-attachments/assets/f6eb27d8-5c87-4047-ae5e-6534451a647c" />

#### ARP Reply

<img width="1568" height="547" alt="ARP Reply" src="https://github.com/user-attachments/assets/a9a4458b-5815-49bf-a26d-f8f7f65a90d5" />

---

### ARP Poisoning Attack Pattern

**Normal ARP:**
```
Host A → Broadcast: "Who has 192.168.1.1?"
Router → "192.168.1.1 is at 50:78:b3:f3:cd:f4"
```

**ARP Poisoning:**

<img width="1568" height="601" alt="IP spoof" src="https://github.com/user-attachments/assets/86956343-f819-4b34-afe7-b34d5f10a007" />

```
Attacker → "192.168.1.1 is at 00:0c:29:e2:18:b4"  ← FAKE
Attacker → "192.168.1.12 is at 00:0c:29:e2:18:b4" ← FAKE
→ Victim and gateway now send traffic to attacker (MITM)
```

---

### Investigation Workflow

```
1. Filter: arp.duplicate-address-detected
   → Wireshark expert info warns of conflict

2. Filter: arp.opcode == 1
   → Look for flood of ARP requests from single MAC

3. Note suspicious MAC → check what IPs it claims to have

4. Add MAC address column to packet list
   → Check if suspicious MAC appears as dst for other protocols (HTTP, etc.)

5. If suspicious MAC = destination of victim's HTTP traffic → MITM confirmed
```

---

### Case Study — Investigation Notes

| Finding | Detection | Evidence |
|---------|-----------|---------|
| IP→MAC match | Single IP announced from MAC | `00:0c:29:e2:18:b4` = `192.168.1.25` |
| ARP spoofing | 2 MACs claim same IP (gateway) | MAC1: `50:78:b3:f3:cd:f4`, MAC2: `00:0c:29:e2:18:b4` both claim `192.168.1.1` |
| ARP flooding | Multiple requests across IP range | `00:0c:29:e2:18:b4` → `192.168.1.xxx` range |
| MITM confirmed | All victim HTTP traffic → attacker MAC | `00:0c:29:98:c7:a8` (victim) → all HTTP dst = `00:0c:29:e2:18:b4` |

**Roles identified:**
```
Attacker: MAC 00:0c:29:e2:18:b4 = IP 192.168.1.25
Gateway:  MAC 50:78:b3:f3:cd:f4 = IP 192.168.1.1
Victim:   MAC 00:0c:29:98:c7:a8 = IP 192.168.1.12
```

---

### Key Indicators of ARP Attack

| Indicator | What it means |
|-----------|--------------|
| Duplicate IP in ARP responses | ARP poisoning in progress |
| Single MAC claiming multiple IPs | Attacker spoofing gateway + own IP |
| Flood of ARP requests | ARP scanning or poisoning setup |
| Victim traffic → attacker MAC | MITM established — traffic being intercepted |

---

### Analyst Tips
> Always add MAC address as a column when investigating ARP anomalies.
> Cross-reference ARP findings with HTTP/other protocol traffic.
> Note findings progressively — ARP anomaly + MAC as HTTP destination = MITM confirmed.
> Know your network architecture — legitimate gateway MAC = baseline for comparison.

---

## Wireshark – Host & User Identification (DHCP, NetBIOS, Kerberos)

Beyond just matching an IP to a MAC address, one of the most useful things a security analyst can do during an investigation is figure out *who* and *what* was actually behind a piece of malicious traffic — the actual hostname and username tied to it. This narrows down where to start looking and who to talk to.

**Why this matters (and its double edge):** enterprise networks usually follow a consistent naming pattern for hosts and users (e.g. `FIN-LAPTOP-042` or `jdoe`). That consistency is genuinely useful for inventory purposes — you can tell what a machine is just by its name. But that same predictability is a gift to an attacker: once they learn the naming convention, they can clone it and create a rogue host or account that blends right into the environment, making it much harder to spot. So knowing how to trace real host/user identity from raw traffic is a core skill regardless of how good the naming convention is.

Three main protocols are useful for this kind of identification: **DHCP**, **NetBIOS (NBNS)**, and **Kerberos**.

---

### DHCP Analysis

**DHCP (Dynamic Host Configuration Protocol)** is what automatically hands out IP addresses and network configuration details to devices joining a network.

- Global Wireshark filter: `dhcp or bootp`

<img width="1502" height="1068" alt="DHCP" src="https://github.com/user-attachments/assets/1dd680d9-0589-4f6e-af60-985e1da24b64" />


DHCP traffic breaks down into a few key packet types, each useful for different info:

| Packet Type | What It Means | Filter |
|---|---|---|
| DHCP Request | Client asking for an IP — **contains the hostname** | `dhcp.option.dhcp == 3` |
| DHCP ACK | Server accepted the request | `dhcp.option.dhcp == 5` |
| DHCP NAK | Server denied the request | `dhcp.option.dhcp == 6` |

(These numeric values come from DHCP "Option 53," the message-type field — it's the only option with fixed, predefined values across all DHCP traffic, which is why it's the natural first filter before drilling into anything else.)

**Useful fields inside a DHCP Request** (the "low-hanging fruit" for identifying a host):
- **Option 12** – Hostname
- **Option 50** – Requested IP address
- **Option 51** – Requested IP lease time
- **Option 61** – Client's MAC address
- Filter example: `dhcp.option.hostname contains "keyword"`

**Useful fields inside a DHCP ACK:**
- **Option 15** – Domain name
- **Option 51** – Assigned IP lease time
- Filter example: `dhcp.option.domain_name contains "keyword"`

**Useful field inside a DHCP NAK:**
- **Option 56** – the rejection message/reason. Since the exact wording of this message varies case by case, it's better to actually *read* it rather than try to filter on specific text — that context can help build a more accurate picture of what happened.

---

### NetBIOS (NBNS) Analysis

**NetBIOS** lets applications on different hosts on the same network talk to each other — think of it as an older, local-network-scoped way for machines to find and address one another by name (before DNS became the default everywhere).

- Global Wireshark filter: `nbns`

<img width="1502" height="1068" alt="NetBIOS (NBNS) Analysis" src="https://github.com/user-attachments/assets/4f465fc8-034e-4684-b3f7-39e3fde0d7f1" />


**Useful field:**
- **Queries** — contains the name being looked up, along with TTL (time to live) and IP address details
- Filter example: `nbns.name contains "keyword"`

---

### Kerberos Analysis

**Kerberos** is the default authentication protocol for Microsoft Windows domains — it handles proving identity securely between machines over a network that isn't inherently trusted, without sending passwords in plaintext.

- Global Wireshark filter: `kerberos`

<img width="1502" height="1068" alt="Kerberos Analysis" src="https://github.com/user-attachments/assets/d6008e38-e77f-4a22-a3c7-3304a86659d9" />


**Finding usernames:**
- The field `CNameString` holds the username tied to the ticket request.
- ⚠️ Important nuance: sometimes this field actually holds a **hostname** instead of a username — Windows appends a `$` to the end of hostnames to distinguish them. So to isolate real usernames, exclude anything ending in `$`.
  - Search by keyword: `kerberos.CNameString contains "keyword"`
  - Usernames only (excluding hostnames): `kerberos.CNameString and !(kerberos.CNameString contains "$")`

**Other useful fields:**
- **pvno** – protocol version number → `kerberos.pvno == 5`
- **realm** – the domain name associated with the generated ticket → `kerberos.realm contains ".org"`
- **sname** – the service + domain name tied to the ticket (e.g. filtering for the special `krbtgt` service account, which is central to Kerberos ticket-granting) → `kerberos.SNameString == "krbtg"`
- **addresses** – the client's IP address and NetBIOS name — note this is only present in **request** packets, not responses

---

**Big picture:** these three protocols each leak a different piece of the "who and what" puzzle — DHCP gives you the hostname tied to an IP at a point in time, NetBIOS helps resolve names on the local network, and Kerberos ties actual usernames to authentication activity. Cross-referencing all three during an investigation is often what turns "this IP did something bad" into "this specific host and user account did something bad."

---

## Wireshark – ICMP & DNS Tunnelling

**Tunnelling** = hiding malicious data inside a trusted, ordinary-looking protocol so it slips past security perimeters. ICMP and DNS are the two most commonly abused for this since both are everyday traffic that's rarely inspected closely.

### ICMP Tunnelling
ICMP is normally just used for diagnostics and error reporting (like `ping`). Because it's such a trusted protocol, attackers can stuff extra data into ICMP packets — even disguising TCP, HTTP, or SSH traffic inside — to exfiltrate data or run a C2 channel. This kind of activity usually shows up as a fresh anomaly right after malware execution or a successful exploit.

**What to watch for:**
- Unusually high volume of ICMP traffic
- Packet sizes bigger than the ~64 byte norm
- Signs of another protocol's data hidden inside the payload

| Purpose | Filter |
|---|---|
| Global search | `icmp` |
| Oversized packets | `data.len > 64 and icmp` |

<img width="1503" height="1069" alt="ICMP" src="https://github.com/user-attachments/assets/148dd0f4-4259-4ec3-94e1-a12d9aabce3b" />


> Note: many enterprise networks block custom ICMP packets or require admin rights to craft them — this limits how easily attackers can pull this off.

### DNS Tunnelling
DNS translates domain names into IPs and is such routine, constant traffic that it's rarely scrutinized — making it a favorite channel for C2 and exfiltration. The attacker owns a domain set up as their C2 server; after exploitation, the malware sends DNS queries where the "subdomain" isn't real at all — it's an **encoded command**, like: `encoded-cmd.maliciousdomain.com`


The query resolves to the attacker's server, which decodes it and sends back real instructions. Since it still looks like normal DNS activity, it often slips past network perimeter defenses.

**What to watch for:**
- Query length longer than typical
- Random or anomalous-looking domain names
- Long, encoded-looking subdomains
- Known tool signatures — **dnscat**, **dns2tcp**
- Abnormal spike in requests to one particular domain

| Purpose | Filter |
|---|---|
| Global search | `dns` |
| Exclude local noise | `!mdns` |
| Tool signature match | `dns contains "dnscat"` |
| Long non-local query names | `dns.qry.name.len > 15 and !mdns` |

<img width="1503" height="1069" alt="DNS" src="https://github.com/user-attachments/assets/59aa14ba-c1fa-4dad-8c08-54feaa676fef" />

---

## Wireshark – FTP (Cleartext Protocol) Analysis

Analyzing cleartext protocols isn't just "follow the stream and read the text" — on a large network capture, a proper investigation means pulling out statistics and key patterns, not just eyeballing individual sessions.

### FTP Basics
**FTP (File Transfer Protocol)** is built for simplicity, not security — it transfers everything, including credentials, in **cleartext**. In an unsecured environment this opens the door to:
- MITM attacks
- Credential stealing / unauthorized access
- Phishing
- Malware planting
- Data exfiltration

- Global filter: `ftp`

### FTP Response Codes
FTP responses follow a numeric pattern by category:

<img width="1503" height="1069" alt="ftp" src="https://github.com/user-attachments/assets/dcd5860e-300f-4c02-b14d-bd975535528b" />

| Series | Meaning | Example Codes |
|---|---|---|
| x1x | Information/request responses | 211 System status, 212 Directory status, 213 File status |
| x2x | Connection messages | 220 Service ready, 227 Entering passive mode, 228 Long passive mode, 229 Extended passive mode |
| x3x | Authentication messages | 230 User login, 231 User logout, 331 Valid username, 430 Invalid username/password, 530 No login (invalid password) |

- `200` generally means the command was successful.
- Filter examples: `ftp.response.code == 211` · `ftp.response.code == 227` · `ftp.response.code == 230`

### Key FTP Commands
- **USER** – username → `ftp.request.command == "USER"`
- **PASS** – password → `ftp.request.command == "PASS"`
- **CWD** – current working directory
- **LIST** – directory listing

### Spotting Attacks in FTP Traffic
- **Brute-force signal** — list of failed login attempts: `ftp.response.code == 530`
- **Brute-force on one username** — failed logins tied to a specific username: `(ftp.response.code == 530) and (ftp.response.arg contains "username")`
- **Password spray signal** — same password tried against multiple usernames: `(ftp.request.command == "PASS") and (ftp.request.arg == "password")`

---

## Wireshark – HTTP Analysis & Log4j Detection

### HTTP Basics
**HTTP** is a cleartext, request-response, client-server protocol — the backbone of normal web traffic, and by default it's not blocked by network perimeters. Because it's unencrypted and universal, HTTP analysis can reveal:
- Phishing pages
- Web attacks
- Data exfiltration
- C2 traffic

- Global filter: `http` (also `http2` — a newer revision supporting binary data and multiplexed requests/responses for better performance/security)

### HTTP Request Methods
- **GET** / **POST** — filter examples: `http.request.method == "GET"` · `http.request.method == "POST"` · list all requests: `http.request`

### HTTP Response Status Codes

| Code | Meaning |
|---|---|
| 200 OK | Request successful |
| 301 / 302 | Resource moved permanently / temporarily |
| 400 Bad Request | Server didn't understand the request |
| 401 Unauthorised | Needs login/authorization |
| 403 Forbidden | No access to the resource |
| 404 Not Found | Resource doesn't exist |
| 405 Method Not Allowed | Method not supported/blocked |
| 408 Request Timeout | Took too long |
| 500 Internal Server Error | Unexpected server error |
| 503 Service Unavailable | Server/service down |

Filter examples: `http.response.code == 200/401/403/404/405/503`

### Useful HTTP Parameters
- **User agent** – browser/OS identity → `http.user_agent contains "nmap"`
- **Request URI / Full URI** – points to the requested resource → `http.request.uri contains "admin"` · `http.request.full_uri contains "admin"`
- **Server** – server software → `http.server contains "apache"`
- **Host** – hostname → `http.host contains "keyword"`
- **Connection** – connection status → `http.connection == "Keep-Alive"`
- **Line-based text data** – cleartext data from server → `data-text-lines contains "keyword"`

### User Agent Analysis
Attackers try to blend into normal traffic, and the User-Agent field is a useful (but not fully reliable) place to spot anomalies — it can be spoofed, so never whitelist a user agent purely because it looks normal. Treat it as one supporting signal among several.

**What to look for:**
- Different user agents from the same host in a short time window
- Non-standard/custom user agent strings
- Subtle spelling differences (e.g. "Mozilla" vs "Mozlilla")
- Known audit/attack tool signatures — Nmap, Nikto, Wfuzz, sqlmap
- Payload data stuffed directly into the user agent field

- Global filter: `http.user_agent`
- Tool detection: `(http.user_agent contains "sqlmap") or (http.user_agent contains "Nmap") or (http.user_agent contains "Wfuzz") or (http.user_agent contains "Nikto")`


<img width="1668" height="1069" alt="User agent" src="https://github.com/user-attachments/assets/99496cb3-9b3d-43d6-aa02-094d494925a7" />


---

## Log4j Attack Detection

Good investigation starts with knowing the threat's known patterns *before* opening Wireshark. For Log4j specifically:

- The attack begins with a **POST** request → `http.request.method == "POST"`
- Known cleartext exploit patterns in traffic: **`jndi:ldap`** and **`Exploit.class`**
  - `(ip contains "jndi") or (ip contains "Exploit")`
  - `(frame contains "jndi") or (frame contains "Exploit")`
- Obfuscated/encoded payloads often show up in the user agent field, frequently containing **`$`** or **`==`** (Base64 padding) → `(http.user_agent contains "$") or (http.user_agent contains "==")`

<img width="1668" height="1069" alt="Log4j vulnerability" src="https://github.com/user-attachments/assets/179506ac-9f98-4c62-bc8b-a178a592970c" />
