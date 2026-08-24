<img width="1082" height="465" alt="capture filter" src="https://github.com/user-attachments/assets/41b95815-c95e-4e9d-8275-7afa8f60749e" />## Wireshark — Statistics Menu

### Overview
Statistics menu = big picture view of PCAP.
Use to build investigation hypothesis before diving into individual packets.

---

### Statistics Options

#### 1. Resolved Addresses
`Statistics → Resolved Addresses`

<img width="1463" height="803" alt="Resolved address" src="https://github.com/user-attachments/assets/4f60b0a5-8a91-4603-a8b8-99f19c5eb2af" />

- Lists all IP addresses + their resolved hostnames
- Hostname info pulled from DNS answers in the capture
- Quickly identify which domains/resources were accessed

---

#### 2. Protocol Hierarchy
`Statistics → Protocol Hierarchy`

<img width="1463" height="648" alt="Protocol hierarchy" src="https://github.com/user-attachments/assets/0d39831d-81b5-472f-a32e-27d99e9231ad" />

- Tree view of all protocols in the capture
- Shows packet counts + percentages per protocol
- Identify unusual protocols or unexpected traffic volume
- Right-click any protocol → filter directly

---

#### 3. Conversations
`Statistics → Conversations`

<img width="1299" height="1200" alt="conversations" src="https://github.com/user-attachments/assets/57d659f0-5da3-4195-9d1f-70d804bc22af" />


Traffic between **two specific endpoints**.
Available in 5 formats:

| Format | Shows |
|--------|-------|
| Ethernet | MAC-to-MAC conversations |
| IPv4 | IP-to-IP conversations |
| IPv6 | IPv6 conversations |
| TCP | TCP stream conversations |
| UDP | UDP conversations |

---

#### 4. Endpoints
`Statistics → Endpoints`

<img width="1463" height="784" alt="Endpoints" src="https://github.com/user-attachments/assets/65003357-22ca-440f-9897-78b4490bf871" />

Unique endpoints in the capture (single field view vs conversations).
Same 5 formats as Conversations.

**Name Resolution options:**
- **MAC → Manufacturer name** (IEEE lookup, first 3 bytes)
  - Enable: `Name resolution` button (lower-left of Endpoints window)
- **IP → Hostname resolution**
  - Enable: `Edit → Preferences → Name Resolution`
- **Port → Service name resolution**
  - Enable: same preferences menu

**GeoIP Mapping:**

<img width="1463" height="493" alt="Endpoints Geoip" src="https://github.com/user-attachments/assets/0b7c1d20-d8b8-49b7-8c93-529721d28d43" />

- Maps source/destination IPs to geographic locations
- Requires MaxMind DB files
- Configure: `Edit → Preferences → Name Resolution → MaxMind database directories`
- Once configured: GeoIP info appears under IP protocol details for matched IPs

---

### Statistics Workflow for SOC Analysis

```
Load PCAP
    ↓
Resolved Addresses → what domains were accessed?
    ↓
Protocol Hierarchy → any unexpected protocols?
    ↓
Conversations → who talked to who? volume?
    ↓
Endpoints → unique IPs — check reputation
    ↓
Enable GeoIP → any unexpected countries?
    ↓
Form hypothesis → drill into specific packets
```

---

## Wireshark — Protocol-Specific Statistics

### IPv4 / IPv6 Statistics
`Statistics → IPv4 Statistics` / `Statistics → IPv6 Statistics`

<img width="1239" height="1200" alt="ipv4 and ipv6" src="https://github.com/user-attachments/assets/2a74a108-0f0c-40fb-9f96-7e1ecfab3069" />


- Narrows all stats to specific IP version
- Lists all events linked to IPv4 or IPv6 only
- Useful when capture contains mixed traffic and you need to isolate one version

---

### DNS Statistics
`Statistics → DNS`

<img width="1463" height="879" alt="dns" src="https://github.com/user-attachments/assets/0effbbfa-72d0-42e9-bd76-a3e22cd692ef" />


Tree view breakdown of all DNS packets:

| Info Available | Use |
|----------------|-----|
| **Rcode** | Response codes (NOERROR, NXDOMAIN, REFUSED) |
| **Opcode** | Query type (standard, inverse, status) |
| **Class** | IN (Internet) = normal |
| **Query type** | A, AAAA, TXT, MX, PTR, CNAME, etc. |
| **Service stats** | Request/response counts |
| **Query stats** | Most queried domains |

**SOC use cases:**
- High TXT query count → possible DNS tunneling
- NXDOMAIN spikes → DGA (Domain Generation Algorithm) malware
- Unusual query types → C2 communication via DNS

---

### HTTP Statistics
`Statistics → HTTP`

<img width="1320" height="1200" alt="http" src="https://github.com/user-attachments/assets/ad9adbd2-3a9b-4386-a9a2-8e3071d1ccf4" />


Tree view breakdown of all HTTP packets:

| Info Available | Use |
|----------------|-----|
| **Request methods** | GET, POST, PUT, DELETE counts |
| **Response codes** | 200, 301, 404, 500, etc. |
| **Original requests** | Full URLs requested |

**SOC use cases:**
- Many 404s from same host → directory brute-forcing
- POST requests to unknown domains → data exfiltration
- Unusual User-Agents → malware C2 over HTTP
- Large responses → file downloads

---

### Protocol Statistics Quick Reference

| Menu | Best for |
|------|---------|
| `Statistics → IPv4 Statistics` | IPv4-specific traffic breakdown |
| `Statistics → IPv6 Statistics` | IPv6-specific traffic breakdown |
| `Statistics → DNS` | DNS abuse detection, query analysis |
| `Statistics → HTTP` | Web traffic analysis, exfiltration detection |

---

## Wireshark — Packet Filtering

### Two Filter Types

| | Capture Filter | Display Filter |
|-|---------------|----------------|
| **When set** | Before capture starts | Anytime during/after capture |
| **Changeable** | No — fixed during capture | Yes — change anytime |
| **Purpose** | Save only specific traffic | Reduce visible packets for analysis |
| **Protocol support** | Limited | 3000+ protocols |
| **Syntax** | BPF (byte offset/hex) | Wireshark display filter language |

> **Rule:** Capture everything → filter with display filters for investigation.
> Only use capture filters when you know exactly what traffic you need.

---

### Capture Filter Syntax (BPF)

<img width="1082" height="465" alt="capture filter" src="https://github.com/user-attachments/assets/abfe6845-5b2b-4642-a96f-9e8d4ed84ba7" />


```
Scope:     host, net, port, portrange
Direction: src, dst, src or dst, src and dst
Protocol:  ether, wlan, ip, ip6, arp, rarp, tcp, udp
```

**Examples:**
```bash
tcp port 80                    # HTTP traffic
host 192.168.1.1               # Traffic to/from specific host
src 10.10.10.100               # Traffic from specific source
net 192.168.1.0/24             # Entire subnet
tcp portrange 1-1024           # System port range
```

Quick reference: `Capture → Capture Filters`

---

### Display Filter Syntax

<img width="1082" height="457" alt="display filter" src="https://github.com/user-attachments/assets/f524f4cc-6611-49e8-aea4-45c9e0810a8d" />


**Examples:**
```wireshark
tcp.port == 80
ip.src == 10.10.10.100
```

Quick reference: `Analyse → Display Filters`
Full reference: [Display Filter Reference](https://www.wireshark.org/docs/dfref/)

---

### Comparison Operators

| English | C-Like | Description | Example |
|---------|--------|-------------|---------|
| `eq` | `==` | Equal | `ip.src == 10.10.10.100` |
| `ne` | `!=` | Not equal | `ip.src != 10.10.10.100` |
| `gt` | `>` | Greater than | `ip.ttl > 250` |
| `lt` | `<` | Less than | `ip.ttl < 10` |
| `ge` | `>=` | Greater than or equal | `ip.ttl >= 0xFA` |
| `le` | `<=` | Less than or equal | `ip.ttl <= 0xA` |

> Wireshark supports both decimal and hex values in filters.

---

### Logical Operators

| English | C-Like | Example |
|---------|--------|---------|
| `and` | `&&` | `(ip.src == 10.10.10.100) AND (tcp.port == 80)` |
| `or` | `\|\|` | `(ip.src == 10.10.10.100) OR (ip.src == 10.10.10.111)` |
| `not` | `!` | `!(ip.src == 10.10.10.222)` |

> ⚠️ Use `!(value)` style — `!=value` is deprecated and gives inconsistent results.

---

### Filter Toolbar Tips
- Filters are **lowercase**
- **Autocomplete** with dot notation: `ip.` → shows all IP fields
- **Color coding:**

<img width="1463" height="361" alt="valid filter comparison" src="https://github.com/user-attachments/assets/03822f68-91c6-43b7-b8c9-116752559ea3" />


| Color | Meaning |
|-------|---------|
| 🟢 Green | Valid filter |
| 🟡 Yellow | Valid but possibly unexpected results |
| 🔴 Red | Invalid filter — syntax error |

---

### Common Display Filters Quick Reference

```wireshark
# By IP
ip.src == 192.168.1.1
ip.dst == 192.168.1.1
ip.addr == 192.168.1.1          # src OR dst

# By port
tcp.port == 443
udp.port == 53
tcp.dstport == 80

# By protocol
http
dns
ftp
smtp
icmp
arp

# Combinations
ip.src == 10.10.10.1 && tcp.port == 80
http && ip.dst == 192.168.1.100
!(arp) && !(dns)                # exclude noise
```
---

## Wireshark — Protocol Filters

### IP Filters (Network Layer)

<img width="1555" height="1089" alt="IP filter" src="https://github.com/user-attachments/assets/af536e25-cdec-444c-be5b-706d0dcd5a90" />

```wireshark
ip                              # All IP packets
ip.addr == 10.10.10.111         # Packets containing this IP (src OR dst)
ip.addr == 10.10.10.0/24        # Entire subnet (src OR dst)
ip.src == 10.10.10.111          # Packets FROM this IP only
ip.dst == 10.10.10.111          # Packets TO this IP only
```

> `ip.addr` = direction-agnostic (src OR dst)
> `ip.src` / `ip.dst` = direction-specific

---

### TCP & UDP Filters (Transport Layer)

<img width="1555" height="1089" alt="TCP and UDP filter" src="https://github.com/user-attachments/assets/bf5be686-4471-4bd6-8618-160e2cf5b1b2" />

```wireshark
# TCP
tcp.port == 80                  # All TCP on port 80 (src or dst)
tcp.srcport == 1234             # TCP from source port 1234
tcp.dstport == 80               # TCP to destination port 80

# UDP
udp.port == 53                  # All UDP on port 53
udp.srcport == 1234             # UDP from source port 1234
udp.dstport == 5353             # UDP to destination port 5353
```

---

### HTTP Filters (Application Layer)

<img width="1555" height="1089" alt="Application Level Protocol Filters (HTTP and DNS)" src="https://github.com/user-attachments/assets/db23f7d2-4965-4c53-b426-93f1f1d268c3" />

```wireshark
http                            # All HTTP packets
http.request.method == "GET"    # GET requests only
http.request.method == "POST"   # POST requests only
http.response.code == 200       # Successful responses
http.response.code == 404       # Not found responses
http.response.code == 500       # Server error responses
```

---

### DNS Filters (Application Layer)

```wireshark
dns                             # All DNS packets
dns.flags.response == 0         # DNS requests only
dns.flags.response == 1         # DNS responses only
dns.qry.type == 1               # DNS "A" record queries
dns.qry.type == 28              # DNS "AAAA" record queries
dns.qry.type == 16              # DNS "TXT" record queries (C2 indicator)
```

---

### Display Filter Expressions (Built-in Guide)
`Analyse → Display Filter Expression`

<img width="862" height="746" alt="Display filter Expressions" src="https://github.com/user-attachments/assets/824d6b6c-f3cb-4813-b28c-9a9839bf09f6" />

Use when you:
- Can't recall the exact filter field name
- Are unsure what values a filter accepts
- Need to explore available fields for a protocol

Shows: protocol fields + accepted value types (integer/string) + predefined values

---

### Common Investigation Combinations

```wireshark
# HTTP from specific host
http && ip.src == 192.168.1.100

# DNS TXT queries (possible C2/tunneling)
dns && dns.qry.type == 16

# Failed HTTP responses
http.response.code >= 400

# POST requests to external IPs
http.request.method == "POST" && !(ip.dst == 192.168.0.0/16)

# Large DNS responses (possible tunneling)
dns && dns.flags.response == 1 && frame.len > 512

# TCP SYN only (connection attempts)
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

---

### Quick Filter Reference Card

| Filter | What it finds |
|--------|--------------|
| `ip.src == X` | Traffic from X |
| `ip.dst == X` | Traffic to X |
| `tcp.port == 443` | HTTPS traffic |
| `udp.port == 53` | DNS traffic |
| `http.request.method == "POST"` | Data submissions |
| `http.response.code == 200` | Successful HTTP |
| `dns.flags.response == 0` | DNS queries |
| `dns.qry.type == 16` | TXT records (C2 check) |
