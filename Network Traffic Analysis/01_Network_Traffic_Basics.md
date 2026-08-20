## Network Traffic Analysis — Why It Matters

### The Core Problem
Logs (firewall, DNS) record **what** happened but not **what was in it**.
Network traffic analysis reveals the **content** of communications.

---

### DNS Tunneling — Real Scenario

**Alert:** Unusual DNS queries from WIN-016 (192.168.1.16)

```
2025-10-03 09:15:23  SRC=192.168.1.16  QUERY=aj39skdm.malicious-tld.com  QTYPE=A
2025-10-03 09:15:31  SRC=192.168.1.16  QUERY=msd91azx.malicious-tld.com  QTYPE=A
2025-10-03 09:15:45  SRC=192.168.1.16  QUERY=cmd01.malicious-tld.com     QTYPE=TXT
```

**What DNS logs give you:**

| Info | Use |
|------|-----|
| Query + query type | Identify TXT queries (C2 channel) |
| Subdomain + TLD | Check against VirusTotal/AbuseIPDB |
| Source IP | Identify compromised host |
| Destination IP | Check reputation |
| Timestamp | Build attack timeline |

**What DNS logs DON'T give you:** Content of the query/response

**Packet capture reveals:**
```json
cmd1.evilc2.com: type TXT
TXT: "SSBsb3ZlIHlvdXIgY3VyaW91c2l0eQ=="
         ↑ Base64 encoded C2 command
```
→ Decode with CyberChef → reveals actual C2 instructions

---

### Why Network Traffic Analysis

**General use:**
- Monitor network performance
- Detect abnormalities (traffic spikes, slow network)
- Inspect content of suspicious communications
  - DNS exfiltration
  - Malicious file download over HTTP
  - Lateral movement traffic

**SOC use:**
- Detect suspicious/malicious activity
- Reconstruct attacks during incident response
- Verify and validate alerts from SIEM/EDR

---

### Real Examples

```
Scenario 1:
Host behavior changes at 4PM UTC
    ↓ Network traffic analysis
Suspicious HTTP request found → extracted malicious ZIP file

Scenario 2:
Alert: host sending abnormal volume of DNS requests
    ↓ Inspect DNS request content
Data being exfiltrated via DNS tunneling confirmed
```

---

### Logs vs Packet Capture

| | Firewall/DNS Logs | Packet Capture (PCAP) |
|-|-------------------|----------------------|
| **Connection info** | ✓ | ✓ |
| **Timestamps** | ✓ | ✓ |
| **Packet content** | ✗ | ✓ |
| **Payload data** | ✗ | ✓ |
| **C2 commands in DNS TXT** | ✗ | ✓ |
| **Exfiltrated data** | ✗ | ✓ |

> Logs tell you something happened.
> PCAP tells you exactly what happened and what was transferred.

---

### Tools for Reputation Checks
| Tool | Link |
|------|------|
| AbuseIPDB | [abuseipdb.com](https://www.abuseipdb.com/) |
| VirusTotal | [virustotal.com](https://www.virustotal.com/) |

---
## Network Traffic Analysis — TCP/IP Layers

### Why Layer-by-Layer Analysis Matters
Logs capture bits of each layer's headers — never the full picture.
PCAP gives you everything: headers + payload at every layer.

---

### Application Layer

**What logs capture:** HTTP method, URL, response code, User-Agent
**What logs miss:** The actual payload/content

```http
# Request (logged by proxy/firewall)
GET /downloads/suspicious_package.zip HTTP/1.1
Host: www.tryhackme.thm
User-Agent: curl/7.85.0

# Response (logged)
HTTP/1.1 200 OK
Content-Type: application/zip
Content-Length: 10485760

# NOT logged → actual ZIP file content (10MB of binary data)
```

> Log shows file was downloaded. PCAP shows what's inside it.

---

### Transport Layer (TCP/UDP)

**What logs capture:** Src/dst ports, TCP flags
**What logs miss:** Sequence numbers, full header fields

```
# Normal TCP 3-way handshake
Seq=0  [SYN]      →
       [SYN,ACK]  ← Seq=0
Seq=1  [ACK]      →

# Session hijacking detection — Seq number jumps
Packet 6: NEW SOURCE IP, Seq=34567232  ← massive jump = session hijack attempt
```

**TCP Flags Reference:**

| Flag | Meaning |
|------|---------|
| SYN | Initiate connection |
| ACK | Acknowledge |
| PSH | Push data immediately |
| RST | Reset connection |
| FIN | Close connection |

---

### Internet Layer (IP)

**What logs capture:** Src/dst IP, TTL
**What logs miss:** Fragment offset, total length

**Fragmentation Attack Detection:**
```
# Normal fragmentation
Frag 1: Offset=0,    Len=1480  [MF]
Frag 2: Offset=1480, Len=1480  [MF]
Frag 3: Offset=2960, Len=64         ← normal

# Overlapping fragments (evasion attack)
Frag 1: Offset=0,    Len=1480  [MF]
Frag 2: Offset=1480, Len=1480  [MF]
Frag 3: Offset=1480, Len=64   ← OVERLAP with Frag 2 → IDS evasion
```

Overlapping byte ranges = attacker manipulating reassembly to bypass IDS.

---

### Link Layer (Ethernet/ARP)

**What logs capture:** Src/dst MAC addresses
**What logs miss:** ARP conflicts, gratuitous ARP floods

**ARP Poisoning Detection (requires full PCAP):**
```
# Legitimate ARP
192.168.1.1    → Who has 192.168.1.10?
192.168.1.10   → 192.168.1.10 is at 00:11:22:33:44:55  ✓

# Attacker spoofing (192.168.1.200 = attacker)
192.168.1.200  → 192.168.1.10 is at aa:bb:cc:dd:ee:ff  ← spoof
192.168.1.200  → 192.168.1.1 is at aa:bb:cc:dd:ee:ff   ← spoof
→ Traffic now routed through attacker (MITM)
```

---

### Layer Summary — Logs vs PCAP

| Layer | What logs give you | What PCAP adds |
|-------|-------------------|----------------|
| **Application** | URL, method, status code | Full payload/content |
| **Transport** | Ports, flags | Sequence numbers (session hijack detection) |
| **Internet** | Src/dst IP, TTL | Fragment offsets (fragmentation attacks) |
| **Link** | MAC addresses | ARP conflicts, gratuitous ARP (ARP poisoning) |

> Every attack type has a corresponding layer where it leaves traces.
> Logs alone = partial picture. PCAP = full investigation capability.

---

## Network Traffic Sources & Flows

### Traffic Sources

#### Intermediary Devices
Devices traffic passes **through** — generate low traffic volume themselves.
`Firewalls` `Switches` `Routers` `Web Proxies` `IDS/IPS` `Access Points` `WLC`

**Traffic they generate:**
- Routing protocols: EIGRP, OSPF, BGP
- Management: SNMP, PING
- Logging: SYSLOG
- Supporting: ARP, STP, DHCP

#### Endpoint Devices
Devices where traffic **originates and ends** — bulk of network bandwidth.
`Servers` `Workstations` `IoT devices` `Printers` `Mobile phones` `Cloud resources`

---

### Traffic Flows

#### North-South (LAN ↔ WAN)
Traffic crossing the firewall — **monitored closely**.

| Protocol | Direction |
|----------|-----------|
| HTTPS, DNS, SSH | Egress (outbound) |
| VPN, SMTP, RDP | Ingress/Egress |

> All NS traffic passes the firewall — proper firewall rules + logging = visibility.

#### East-West (Within LAN)
Traffic staying inside corporate network — **often monitored less** but critical for detecting lateral movement.

| Category | Protocols |
|----------|-----------|
| **Auth & Identity** | Kerberos, LDAP, RADIUS, TACACS+ |
| **File & Print** | SMB/CIFS, IPP/LPD |
| **Infrastructure** | DHCP, ARP, Internal DNS, Routing protocols |
| **Applications** | SQL over TCP, REST/gRPC APIs |
| **Backup/Replication** | File replication, MySQL binlog, PostgreSQL streaming |

> Attackers use EW traffic for lateral movement after initial access.
> Monitoring EW = detecting post-compromise activity.

---

### Flow Examples

#### HTTPS with TLS Inspection (Web Proxy)
```
Host → NGFW/Web Proxy → Web Server
         ↑ TLS terminated here
         ↑ Content inspected
         ↑ Two separate TCP sessions:
           Session 1: Client ↔ Proxy
           Session 2: Proxy ↔ Web Server
```

#### External DNS Flow
```
Host → Internal DNS Server (port 53)
    ↓ Cache miss
Internal DNS → Router → Firewall → External DNS Server
External DNS → Firewall → Router → Internal DNS → Host
```

#### SMB with Kerberos Authentication
```
Host wants \\FILESERVER\MARKETING
    ↓
Host → Domain Controller (KDC): request service ticket using TGT
DC → Host: service ticket
    ↓
Host → FILESERVER: SMB session using service ticket
FILESERVER → Host: access granted to share
```

---

### SOC Monitoring Priority

| Traffic | Priority | Why |
|---------|---------|-----|
| North-South | High | External threats entering/leaving |
| East-West Auth (Kerberos/LDAP) | High | Lateral movement detection |
| East-West SMB | High | Pass-the-hash, ransomware spread |
| Internal DNS | Medium | DNS tunneling, C2 beaconing |
| Infrastructure (ARP/DHCP) | Medium | ARP poisoning, rogue DHCP |

---

## Network Traffic Collection Methods

### 1. Logs
First entry point for network information. No universal standard — each vendor implements differently.

**Examples:**
```bash
# Linux Auth log (Syslog format)
Oct 8 11:20:15 web01 sshd[2145]: Accepted password for gensane from 192.168.1.50 port 52234 ssh2

# Apache access log (CLF format)
192.168.1.50 - - [08/Oct/2025:11:20:18 +0200] "GET /index.html HTTP/1.1" 200 2326
```

**Limitation:** Vendors log only select fields — never full packet content.
**Solution when logs aren't enough:** Full packet capture + log correlation + network statistics.

---

### 2. Full Packet Capture

Two methods to capture traffic:

#### Network TAP (Physical)
- Hardware device placed **inline** in network
- Copies all traffic without affecting performance
- Operates at link layer — no IP/MAC needed
- Copies electrical/light signals → forwarded to monitoring port
- **Near-zero performance impact**

#### Port Mirroring (Software)
- Software copy of packets from one port to another
- Cisco calls it **SPAN**

```bash
# Cisco SPAN configuration
Switch(config)# monitor session 1 source interface fastEthernet0/1
Switch(config)# monitor session 1 destination interface fastEthernet0/2
```
Also available on:
- VMware vSwitch (virtual environments)
- AWS VPC Traffic Mirroring (cloud)

#### TAP vs Port Mirroring

| | Network TAP | Port Mirroring |
|-|-------------|---------------|
| **Type** | Physical hardware | Software config |
| **Performance impact** | Near zero | Can impact on high traffic |
| **Layer** | Link layer only | All layers |
| **Cost** | Higher | Free (software) |

---

### Best Practices for Full Packet Capture

| Consideration | Detail |
|---------------|--------|
| **Placement** | Position TAP/mirror where target traffic flows |
| **Storage** | 1Gbps line × 24hrs ≈ 10.8TB — plan accordingly |
| **Duration** | Capture only what's needed — targeted, not continuous |

---

### Packet Analysis Tools
`Wireshark` `tcpdump` `Snort` `Suricata` `Zeek`

---

### 3. Network Statistics (Flow Data)

Metadata about traffic flows — not individual packets.
Great for detecting: C2 traffic, data exfiltration, lateral movement, anomalies.

#### NetFlow (Cisco)
```
Src IP: 12.1.1.1  Dst IP: 13.1.1.2
Bytes: 45230  Packets: 31  Duration: 120s
Protocol: TCP  Src Port: 51234  Dst Port: 443
```
- Collects flow metadata (not packet content)
- From NetFlow v9: templating support for other vendors

#### IPFIX
- Successor to NetFlow
- Vendor-neutral standard (IETF)
- More flexible field configuration
- Works with most modern NGFWs, IPS, IDS

#### NetFlow vs IPFIX

| | NetFlow | IPFIX |
|-|---------|-------|
| **Origin** | Cisco proprietary | IETF standard |
| **Vendor support** | Cisco + v9 adaptable | Vendor-neutral |
| **Flexibility** | Limited | High |
| **Purpose** | Flow metadata | Flow metadata |

---

### Collection Method Summary

| Method | What you get | Best for |
|--------|-------------|---------|
| **Logs** | Selected header fields | Quick triage, SIEM correlation |
| **Full PCAP** | Complete packet content | Deep investigation, malware analysis |
| **NetFlow/IPFIX** | Flow metadata | Anomaly detection, exfiltration detection |
