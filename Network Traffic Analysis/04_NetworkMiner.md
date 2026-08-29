## NetworkMiner — Network Forensic Analysis Tool

### What is NetworkMiner?
Open-source **NFAT (Network Forensic Analysis Tool)**.
Passive analysis — fingerprints hosts/sessions/ports without sending any traffic.

**Platforms:** Windows, Linux, macOS, FreeBSD

---

### Two Operating Modes

| Mode | Description |
|------|-------------|
| **Passive Sniffer** | Captures live traffic without sending any packets — zero footprint |
| **PCAP Parser** | Loads existing capture files — reassembles files, certificates, sessions |

---

### What NetworkMiner Provides

| Info | Details |
|------|---------|
| **Host context** | IP, MAC, hostname, OS fingerprint |
| **Attack indicators** | Traffic spikes, port scans, anomalies |
| **Tool identification** | Detects tools used (e.g. Nmap scan signatures) |

---

### Network Forensics Goal
Provide sufficient information to detect:
- Malicious activities
- Security breaches
- Network anomalies

NetworkMiner gives analysts a **quick starting point** — context before deep-diving into packet details.

---

### Supported Data Types

| Data Type | Examples |
|-----------|---------|
| **Live Traffic** | Real-time capture from network interface |
| **Traffic Captures** | PCAP/PCAPNG files |
| **Log Files** | Network log analysis |

---

### NetworkMiner vs Wireshark

| | NetworkMiner | Wireshark |
|-|-------------|-----------|
| **Primary use** | Host/session context, file extraction | Deep packet analysis |
| **Ease of use** | Beginner-friendly GUI | More complex |
| **File extraction** | Automatic from PCAP | Manual via Follow Stream |
| **OS fingerprinting** | Built-in | Not built-in |
| **Filtering** | Limited | Extremely powerful |
| **Best for** | Quick forensic triage | Detailed investigation |

> Use NetworkMiner for quick context → use Wireshark for deep analysis.
> They complement each other in a forensic workflow.

---

## NetworkMiner — Capabilities & Comparison

### Core Capabilities

| Capability | Description |
|-----------|-------------|
| **Traffic Sniffing** | Intercept, collect and log packets (Windows only) |
| **PCAP Parsing** | Parse pcap files, show packet details |
| **Protocol Analysis** | Identify protocols from parsed PCAP |
| **OS Fingerprinting** | Identify OS via Satori + p0f |
| **File Extraction** | Extract images, HTML, emails from PCAP |
| **Credential Grabbing** | Extract credentials from PCAP |
| **Cleartext Keyword Parsing** | Extract cleartext strings/keywords |

---

### Operating Modes

| Mode | Notes |
|------|-------|
| **Sniffer** | Windows only — not reliable, not recommended as primary sniffer |
| **PCAP Parsing** | Primary use — quick overview before deep investigation |

> NetworkMiner = NFAT with a sniffer feature, NOT a dedicated sniffer.
> Use Wireshark/tcpdump for reliable sniffing.

---

### Pros & Cons

| Pros | Cons |
|------|------|
| OS fingerprinting | Not useful for active sniffing |
| Easy file extraction | Not useful for large PCAPs |
| Credential grabbing | Limited filtering options |
| Cleartext keyword parsing | Not built for manual traffic investigation |
| Quick overall overview | |

---

### NetworkMiner vs Wireshark

| Feature | NetworkMiner | Wireshark |
|---------|-------------|-----------|
| **Purpose** | Quick overview + data extraction | Deep packet analysis |
| **GUI** | ✅ | ✅ |
| **Sniffing** | ✅ (Windows, unreliable) | ✅ (reliable) |
| **PCAP handling** | ✅ | ✅ |
| **OS Fingerprinting** | ✅ | ❌ |
| **Keyword/Parameter Discovery** | ✅ | Manual |
| **Credential Discovery** | ✅ | ✅ |
| **File Extraction** | ✅ | ✅ |
| **Filtering** | Limited | ✅ Extremely powerful |
| **Packet Decoding** | Limited | ✅ |
| **Protocol Analysis** | ❌ | ✅ |
| **Payload Analysis** | ❌ | ✅ |
| **Statistical Analysis** | ❌ | ✅ |
| **Host Categorisation** | ✅ | ❌ |
| **Cross-platform** | ✅ | ✅ |

---

### Best Practice Workflow

```
Capture traffic
    ↓
NetworkMiner → quick triage
    → Host inventory (IP, MAC, OS)
    → Extract files, credentials, keywords
    → Identify attack indicators
    ↓
Wireshark → deep investigation
    → Filter specific traffic
    → Analyze protocols and payloads
    → Reconstruct attack timeline
```

> NetworkMiner = "low hanging fruit" first pass.
> Wireshark = detailed forensic investigation.

---

## NetworkMiner — Interface & Key Menus

### Loading Files
```
File → Open → select .pcap/.pcapng
```

<img width="1035" height="494" alt="Landing page" src="https://github.com/user-attachments/assets/d6fc320e-279f-4f9a-97cc-af3a5bdfd76c" />

**View file metadata:**
```
Case Panel (right side) → right-click filename → Show Metadata
```

<img width="755" height="470" alt="Viewing metadata" src="https://github.com/user-attachments/assets/e961280a-2d59-402f-857e-b966e625e35a" />

---

### Hosts Tab
Identified hosts from PCAP with:

<img width="924" height="825" alt="Host" src="https://github.com/user-attachments/assets/30607187-cc9b-4be2-a618-b9e0cacec3b2" />

| Info | Details |
|------|---------|
| IP + MAC address | Host identification |
| OS type | Fingerprinted via Satori + p0f |
| Open ports | Detected from traffic |
| Sent/Received packets | Traffic volume per host |
| Incoming/Outgoing sessions | Session count |
| Host details | Additional context |

**MAC database:** mac-ages GitHub repo
**Sorting:** Available via sort menu
**Color coding:** Customizable per host
**OSINT lookup:** Premium only

---

### Sessions Tab
Detected sessions with:

<img width="928" height="163" alt="sessions" src="https://github.com/user-attachments/assets/8ccfd405-e830-4a2c-b2c8-7d06b4182310" />

| Field | Info |
|-------|------|
| Frame number | Packet reference |
| Client + Server address | Endpoints |
| Source + Destination port | Port details |
| Protocol | Session protocol |
| Start time | When session began |

**Search bar filter types:**
```
"ExactPhrase"   → exact string match
"AllWords"      → all words must appear
"AnyWord"       → any word matches
"RegExe"        → regex pattern match
```

---

### DNS Tab
DNS queries with full detail:

<img width="927" height="195" alt="dns" src="https://github.com/user-attachments/assets/2871cf8d-3ab5-41fa-9ed8-a6163b9ae5ee" />

| Field | Info |
|-------|------|
| Frame number + Timestamp | When query occurred |
| Client + Server | Who queried whom |
| Src + Dst port | Port 53 details |
| IP TTL + DNS time | Timing info |
| Transaction ID + Type | Query tracking |
| DNS query + answer | Full Q&A |
| Alexa Top 1M | Premium only |

---

### Credentials Tab
Auto-extracted credentials and hashes:

<img width="1204" height="561" alt="Credentials" src="https://github.com/user-attachments/assets/837c612d-f2cd-464c-9ae4-b37661e12cd4" />

**Supported protocols:**
`Kerberos` `NTLM` `RDP cookies` `HTTP cookies` `HTTP requests` `IMAP` `FTP` `SMTP` `MS SQL`

**Post-extraction:** Use Hashcat or John the Ripper to crack extracted hashes.
```
Hashcat: https://github.com/hashcat/hashcat
John:    https://github.com/openwall/john
```

**Right-click:** Copy username/password values directly.

---

## NetworkMiner — Additional Tabs

### Files Tab
Extracted files from PCAP with full metadata:

<img width="1372" height="772" alt="Files" src="https://github.com/user-attachments/assets/54a07889-7362-42b1-bb9f-f9550e76326d" />

| Field | Info |
|-------|------|
| Frame number | Packet reference |
| Filename + Extension | File identity |
| Size | File size |
| Src + Dst address/port | Transfer endpoints |
| Protocol | How file was transferred |
| Timestamp | When extracted |
| Reconstructed path | Where file was saved |

**Right-click:** Open file, open folder, view details
**OSINT hash lookup + sample submission:** Premium only

---

### Images Tab
Extracted images from PCAP — visual browser.

<img width="713" height="772" alt="Images" src="https://github.com/user-attachments/assets/c168172a-42fe-452f-bae2-287386f9a0ef" />

- Right-click → open, zoom in/out
- Hover over image → shows src/dst address + file path
- Quick visual triage for suspicious images transferred over network

---

### Parameters Tab
Extracted HTTP/URL parameters:

<img width="1123" height="355" alt="Parameters" src="https://github.com/user-attachments/assets/e22b6a66-fb7d-44c0-87e9-ff2b5675aaec" />

| Field | Info |
|-------|------|
| Parameter name | e.g. `username`, `token` |
| Parameter value | Actual value passed |
| Frame number | Packet reference |
| Src + Dst host/port | Endpoints |
| Timestamp | When captured |

**Right-click:** Copy parameter name/value directly
> Useful for finding credentials passed in GET/POST parameters.

---

### Keywords Tab
Extracted cleartext keywords from all data in PCAP.

<img width="1201" height="914" alt="Keywords" src="https://github.com/user-attachments/assets/7036905d-3e17-4342-9691-e8166185a810" />


| Field | Info |
|-------|------|
| Frame number | Packet reference |
| Timestamp | When found |
| Keyword | Matched term |
| Context | Surrounding text |
| Src + Dst host/port | Endpoints |

**How to use keyword search:**
```
1. Add keywords to search list
2. Reload case files (required after updating keywords)
3. Results appear with context
```
> Searches ALL possible data in processed PCAPs — comprehensive coverage.
> Multiple keywords supported — reload required after each update.

---

### Messages Tab
Extracted emails, chats, and messages:

<img width="1463" height="777" alt="Messages" src="https://github.com/user-attachments/assets/da90dbef-3919-4be4-be84-751f1f45dbc6" />


| Field | Info |
|-------|------|
| Frame number | Packet reference |
| Src + Dst host | Endpoints |
| Protocol | Email/chat protocol |
| Sender (From) | Message origin |
| Receiver (To) | Intended recipient |
| Timestamp | When sent |
| Size | Message size |

- Click message → see attachments + attributes
- Built-in viewer for full message inspection
- Right-click → open file to explore attachments

---

### Anomalies Tab
Auto-detected anomalies in the PCAP.

> NetworkMiner is NOT an IDS — anomaly detection is limited.

**Built-in detections:**
- **EternalBlue exploit** (MS17-010 — WannaCry vector)
- **Spoofing attempts** (ARP/IP spoofing indicators)

---

## NetworkMiner — Version Differences (v1.6 vs v2.7)

### Feature Comparison

| Feature | v1.6 | v2.7+ |
|---------|------|-------|
| **MAC address conflict detection** | ❌ | ✅ |
| **Detailed packet view** (sent/received) | ✅ | ❌ |
| **Frame processing** | ✅ | ❌ |
| **Parameter processing** | Limited | ✅ Extended |
| **Cleartext data tab** (all in one place) | ✅ | ❌ |

---

### Key Differences Explained

#### MAC Address Processing
- **v2.7+:** Processes MAC-specific correlation → identifies MAC address conflicts
- **v1.6:** Not available

<img width="958" height="906" alt="Mac address" src="https://github.com/user-attachments/assets/f31e906a-9dc8-4ad3-9aab-bb1d12bfdbeb" />


#### Packet Detail Processing
- **v1.6:** Detailed sent/received packet inspection
- **v2.7+:** Not available

<img width="955" height="899" alt="packet details" src="https://github.com/user-attachments/assets/c2853121-5dad-4a1c-bf25-6556f35a9fe4" />

#### Frame Processing
- **v1.6:** Frame count + essential frame details tab
- **v2.7+:** Not available

<img width="953" height="903" alt="Frames" src="https://github.com/user-attachments/assets/708f4cad-7a98-40d1-aae0-33465150a21e" />

#### Parameter Processing
- **v1.6:** Catches fewer parameters
- **v2.7+:** Extended parameter extraction — catches significantly more

<img width="962" height="911" alt="More parameters" src="https://github.com/user-attachments/assets/c015b46f-d8ba-4108-b03f-1aff943c7bf6" />

#### Cleartext Data Tab
- **v1.6:** All cleartext data in single dedicated tab — easy to browse
- **Limitation:** Cannot match cleartext data back to specific packets
- **v2.7+:** Not available as a dedicated tab

<img width="948" height="901" alt="Cleartext" src="https://github.com/user-attachments/assets/4a5417cf-923f-4349-a9b0-2b3fd247108d" />

---

### Which Version to Use

| Use Case | Recommended Version |
|----------|-------------------|
| MAC conflict detection | v2.7+ |
| Extended parameter extraction | v2.7+ |
| Detailed frame/packet inspection | v1.6 |
| Cleartext data overview | v1.6 |
| General forensic triage | v2.7+ |

---
