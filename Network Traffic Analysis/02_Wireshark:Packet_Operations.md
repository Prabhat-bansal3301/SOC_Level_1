## Wireshark — Statistics Menu

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
