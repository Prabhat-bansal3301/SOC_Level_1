## Enterprise Network Components — Security Perspective

### Network as an Ecosystem
All components are interconnected — compromise one = potential access to all.
The network perimeter (internal ↔ Internet boundary) is the primary attack surface.

---

### Key Network Components

#### 1. User Workstations (Endpoints)
**What:** Employee PCs and laptops — daily work devices.
**Attack vector:** Phishing emails, malicious downloads.

| Security concern | Monitoring focus |
|-----------------|-----------------|
| Most common entry point for attackers | Endpoint logs → malicious processes |
| Less monitored than servers | Network logs → C2 connections |
| Foothold for lateral movement | EDR alerts, process creation events |

---

#### 2. File & Database Servers
**What:** Store the organization's most valuable data — documents, customer records, HR, financial data.

| Attacker goal | Detection |
|---------------|-----------|
| Ransomware → encrypt file servers | Unusual file modification volume |
| Data exfiltration → steal DB contents | Large outbound transfers |
| Unauthorized DB queries | Database audit logs |

---

#### 3. Application Servers (Web, Email, VPN)
**What:** Externally-facing services employees and customers rely on.

| Type | Security risk |
|------|--------------|
| **Web servers** | SQLi, XSS, RCE exploits |
| **Email servers** | Phishing delivery, credential theft |
| **VPN gateways** | Brute-force, stolen credentials → internal access |

**Monitor for:**
- Exploit attempts (SQLi, directory traversal)
- Brute-force login attempts
- Suspicious external IPs on sensitive apps

---

#### 4. Active Directory (AD) / Authentication Servers
**What:** Identity backbone — manages all users, groups, computers, and access rights.

**Why attackers love AD:**
```
Compromise one domain admin account
    → Control entire enterprise
    → Access all systems, data, and services
```

**Monitor for:**
- Multiple failed logins (password spraying)
- Unusual logins from external IPs or odd hours
- Accounts accessing systems they normally don't

---

#### 5. Routers & Switches (Network Infrastructure)
**What:** Routers connect networks (LAN ↔ Internet); switches connect internal devices.

**If compromised, attackers can:**
- Intercept and manipulate traffic (MITM)
- Create backdoors by rerouting traffic
- Open hidden channels to Internet

---

#### 6. Firewalls / Perimeter Devices
**What:** Primary security gateway between trusted internal network and untrusted Internet.

**Functions:**
- Inspects and filters inbound/outbound packets
- Blocks unauthorized access to internal services (DB, RDP)
- Deep packet inspection, IPS, malware detection

**Logs are often FIRST indicators of:**
```
Port scans → attacker reconnaissance
Brute-force → credential attacks
Exploit attempts → active attack in progress
```

---

### Component Security Priority Matrix

| Component | Attack Target? | Monitoring Priority |
|-----------|---------------|-------------------|
| Endpoints | ✓ (entry point) | High — EDR + network |
| File/DB Servers | ✓ (data) | Critical |
| Web/Email/VPN | ✓ (external facing) | Critical |
| Active Directory | ✓ (identity/privilege) | Critical |
| Routers/Switches | Occasionally | Medium |
| Firewalls | Rarely | High (log analysis) |

---

### Attack Path — Typical Enterprise Breach

```
Phishing → endpoint compromise
    ↓
C2 established → network logs show unusual traffic
    ↓
Lateral movement → AD auth logs show account anomalies
    ↓
Privilege escalation → AD domain admin compromised
    ↓
Data exfiltration → file/DB server + firewall logs show large outbound transfers
```

> Knowing each component's role = knowing where to look when something goes wrong.
