## Log Analysis — Introduction

### What is Log Analysis?
Examining and interpreting log event data from various sources to:
- Monitor system metrics
- Identify security incidents
- Turn raw data into actionable objectives

---

### What is a Log?
A stream of time-sequenced messages recording events within a system, device, or application.

**Sample log entry:**
```
Jul 28 17:45:02 10.10.0.4 FW-1: %WARNING% general: Unusual network activity detected 
from IP 10.10.0.15 to IP 203.0.113.25. Source Zone: Internal, Destination Zone: External, 
Application: web-browsing, Action: Alert.
```

**Field breakdown:**

| Field | Value | Meaning |
|-------|-------|---------|
| Timestamp | `Jul 28 17:45:02` | When event occurred |
| Source | `10.10.0.4` | System that generated the log |
| Severity | `%WARNING%` | Relative importance of the event |
| Source IP | `10.10.0.15` | Internal host generating traffic |
| Destination IP | `203.0.113.25` | External internet destination |
| Source Zone | Internal | Traffic origin |
| Destination Zone | External | Traffic going to internet |
| Application | web-browsing | Traffic category |
| Action | Alert | Firewall notified — did not block |

---

### Severity Levels (Ascending)

```
Informational → Warning → Error → Critical
```

---

### Why Logs Matter

| Use Case | How Logs Help |
|----------|--------------|
| **System Troubleshooting** | Identify errors/warnings → minimize downtime |
| **Incident Response** | Detect unauthorized access, malware, breaches |
| **Threat Hunting** | Find anomalies, IOCs, unusual patterns proactively |
| **Compliance** | Demonstrate adherence to GDPR, HIPAA, PCI DSS |

---

### Log Types

| Type | Contains |
|------|---------|
| **Application** | App status, errors, warnings |
| **Audit** | User activities, system changes, history |
| **Security** | Logins, permission changes, firewall activity |
| **Server** | System events, access logs, error logs |
| **System** | Kernel, boot sequences, hardware status |
| **Network** | Connections, data transfers, network events |
| **Database** | Queries, actions, updates |
| **Web Server** | HTTP requests, URLs, IPs, response codes |

---

### Key Principle
> Analyzing log types individually is useful.
> Analyzing them **in context with each other** is essential for effective investigation and threat detection.
> Single log = limited view.
> Correlated logs = full attack picture.

---

## Log Analysis — Methodologies & Techniques

### Timeline Analysis

**Why timelines matter:**
- Chronological view of all logged events
- Reconstruct attack sequence from first compromise to impact
- Identify attacker TTPs at each stage
- Establish what happened, when, and in what order

---

### Timestamps & Time Zones

**Key challenge:** Multiple distributed systems log in different time zones and formats.

**Solution:**
- Convert all timestamps to consistent timezone (UTC recommended)
- SIEM solutions (Splunk, Elastic) handle this automatically
- Splunk stores all timestamps as **UNIX time** in `_time` field → converts to local timezone for display

---

### Super Timelines (Consolidated Timeline)

Combines logs from ALL sources into one unified chronological view.

**Sources merged:**
`System logs` `Application logs` `Network logs` `Firewall logs` `Auth logs` + more

**Tool — Plaso (Python Log2Timeline):**
- Open-source DFIR tool
- Automates timeline creation from multiple log sources
- Parses wide range of formats automatically
- 🔗 https://github.com/log2timeline/plaso

> Manual consolidated timeline = extremely time-consuming.
> Plaso = automated, comprehensive, forensically sound.

---

### Data Visualization

Tools: **Kibana** (Elastic Stack), **Splunk**

**Purpose:** Convert raw log data into visual patterns and anomalies.

**Effective visualization workflow:**
```
1. Understand data sources being collected
2. Define clear objective (what are you monitoring for?)
3. Choose appropriate visualization type
4. Set time range filter
5. Build dashboard ("single pane of glass")
```

**Example — Failed Login Monitoring:**
```
Objective:  Detect brute force / credential stuffing
Log source: Authentication server logs
Visual:     Line chart — failed logins over time
Time range: Last 7 days
Result:     Spot spikes indicating attack activity
```

---

### Log Monitoring & Alerting

**Common alert triggers:**
- Multiple failed login attempts
- Privilege escalation
- Access to sensitive files
- New admin account creation
- Off-hours logins

**Best practice:**
```
Define alert → set threshold → notify right team member
    ↓
Escalation procedures per severity level
    ↓
Right person notified at right time
```

🔗 Splunk Dashboards & Alerting: TryHackMe room `splunkdashboardsandreports`

---

### Threat Intelligence in Log Analysis

**What is threat intel?** Information attributable to malicious actors.

| Type | Example |
|------|---------|
| IP addresses | Known C2 servers, scanners |
| File hashes | Known malware samples |
| Domains | Phishing/C2 domains |

**Workflow — Threat Intel + Log Analysis:**
```bash
# Check Apache log for suspicious admin access
cat access.log

54.36.149.64 - - [25/Aug/2023:00:05:36] "GET /admin HTTP/1.1" 200 8260
```

```
1. Extract IPs/domains/hashes from logs
2. Search against threat intel feeds
3. Match = known malicious actor confirmed in your logs
4. Investigate further → incident response
```

**Threat Intel Resources:**

| Tool | Link |
|------|------|
| ThreatFox | [threatfox.abuse.ch](https://threatfox.abuse.ch/) |
| VirusTotal | [virustotal.com](https://www.virustotal.com) |
| AbuseIPDB | [abuseipdb.com](https://www.abuseipdb.com) |

---

### Summary — Log Analysis Methodology

```
Collect logs (all sources)
    ↓
Normalize timestamps → consistent timezone
    ↓
Build timeline (manual or Plaso)
    ↓
Visualize patterns (Kibana/Splunk dashboards)
    ↓
Alert on anomalies → notify right team
    ↓
Enrich with threat intelligence
    ↓
Investigate → respond → document
```

---

## Log Analysis — File Locations & Attack Patterns

### Common Log File Locations

#### Web Servers
```
Nginx:
  /var/log/nginx/access.log
  /var/log/nginx/error.log

Apache:
  /var/log/apache2/access.log
  /var/log/apache2/error.log
```

#### Databases
```
MySQL:      /var/log/mysql/error.log
PostgreSQL: /var/log/postgresql/postgresql-{version}-main.log
```

#### Web Applications
```
PHP:        /var/log/php/error.log
```

#### Operating System (Linux)
```
Syslog:     /var/log/syslog
Auth:       /var/log/auth.log
```

#### Firewalls & IDS
```
iptables:   /var/log/iptables.log
Snort:      /var/log/snort/
```

> Paths may vary by config/version — always check official docs.

---

### Abnormal User Behavior Patterns

| Indicator | What it suggests |
|-----------|-----------------|
| Multiple failed logins in short time | Brute-force attack |
| Logins outside normal hours | Unauthorized access / compromised account |
| Logins from unusual countries | Account compromise / geographic anomaly |
| Simultaneous logins from different locations | Impossible travel → account sharing or unauthorized access |
| Frequent password changes | Attacker trying to hide access / account takeover |
| Unusual User-Agent strings | Automated tools, scanners, malicious scripts |

**Tool User-Agent indicators:**
```
"Nmap Scripting Engine"  → Nmap scanner
"(Hydra)"                → Hydra brute-force tool
```

**UBA Solutions:** Splunk UBA, IBM QRadar UBA, Azure AD Identity Protection

---

### Common Attack Signatures in Logs

#### SQL Injection
Look for: `'` single quotes, `--` `#` comments, `UNION`, `WAITFOR DELAY`, `SLEEP()`

```
# Example SQLi in Apache log
10.10.61.21 - - [2023-08-02 15:27:42] "GET /products.php?q=books' UNION SELECT null,null,username,password,null FROM users-- HTTP/1.1" 200 3122
```
**Indicators:** `'` escape + `UNION SELECT` + target table name

> Often URL-encoded — decode before analysis.

---

#### Cross-Site Scripting (XSS)
Look for: `<script>` tags, event handlers (`onmouseover`, `onclick`, `onerror`)

```
# Example XSS in web log
10.10.19.31 - - [2023-08-04 16:12:11] "GET /products.php?search=<script>alert(1);</script> HTTP/1.1" 200 5153
```
**Indicators:** `<script>alert(` = classic XSS test payload

---

#### Path/Directory Traversal
Look for: `../` sequences, `/etc/passwd`, `/etc/shadow`, URL-encoded variants

```
# Example directory traversal
10.10.113.45 - - [2023-08-05 18:17:25] "GET /../../../../../etc/passwd HTTP/1.1" 200 505
```

**URL-encoded equivalents:**
| Character | URL Encoded |
|-----------|-------------|
| `.` | `%2E` |
| `/` | `%2F` |

> Attackers encode payloads to evade WAF/monitoring — always decode before analysis.

---

### Attack Pattern Quick Reference

| Attack | Key Indicators in Logs |
|--------|----------------------|
| SQLi | `'`, `UNION SELECT`, `--`, `SLEEP()`, `WAITFOR` |
| XSS | `<script>`, `alert(`, `onerror=`, `onclick=` |
| Path traversal | `../`, `../../`, `%2E%2E%2F`, `/etc/passwd` |
| Brute force | Many 401/403 responses, same IP, rapid succession |
| Scanner | Nmap/Hydra User-Agents, sequential port/path probing |
| Credential stuffing | Many failed logins across multiple usernames, same IP |

---

## Log Analysis — Automated vs Manual

### Automated Analysis

Uses tools (XPLG, SolarWinds Loggly, SIEM platforms) with AI/ML to process logs at scale.

| Advantages | Disadvantages |
|-----------|--------------|
| Saves time — handles manual work automatically | Usually commercial-only → expensive |
| AI effective at recognizing patterns + trends | AI effectiveness depends on model quality |
| Scales to massive log volumes | Risk of false positives |
| Real-time alerting | New/unseen attack patterns can be missed — AI not trained on them |

---

### Manual Analysis

Analyst directly examines logs without automation — e.g., scrolling through web server logs using Linux CLI tools.

| Advantages | Disadvantages |
|-----------|--------------|
| Cheap — no expensive tooling needed (just Linux commands) | Time-consuming — analyst does all the work |
| Thorough investigation | Events can be missed in large datasets |
| Reduces false positive risk from automated tools | May require manual log reformatting |
| Contextual analysis — analyst understands org + threat landscape | |

---

### Automated vs Manual — Comparison

| | Automated | Manual |
|-|-----------|--------|
| **Speed** | Fast | Slow |
| **Cost** | High (commercial tools) | Low (CLI tools) |
| **False positives** | Higher risk | Lower risk |
| **New threat detection** | Weak (unseen patterns) | Strong (analyst judgment) |
| **Context awareness** | Limited | Strong |
| **Scale** | Handles large volumes | Struggles at scale |

---

### Best Practice
```
Automated tools → handle volume, generate alerts, spot known patterns
    ↓
Manual analysis → investigate alerts, verify findings, provide context
    ↓
Neither alone is sufficient — use both together
```

> Automation without manual review = false positive overload + missed novel attacks.
> Manual without automation = unsustainable at enterprise scale.
> The winning approach: automate the detection, manually validate the findings.

---

## Linux CLI — Log Analysis Commands

### Quick Reference Table

| Command | Purpose |
|---------|---------|
| `cat` | Display full file content |
| `less` | Page-by-page file viewing |
| `tail` | View end of file / follow live |
| `head` | View beginning of file |
| `wc` | Count lines, words, characters |
| `cut` | Extract specific fields/columns |
| `sort` | Sort output ascending/descending |
| `uniq` | Remove duplicates / count occurrences |
| `sed` | Find and replace text patterns |
| `awk` | Conditional filtering by field value |
| `grep` | Search for patterns/keywords |

---

### Commands in Detail

#### `cat` — View full file
```bash
cat apache.log
```
Not ideal for large files — dumps everything to terminal.

#### `less` — Page-by-page viewing
```bash
less apache.log
# Navigate: arrow keys, Page Up/Down
# Search: /keyword
# Quit: q
```

#### `tail` — View end of file
```bash
tail apache.log              # last 10 lines (default)
tail -n 5 apache.log         # last 5 lines
tail -f apache.log           # follow live (real-time monitoring)
tail -f -n 5 apache.log      # last 5 lines + follow live
```

#### `wc` — Count lines/words/characters
```bash
wc apache.log
# Output: 70  1562  14305  apache.log
#          ↑     ↑      ↑
#        lines words  chars
```

#### `cut` — Extract fields
```bash
cut -d ' ' -f 1 apache.log    # extract IP addresses (field 1)
cut -d ' ' -f 7 apache.log    # extract URLs (field 7)
cut -d ' ' -f 9 apache.log    # extract HTTP status codes (field 9)
# -d = delimiter, -f = field number
```

#### `sort` — Sort output
```bash
cut -d ' ' -f 1 apache.log | sort -n     # numeric ascending
cut -d ' ' -f 1 apache.log | sort -n -r  # numeric descending
```

#### `uniq` — Remove duplicates
```bash
cut -d ' ' -f 1 apache.log | sort -n | uniq       # unique IPs only
cut -d ' ' -f 1 apache.log | sort -n | uniq -c    # unique IPs + count
# Must sort first — uniq only removes adjacent duplicates
```

#### `sed` — Find and replace
```bash
sed 's/31\/Jul\/2023/July 31, 2023/g' apache.log
# s/old/new/g = substitute all occurrences
# \ escapes the / in the pattern
# Does NOT modify original file — outputs to stdout only
# To save: add -i (edit in place) or redirect with >

# WARNING: -i overwrites original — always backup first!
```

#### `awk` — Conditional field filtering
```bash
awk '$9 >= 400' apache.log    # show entries where field 9 (status code) >= 400
# $9 = 9th space-separated field
# Returns all HTTP error entries (400, 404, 500, etc.)
```

#### `grep` — Pattern/keyword search
```bash
grep "admin" apache.log           # search for keyword
grep -c "admin" apache.log        # count matching lines
grep -n "admin" apache.log        # show line numbers
grep -v "/index.php" apache.log   # invert — exclude matching lines

# Combine filters
grep -v "/index.php" apache.log | grep "203.64.78.90"
# → exclude index.php AND show only specific IP
```

---

### Common Investigation Pipelines

```bash
# Top 10 IPs by request count
cut -d ' ' -f 1 apache.log | sort | uniq -c | sort -rn | head -10

# All HTTP errors (400+)
awk '$9 >= 400' apache.log

# Unique URLs accessed
cut -d ' ' -f 7 apache.log | sort | uniq

# Count requests per status code
cut -d ' ' -f 9 apache.log | sort | uniq -c | sort -rn

# Search for specific attack patterns
grep -n "UNION SELECT" apache.log
grep -n "../" apache.log
grep -n "<script>" apache.log

# Real-time monitoring for errors
tail -f apache.log | grep "404"

# Count total log entries
wc -l apache.log
```

---

## Regex for Log Analysis

### Using Regex with grep

Add `-E` flag to enable regex pattern matching:

```bash
# Match blog posts with ID 10-19
grep -E 'post=1[0-9]' apache-ex2.log

# Match any IPv4 address
grep -E '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' apache.log

# Match HTTP errors (4xx or 5xx)
grep -E '" [45][0-9]{2} ' apache.log

# Match specific user agents (scanners)
grep -E '(Nmap|Hydra|sqlmap|nikto)' apache.log

# Match SQL injection patterns
grep -E "(UNION|SELECT|DROP|INSERT|UPDATE|'|--)" apache.log

# Match XSS patterns
grep -E '(<script|onerror=|onclick=|alert\()' apache.log

# Match directory traversal
grep -E '(\.\./|%2e%2e%2f)' apache.log
```

---

### Building Regex Patterns for Log Parsing

**Sample log entry:**
```
126.47.40.189 - - [28/Jul/2023:15:30:45 +0000] "GET /admin.php HTTP/1.1" 200 1275 "" "Mozilla/5.0..."
```

**Fields to extract:**

| Field | Regex Pattern | Explanation |
|-------|--------------|-------------|
| **IP Address** | `\b([0-9]{1,3}\.){3}[0-9]{1,3}\b` | 4 octets separated by dots |
| **Timestamp** | `\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})` | Date/time in brackets |
| **HTTP Method** | `"(GET\|POST\|PUT\|DELETE)` | HTTP verb in quotes |
| **URL** | `"(?:GET\|POST\|PUT) (\S+)` | Path after HTTP method |
| **Status Code** | `" ([0-9]{3}) ` | 3-digit code after closing quote |
| **User-Agent** | `"([^"]+)"$` | Last quoted string |

---

### IP Address Regex — Breakdown

```
\b([0-9]{1,3}\.){3}[0-9]{1,3}\b
```

| Part | Meaning |
|------|---------|
| `\b` | Word boundary — match complete IP, not partial |
| `[0-9]{1,3}` | 1-3 digits (one octet) |
| `\.` | Literal dot (escaped) |
| `{3}` | Repeat octet+dot group 3 times |
| `[0-9]{1,3}` | Final octet (no trailing dot) |
| `\b` | Word boundary at end |

---

### Logstash + Grok — Custom Field Extraction

Grok syntax: `%{SYNTAX:SEMANTIC}` or custom regex with named capture groups.

**logstash.conf:**
```yaml
input {
  ...
}

filter {
  grok {
    match => {
      "message" => "(?<ipv4_address>\b([0-9]{1,3}\.){3}[0-9]{1,3}\b)"
    }
  }
}

output {
  ...
}
```

**What this does:**
- Matches incoming log `message` field
- Extracts IPv4 address using regex
- Stores extracted value in custom field: `ipv4_address`
- Field is then searchable and visualizable in Kibana/Elasticsearch

---

### Useful Tools

| Tool | Link | Use |
|------|------|-----|
| RegExr | [regexr.com](https://regexr.com/) | Build + test regex patterns |
| Grok Debugger | [grokdebugger.com](https://grokdebugger.com/) | Test Grok patterns |
| Elastic Grok Docs | [elastic.co/grok](https://www.elastic.co/guide/en/logstash/current/plugins-filters-grok.html) | Official reference |

---

### Common Security Regex Patterns

```regex
# IPv4 address
\b([0-9]{1,3}\.){3}[0-9]{1,3}\b

# IPv6 address
([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}

# Email address
[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}

# URL
https?://[^\s"']+

# MD5 hash
\b[a-fA-F0-9]{32}\b

# SHA256 hash
\b[a-fA-F0-9]{64}\b

# HTTP status codes (errors only)
" [45][0-9]{2} 

# SQL injection indicators
('|--|UNION|SELECT|DROP|SLEEP\(|WAITFOR)

# Base64 encoded string
[A-Za-z0-9+/]{20,}={0,2}
```
