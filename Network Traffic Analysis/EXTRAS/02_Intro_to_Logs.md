## Log Analysis — Fundamentals

### What Are Logs?
Records of events within a system — the digital equivalent of a tree's growth rings.
Every interaction leaves a digital footprint: logins, file access, errors, network connections, config changes.

---

### Standard Log Entry Fields

| Field | Example |
|-------|---------|
| **Timestamp** | 2023-09-08 22:10:43 |
| **Source** | System/Application name |
| **Event type** | Authentication, Error, Access, etc. |
| **Additional details** | User, IP address, action performed |

---

### The True Power of Logs — Contextual Correlation

> A single log entry = insignificant.
> Aggregated + cross-referenced logs = powerful investigation tool.

**Logs answer the 6 key investigation questions:**

| Question | What it reveals |
|----------|----------------|
| **What happened?** | Nature of the event/incident |
| **When did it happen?** | Timestamp + timeline reconstruction |
| **Where did it happen?** | System, IP, network segment |
| **Who is responsible?** | User, device, IP, User-Agent |
| **Were they successful?** | Success/failure indicators |
| **What was the result?** | Impact, data accessed, actions taken |

---

### Real-World Example — GitLab Breach

| Question | Answer |
|----------|--------|
| What? | Adversary accessed SwiftSpend Financial's GitLab instance |
| When? | 22:10, Wednesday, September 8th, 2023 |
| Where? | IP 10.10.133.168 — VPN Users segment (10.10.133.0/24) |
| Who? | Device with User-Agent: `Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Firefox/115.0` |
| Successful? | Yes — API key publicly exposed; web proxy confirms access maintained via web shell |
| Result? | Remote code execution achieved + post-exploitation activities performed |

---

### Why Log Analysis Matters

```
Single log → limited context
Multiple logs correlated → full attack picture

Without logs:
→ Can't prove what happened
→ Can't identify attacker
→ Can't determine blast radius
→ Can't build timeline

With logs:
→ Complete forensic reconstruction
→ Attribution evidence
→ Detection of ongoing attacks
→ Compliance and legal evidence
```

---

### Log Analysis Challenges
- Volume: Continuous, fast-paced digital interactions = exponentially growing log files
- Manual review: Impractical at scale
- Solution: Log analysis tools + SIEM for automated correlation and alerting

---

### Key Takeaway
> Logs are not just for troubleshooting — they are your forensic evidence trail.
> The more complete your logging, the better your ability to detect, investigate, and respond.
> Missing logs = blind spots attackers exploit to operate undetected.

---

## Log Types, Formats & Standards

### Common Log Types

| Log Type | Contains |
|----------|---------|
| **Application** | App status, errors, warnings, events |
| **Audit** | Operational procedures — critical for compliance |
| **Security** | Logins, permission changes, firewall activity |
| **Server** | System events, errors, access logs |
| **System** | Kernel activity, boot sequences, hardware status |
| **Network** | Traffic, connections, network events |
| **Database** | Queries, updates, DB activities |
| **Web Server** | HTTP requests, URLs, response codes |

---

### Log Format Categories

#### Semi-structured
Contains both structured and unstructured data — predictable components with free-form text.

**Syslog:**
```
May 31 12:34:56 WEBSRV-02 CRON[2342593]: (root) CMD ([...])
```

**Windows Event Log (EVTX):**
```
TimeCreated: 31/05/2023 17:18:24  Id: 16384  Message: Successfully scheduled...
```

---

#### Structured
Strict standardized format — easy to parse and analyze.

**CSV:**
```
"time","user","action","status","ip","uri"
"2023-05-31T12:34:56Z","adversary","GET",200,"34.253.159.159","http://..."
```

**JSON:**
```json
{"time": "2023-05-31T12:34:56Z", "user": "adversary", "action": "GET", "status": 200}
```

**W3C ELF (IIS web server):**
```
#Fields: date time c-ip c-username s-ip s-port cs-method cs-uri-stem sc-status
31-May-2023 13:55:36 34.253.159.159 adversary 34.253.127.157 80 GET /explore 200
```

**XML:**
```xml
<log><time>2023-05-31T12:34:56Z</time><user>adversary</user><status>200</status></log>
```

---

#### Unstructured
Free-form text — rich context but harder to parse systematically.

**NCSA CLF (Apache default):**
```
34.253.159.159 - adversary [31/May/2023:13:55:36 +0000] "GET /explore HTTP/1.1" 200 4886
```

**NCSA Combined (Nginx default) — adds referrer + User-Agent:**
```
34.253.159.159 - adversary [31/May/2023:13:55:36 +0000] "GET /explore HTTP/1.1" 200 4886 "http://..." "Mozilla/5.0..."
```

---

### Format Summary

| Format | Type | Used by |
|--------|------|---------|
| Syslog | Semi-structured | Linux/network devices |
| Windows EVTX | Semi-structured | Windows systems |
| CSV/TSV | Structured | Various apps |
| JSON | Structured | Modern apps, APIs |
| W3C ELF | Structured | IIS web server |
| XML | Structured | Various apps |
| NCSA CLF | Unstructured | Apache (default) |
| NCSA Combined | Unstructured | Nginx (default) |

---

### Log Standards

| Standard | Purpose |
|----------|---------|
| **CEE (MITRE)** | Common structure for generating, transmitting, storing logs |
| **OWASP Logging Cheat Sheet** | Security logging guidance for developers |
| **Syslog Protocol** | Standard for message logging and transmission |
| **NIST SP 800-92** | Computer security log management guidelines |
| **Azure Monitor Logs** | Microsoft Azure logging guidelines |
| **Google Cloud Logging** | GCP logging guidelines |
| **Oracle Cloud Logging** | OCI logging guidelines |

---

### Key Takeaway
> Understanding log formats is essential for parsing and analysis.
> Structured formats (JSON, CSV) are easiest to automate.
> Unstructured formats (CLF, Combined) require regex or parsing tools.
> Custom formats require specialized parsers — always document format specs.

---

## Log Collection, Management & Centralisation

### Why NTP Matters
Logs must have accurate timestamps to form a reliable chronological timeline.
Without time sync → logs from different systems can't be correlated accurately.

```bash
# Sync time with NTP (Linux)
ntpdate pool.ntp.org

# Verify time
date
```

---

### Log Collection Process

```
1. Identify Sources
   → Servers, databases, applications, network devices

2. Choose a Log Collector
   → rsyslog, Filebeat, Winlogbeat, Fluentd, etc.

3. Configure Collection Parameters
   → Enable NTP sync
   → Set which events to log + at what intervals
   → Prioritize by importance

4. Test Collection
   → Verify logs are arriving from all sources
```

---

### Log Management Best Practices

| Step | Action |
|------|--------|
| **Storage** | Secure storage with defined retention period |
| **Organisation** | Classify by source, type, severity |
| **Backup** | Regular backups to prevent data loss |
| **Review** | Periodic checks that logs are stored correctly |

> Hybrid approach: keep all logs + selectively trim low-value entries.

---

### Log Centralisation

**Why centralise:**
- Single location for all logs
- Real-time monitoring and alerting
- Faster incident response
- Correlation across multiple sources

**Process:**
```
1. Choose centralised system (Elastic Stack, Splunk, Graylog)
2. Integrate all log sources
3. Set up real-time monitoring + alerts
4. Integrate with incident management tools
```

---

### Practical — rsyslog SSH Log Collection

**Goal:** Log all sshd messages to `/var/log/websrv-02/rsyslog_sshd.log`

```bash
# 1. Check rsyslog is running
sudo systemctl status rsyslog

# 2. Create config file
sudo nano /etc/rsyslog.d/98-websrv-02-sshd.conf

# 3. Add configuration
$FileCreateMode 0644
:programname, isequal, "sshd" /var/log/websrv-02/rsyslog_sshd.log

# 4. Save and restart rsyslog
sudo systemctl restart rsyslog

# 5. Verify — trigger SSH and check log
ssh localhost
cat /var/log/websrv-02/rsyslog_sshd.log
```

---

### Summary — Collection → Management → Centralisation

```
Multiple log sources (servers, apps, network devices)
    ↓ NTP synced timestamps
Log Collector (rsyslog, Filebeat, etc.)
    ↓ Collect + forward
Centralised System (Splunk, Elastic, Graylog)
    ↓ Store + index + correlate
Real-time monitoring + alerting
    ↓ Alert fired
SOC analyst investigates
```

> Centralised logging = the foundation of effective SOC operations.
> Without it, analysts are investigating blind — one system at a time.

---

## Log Storage, Retention & Deletion

### Storage Location Factors

| Factor | Consideration |
|--------|--------------|
| **Security requirements** | Compliance with org/regulatory protocols |
| **Accessibility needs** | Who needs access and how quickly |
| **Storage capacity** | Volume of logs generated |
| **Cost** | Cloud vs local budget |
| **Compliance** | Industry regulations (HIPAA, PCI-DSS, GDPR) |
| **Retention policies** | How long to keep + retrieval ease |
| **Disaster recovery** | Availability even during system failure |

---

### Log Retention Tiers

| Tier | Timeframe | Access Speed | Use |
|------|-----------|-------------|-----|
| **Hot** | 0–6 months | Near real-time | Active investigations, daily SOC work |
| **Warm** | 6 months–2 years | Accessible (slower) | Data lake — less frequent queries |
| **Cold** | 2–5 years | Slow (archived/compressed) | Retroactive analysis, compliance audits |

> Managing cost = choosing the right tier for the right data.

---

### Log Deletion Guidelines
- Always backup before deletion — especially critical logs
- Define a formal deletion policy
- Ensures compliance with GDPR and other privacy regulations
- Keeps storage costs manageable
- Maintains analysis efficiency

---

### Best Practices Summary

```
✓ Define storage + retention + deletion policy (business + legal requirements)
✓ Review and update policies regularly
✓ Automate processes — reduce human error
✓ Encrypt sensitive logs
✓ Regular backups before any deletion
```

---

### Practical — logrotate Configuration

**Tool:** `logrotate` — automates log rotation, compression, and removal.

```bash
# Create config
sudo nano /etc/logrotate.d/98-websrv-02_sshd.conf
```

**Config file content:**
```bash
/var/log/websrv-02/rsyslog_sshd.log {
    daily                    # Rotate daily
    rotate 30                # Keep 30 rotated files
    compress                 # Compress rotated files (.gz)
    lastaction
        # Generate hash file for integrity verification
        DATE=$(date +"%Y-%m-%d")
        echo "$(date)" >> "/var/log/websrv-02/hashes_"$DATE"_rsyslog_sshd.txt"
        for i in $(seq 1 30); do
            FILE="/var/log/websrv-02/rsyslog_sshd.log.$i.gz"
            if [ -f "$FILE" ]; then
                HASH=$(/usr/bin/sha256sum "$FILE" | awk '{ print $1 }')
                echo "rsyslog_sshd.log.$i.gz "$HASH"" >> "/var/log/websrv-02/hashes_"$DATE"_rsyslog_sshd.txt"
            fi
        done
        systemctl restart rsyslog
    endscript
}
```

```bash
# Manually test/force rotation
sudo logrotate -f /etc/logrotate.d/98-websrv-02_sshd.conf
```

**What the config does:**
| Setting | Effect |
|---------|--------|
| `daily` | Rotates log every day |
| `rotate 30` | Keeps 30 days of history |
| `compress` | Saves space with gzip compression |
| `lastaction` | Runs script after rotation — generates SHA256 hashes for integrity verification |
| `systemctl restart rsyslog` | Ensures rsyslog uses new log file after rotation |

---

### Why Hash Verification Matters
```
After rotation → generate SHA256 hash of each compressed log
Store hashes in separate file
Later → re-hash logs → compare → detect any tampering
Tampered log = different hash = integrity violation
```

> Log integrity = essential for forensic evidence and compliance.
> Hashing ensures logs haven't been modified after collection.

---

## Log Analysis — Process & Tools

### Log Analysis Pipeline

| Stage | What it does |
|-------|-------------|
| **Parsing** | Break raw logs into manageable components — extract fields |
| **Normalisation** | Standardize different log formats into consistent structure |
| **Sorting** | Order by time, source, severity, event type — find patterns |
| **Classification** | Categorize by severity, type, source — filter what matters |
| **Enrichment** | Add context: geo-IP, user details, threat intel, related data |
| **Correlation** | Link related events across sources — detect attack patterns |
| **Visualisation** | Charts, graphs, heat maps — make patterns visible |
| **Reporting** | Summarize for stakeholders — compliance, management, auditors |

---

### Log Analysis Tools

| Scenario | Tools |
|----------|-------|
| **Complex analysis / SIEM** | Splunk, Elastic Stack (ELK) |
| **Linux CLI (quick/IR)** | `cat` `grep` `sed` `sort` `uniq` `awk` `sha256sum` |
| **Windows CLI** | EZ-Tools, `Get-FileHash` |
| **Log viewing** | Open-source Log Viewer |

---

### Linux CLI Log Analysis Commands

```bash
# View raw log
cat /var/log/auth.log

# Search for specific IP
grep "34.253.159.159" /var/log/nginx/access.log

# Normalize nginx log + redirect to temp file
awk -F'[][]' '{print "[" $2 "]", "--- nginx/access.log ---", "\"" $0 "\""}' \
    /var/log/gitlab/nginx/access.log | sed "s/ +0000//g" > /tmp/parsed_consolidated.log

# Filter specific entries from consolidated log
grep "34.253.159.159" /tmp/parsed_consolidated.log > /tmp/filtered_consolidated.log

# Sort all entries by date/time
sort /tmp/parsed_consolidated.log > /tmp/sort_parsed_consolidated.log

# Remove duplicate entries
uniq /tmp/sort_parsed_consolidated.log > /tmp/uniq_sort_parsed_consolidated.log

# Generate hash for integrity verification
sha256sum /var/log/auth.log
```

---

### Log Analysis Techniques

| Technique | Purpose |
|-----------|---------|
| **Pattern Recognition** | Identify recurring sequences — normal vs abnormal |
| **Anomaly Detection** | Spot deviations from baseline — early threat warning |
| **Correlation Analysis** | Link events across sources — root cause analysis |
| **Timeline Analysis** | Trends over time — performance + attack reconstruction |
| **Machine Learning/AI** | Automate classification, enrichment, predictive insights |
| **Visualisation** | Graphs/charts — make complex data intuitive |
| **Statistical Analysis** | Quantitative insights — regression, hypothesis testing |

---

### Log Integrity — Acquisition Best Practice

```bash
# Always hash log files during collection
sha256sum /var/log/auth.log > auth.log.sha256

# Verify integrity later
sha256sum -c auth.log.sha256
```

> Hashing ensures logs are admissible as forensic evidence in court.
> Changed hash = tampered evidence = inadmissible.

---

### Key Takeaway
```
Logs → parse → normalize → correlate → visualize → act
                                              ↓
                                     Incident response
                                     Threat hunting
                                     Compliance reporting
                                     Performance monitoring
```

> Logging without analysis = wasted storage.
> Analysis without integrity verification = unreliable evidence.
> Both together = strong security posture.
