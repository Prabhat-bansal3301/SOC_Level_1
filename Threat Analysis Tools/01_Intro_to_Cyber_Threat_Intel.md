# Cyber Threat Intelligence (CTI) for SOC Triage

CTI gives an L1 analyst the context to decide which of hundreds of alerts is real danger, so time goes to the right issues.

## Three Questions CTI Answers

1. Who or what is behind this alert indicator?
2. What was their behaviour in the past?
3. How does my organisation respond, and what should I do right now?

- Answered early (within minutes), they buy time for the incident response (IR) team
- CTI is a front-line triage tool, not only for intel specialists

## Data vs Information vs Intelligence

| Layer | Definition | Example | L1 action |
|---|---|---|---|
| Data | Unprocessed observable | `45.155.205.3:443` | Capture the artefact |
| Information | Data plus factual annotation | IP registered to Hetzner, first seen 2023-07-14 | Record attributes |
| Intelligence | Analysed information that answers "so what" | IP belongs to the current BumbleBee C2; block immediately | Escalate or suppress |

- L1 job: **enrich** artefacts until they become intelligence, or show they never will
- Enrichment = quick lookups of public, commercial, and internal sources for origin, behaviour, and relevance

## Key Terms

| Term | Meaning | Example |
|---|---|---|
| IOC (Indicator of Compromise) | Evidence of a breach | C2 address in the logs |
| IOA (Indicator of Attack) | A malicious action is underway | PowerShell launching an unknown service |
| TTP (Tactics, Techniques, Procedures) | Adversary methods, written as MITRE ATT&CK IDs | T1055 Process Injection |

## Indicator Types and First Lookups

Recognise the indicator type first, then know where to look.

| Indicator | Example | First resources | IOA / TTP example |
|---|---|---|---|
| IPv4 / IPv6 | `45.155.205.3` | WHOIS (ASN, allocation date), VirusTotal Relations, Shodan banner scan | IOA: repeated SSH failures. TTP: T1110.003 (see corrections) |
| Domain / FQDN | `malicious-updates[.]net` | WHOIS age, RiskIQ or SecurityTrails passive DNS, urlscan.io | IOA: surge of DNS queries to a 24-hour-old domain |
| URL | `hxxp://malicious-updates[.]net/login` | URLhaus reputation, urlscan.io behaviour graph, Any.Run dynamic run (network off) | IOA: browser POST to `/gateway.php` with payload |
| File hash | `e99a18c428cb38d5…` | VirusTotal static and dynamic, Hybrid-Analysis, MalShare corpus | TTP: T1055 Process Injection into `regsvr32.exe` |
| Email address | `billing@evil-corp.com` | MXToolbox header analysis, Have I Been Pwned | IOA: SPF failure plus recent domain registration |
| Local artefact | `HKCU\Software\Run\updater.exe` | Sigma rules, EDR prevalence query, vendor knowledge base | TTP: Registry Run Keys (see corrections) |

- Defanging (`[.]`, `hxxp`) stops indicators from becoming live links in reports and tickets
- Tip: keep a bookmark folder or SIEM launcher panel that opens your lookups with the indicator pre-filled; 30 seconds saved per alert adds up to hours per month

## Feeds vs Platforms

Most SOCs don't build intelligence in-house; they ingest it from reliable sources.

| | Feed | Platform |
|---|---|---|
| What | Scheduled stream of indicators | Repository that stores indicators, tracks enrichment, maps relationships, enforces sharing permissions |
| Formats | CSV, JSON, STIX, TAXII | Examples: MISP, OpenCTI (open source) |
| Risk | Over-ingesting without curation floods analysts with false positives and erodes trust | None named |

Good practice:
- Add feeds gradually
- Confirm each fits the organisation's threat model
- Promote into the platform only after measuring actionability
- The platform becomes the **single source of truth**: query it first, so indicator histories grow in one place and don't fork

## Sources of Threat Intelligence

Intelligence is only as trustworthy as its source. Note where each indicator came from: it drives credibility and legal review if an IOC later disrupts the business.

| Source | Examples | Notes |
|---|---|---|
| Internal telemetry | SIEM logs, EDR detections, phishing-mailbox submissions | Highest immediate relevance |
| Commercial services | Premium vendor feeds, paid sandboxes, closed-source analytics | High fidelity; licensing may limit export and sharing |
| OSINT | AbuseIPDB, URLhaus, public blogs with IOCs, academic research | Cross-confirm before applying |
| Communities and ISACs | Sector-specific lists, e.g. FS-ISAC | Labelled, rich context |

## Threat Intelligence Classifications

| Type | Focus | Example |
|---|---|---|
| Strategic | High-level threat landscape, trends, and risk areas for business decisions | Annual ransomware report predicting a shift to data-wiping extortion in healthcare |
| Tactical | Adversary behaviour through TTPs | Advisory on new T1059.005 (Visual Basic) abuse in malspam |
| Operational | Campaign-specific motives and intent | Shows which critical assets (people, processes, technology) may be targeted |
| Technical | Atomic indicators and artefacts | IPs and hashes tied to an attack |

### L1 Analyst Role

| Intel type | L1 contribution |
|---|---|
| Technical | Escalate many technical IOCs |
| Tactical | Observe and document IOAs |
| Operational | Spot patterns that feed operational reporting |

---

# CTI: TLP, Intel Formats, and the Intelligence Lifecycle

Threat intel is only useful if it is shared correctly and moves through a repeatable cycle. This note covers sharing labels (TLP), the STIX format, and a six-step lifecycle worked through a database-protection scenario.

## Traffic Light Protocol (TLP)

A four-colour labelling scheme from FIRST.org that sets how widely intel may be shared.

| Label | Sharing boundary | Typical L1 behaviour |
|---|---|---|
| TLP:CLEAR | No restriction | Post to the internal wiki or platform |
| TLP:GREEN | Peer community, not public | Upload to a MISP or Slack workspace restricted to partner SOCs |
| TLP:AMBER | Organisation-wide; external only to clients with need-to-know | Keep in the company CTI platform; reference, don't copy, in tickets |
| TLP:RED | Named recipients only | Store in an encrypted note; no ticketing system without clearance |

- The TLP label must **travel with the indicator** into every platform and triage note
- Breaking a label can breach contracts and erode trust with intel partners

## Intel Formats

- Analysts meet intel in many formats, then share and update colleagues on new findings
- **STIX** (Structured Threat Information Expression): a JSON schema describing indicators, relationships, and context in machine-readable form
- Feed formats seen earlier: CSV, JSON, STIX, TAXII (TAXII is the transport for STIX)

## Scenario: TryHatMe Corp

| Item | Detail |
|---|---|
| Asset | PostgreSQL server with sensitive customer data, in a segmented subnet |
| Controls | Next-gen firewall (NGFW) in front, EDR agent on the host |
| Request | Management asks the SOC to "bring in" CTI so controls react faster |
| Owner | L1 analyst Alex builds and runs the workflow |

## The Six Steps

| # | Step | Purpose |
|---|---|---|
| 1 | Direction | Define the mission and questions |
| 2 | Collection | Gather raw intel |
| 3 | Processing | Normalise and correlate |
| 4 | Analysis | Turn information into judgement |
| 5 | Dissemination | Deliver to the right consumers |
| 6 | Feedback | Measure and refine |

## Step 1: Direction

Alex meets the CTI lead and the database administrator and turns the mandate into a requirement:

- **Primary asset:** production PostgreSQL database
- **Business risk:** GDPR fines and loss of customer trust
- **Controls:** NGFW blocks by IP and domain; EDR quarantines by hash
- **Goal:** use feed indicators to block or alert on suspicious IPs at the firewall, and detect known malicious hashes in EDR

Two measurable questions (they become the success criteria later):

| Q | Question |
|---|---|
| Q1 | Which external IPs and domains are currently used to exploit PostgreSQL or exfiltrate database records? |
| Q2 | Which malware families targeting PostgreSQL drivers or credentials are active this week, and what are their hashes? |

## Step 2: Collection

| Source | Why | Collected |
|---|---|---|
| Commercial NGFW vendor feed | Tailored to the same firewall, high fidelity | 37 IPv4 addresses flagged as database-exfil C2 in the last 24 h |
| AbuseIPDB, filtered by tag `PostgreSQL-brute-force` | Fast, community updates | 15 IPs, 4 domains |
| Internal MISP | History of past incidents | 2 SHA-256 hashes of PgSQL credential stealers |
| Vendor threat report (this week) | Strategic insight turned into technical IOCs | 1 new malware hash, 3 C2 domains |

- Each feed is exported as STIX or CSV
- A **dated copy** goes to the SOC's "raw-intel" S3 bucket, so results can be reproduced

## Step 3: Processing

Raw feeds never align, so the data is **normalised** (one standard format) and **correlated** (links between sources, plus contradictions such as "benign" in history vs "malicious" today).

Alex runs scheduled Python scripts that:
- Normalise syntax: compress IPv6, lowercase domains, strip subnet masks
- Correlate and deduplicate against the platform's existing indicators
- Tag each entry with source, date, and TLP label
- Output two action files:
  - `firewall_blocklist.csv`: indicator, action, comments
  - `edr_hash_rules.yar`: YARA file for hash blocking

**TLP collision:** one IP is TLP:AMBER in the NGFW feed and TLP:CLEAR in AbuseIPDB. The **stricter label wins**, so the merged record is AMBER, which prevents accidental disclosure if the list is shared later.

## Step 4: Analysis

Blocking everything suspected of being malicious creates false positives, so Alex checks relevance against the real environment.

| Question | Check | Result |
|---|---|---|
| Q1 (firewall IPs) | Splunk query over the last 30 days | One NGFW IP tried and failed to open TCP 5432 against the production subnet, so the indicator applies |
| Q2 (hashes) | OpenCTI reverse search, then Any.Run sandbox | Hash links to the **PgSteal** family; sandbox shows credential dumping; the organisation uses the exact ODBC driver it targets, so priority is high |

Confidence grading:

| Confidence | Source agreement | Local sightings | Action |
|---|---|---|---|
| High | Same IOC in 2 or more sources | At least 1 local attempt | Immediate block |
| Medium | Single trusted source | No local hits | Alert only |
| Low | OSINT only | No context | Monitor for 14 days |

- Result: **7 IPs and 1 hash** meet the high bar; the rest are medium and monitored

## Step 5: Dissemination

Unused intel is shelfware, so output is tailored to each consumer.

| Stakeholder | Format | Why |
|---|---|---|
| Firewall team | CSV upload plus change ticket | They own block rules; the ticket documents risk and TLP |
| Endpoint team | YARA rule set in the EDR console | To load into the policy |
| CTI platform | Indicator objects with full tags | Keeps history, supports future correlation, honours TLP |
| Management | 200-word summary in the weekly cyber-risk memo | Shows return on investment |

- Each consumer gets only the depth they need to act

## Step 6: Feedback

Two weeks later:

| KPI | Baseline | After first cycle |
|---|---|---|
| Median dwell time of PgSQL brute-force IPs | 48 h | 0 h (pre-emptive block) |
| False-positive rate on new blocks | none | 0% (none revoked) |

- Objectives met, so management approves expansion
- Next sprint adds other threat parameters, such as **DNS tunnelling IOCs** for the same asset group
- Alex updates the direction document, closes the loop, and schedules iteration two

---

# Threat Intel Standards and Frameworks

Standards and frameworks give the industry shared terminology, so threat intel can be distributed, used, and discussed consistently across teams, vendors, and auditors.

## MITRE ATT&CK

- Gives every adversary behaviour a label everyone recognises (a "Rosetta Stone" between vendors, teammates, and auditors)
- Examples: T1059.001 PowerShell, T1048.003 DNS tunnel

L1 workflow:
1. Match the alert's behaviour to a tactic and technique
2. Write the ID in the triage note: `Observed T1071.001 (web-based C2) against FINANCE-TRYHATME-00`
3. Hand off to L2 or IR, who instantly know the mitigations and threat-actor profiles that apply

## MITRE D3FEND

- ATT&CK covers how adversaries **attack**; D3FEND covers how defenders **respond**
- Each entry maps to a defensive technique, e.g. Credential Hardening

Example:
1. Proxy raises a T1048.003 DNS tunnel alert
2. Search D3FEND for the matching defence: a DNS request analysis technique
3. Its page lists practical controls: block excessively large TXT records, alert on unusual query entropy
4. Put the most feasible control in the "next actions" field: you supply a mitigation, not just a diagnosis

## Cyber Kill Chain

- Developed by Lockheed Martin
- Breaks an attack into stages, so you can tell which stage an activity belongs to

| Phase | Purpose | Examples |
|---|---|---|
| Reconnaissance | Gather information about the victim | Harvesting emails, OSINT, social media, network scans |
| Weaponisation | Build malware for the attack's needs | Exploit with a backdoor, malicious Office document |
| Delivery | Get the malware to the victim | Email, weblinks, USB |
| Exploitation | Use a vulnerability to execute code | EternalBlue, Zerologon |
| Installation | Install malware and tools for access | Password dumping, backdoors, RATs |
| Command & Control | Remotely control the system, deliver more malware, move across assets, escalate privileges | Empire, Cobalt Strike |
| Actions on Objectives | Achieve the goal: money, espionage, data theft | Encryption, ransomware, defacement |

- The kill chain was later extended with ATT&CK, leading to the **Unified Kill Chain**
- The source's phase diagram wasn't included; the table above is the text version

## CVE, CVSS, and NVD

SOC queues hold nearly as many vulnerability notices as malware alerts.

| Term | Meaning |
|---|---|
| CVE (Common Vulnerabilities and Exposures) | Catalogue number for a known vulnerability, e.g. `CVE-2023-4863` |
| CVSS (Common Vulnerability Scoring System) | 0 to 10 severity scale, with temporal and environmental modifiers |
| NVD (National Vulnerability Database) | Repository linking CVE numbers to CVSS scores, exploits, and affected products |

## Sharing and Processing Intel

Each peer that consumes and validates published indicators strengthens collective defence. Two standards support this:

| Standard | What it is |
|---|---|
| STIX | JSON schema describing threat indicators, relationships, and context (covered in the CTI lifecycle note) |
| TAXII (Trusted Automated eXchange of Indicator Information) | Secure APIs for exchanging threat intel in near real time, for detection, prevention, and mitigation |

TAXII sharing models:

| Model | How it works |
|---|---|
| Collection | Producer collects and **hosts** the intel; consumers request it |
| Channel | Central server **publishes** intel to subscribed users |

### Benefits of Sharing

- Near-real-time feeds shorten the gap between another organisation's incident and your prevention
- Contributors earn reciprocal trust as valuable intel sources

### When Not to Share

- Privacy laws, customer NDAs, or internal competitive information may forbid disclosure
- Sharing specific IOCs early can tip off adversaries that the campaign has been detected
- Ties to TLP: the label decides how far an indicator may go

