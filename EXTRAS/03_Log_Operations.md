## Log Configuration & Operations

### The Core Challenge
Log analysis = finding a needle in a haystack.
Solution: Proper log configuration — log the right things, not everything.

---

### Four Log Configuration Purposes

#### 1. Security
Detect and respond to anomalies and security incidents.

**Focus areas:**
- Anomaly and threat detection
- Logging user authentication data
- Ensuring system integrity and data confidentiality

**Examples:** Failed logins, privilege escalations, unauthorized access attempts

---

#### 2. Operational
Detect system errors, improve performance and reliability.

**Focus areas:**
- Proactive reports and notifications for system/component status
- Troubleshooting
- Capacity planning
- Service billing

**Examples:** CPU spikes, service failures, disk usage alerts

---

#### 3. Legal
Stay compliant with regulations and standards.

**Focus areas:**
- Alignment with: ISO 27001, COBIT, GDPR, PCI DSS, HIPAA, FISMA
- Audit trails
- Data handling compliance

**PCI DSS Logging Compliance Example:**
```
✓ Active central log management system
✓ Adequate log configuration
✓ 12-month log retention
✓ Last 3 months always searchable
✓ System security checks
✓ Annual audit checks
```

---

#### 4. Debug
Discover bugs and fault conditions during development/testing.

**Focus areas:**
- Increased visibility for debugging
- Enhancing efficiency
- Speeding up development

> Usually NOT enabled in production — for dev/test environments only.

---

### Configuration Purpose Comparison

| Purpose | Primary Goal | Audience |
|---------|-------------|---------|
| **Security** | Detect threats + anomalies | SOC, Security team |
| **Operational** | System health + performance | SysAdmins, DevOps |
| **Legal** | Compliance + audit trail | Legal, Compliance, Auditors |
| **Debug** | Find bugs + faults | Developers, QA |

---

### Key Principle
> Logging everything = noise + wasted storage + harder analysis.
> Logging nothing = blind spots + compliance violations.
> Right configuration = log what matters for your specific purpose.

> Ask before configuring:
> "What am I trying to detect or prove with these logs?"

---

## Log Configuration Planning

### Starting Point — Key Planning Questions

#### Scope & Purpose
```
→ What will you log?
→ What assets are in scope?
→ What is the logging purpose? (Security / Operational / Legal / Debug)
→ Any additional requirements for that purpose?
```

#### Detail Level
```
→ How much will you log? (verbosity/detail level)
→ How much do you NEED to log? (minimum required for purpose)
```

#### Collection
```
→ How will you collect logs? (rsyslog, Filebeat, agents, etc.)
```

#### Storage
```
→ Where will logs be stored? (local, SIEM, cloud)
→ Is there a standard/law requiring specific storage? (GDPR, PCI DSS, HIPAA)
→ What is the retention period?
```

#### Protection
```
→ How will logs be protected from tampering?
→ Encryption? Access controls? Hashing for integrity?
```

#### Analysis
```
→ How will collected logs be analyzed?
→ Manual? SIEM? Automated rules?
→ Who is responsible for review?
```

#### Resources & Budget
```
→ Do you have enough people to manage logging?
→ Do you have the budget to plan, implement and maintain?
```

---

### Planning Process Flow

```
Define objective + scope
    ↓
Brainstorm with team (answer planning questions)
    ↓
Create detailed plan
    ↓
Choose tools and technologies
    ↓
Establish collection + storage processes
    ↓
Establish monitoring + alerting
    ↓
Establish review/analysis processes
    ↓
Implement + test
    ↓
Maintain + review regularly
```

---

### Key Reminder
> Every log implementation is unique — no one-size-fits-all solution.
> These questions are a starting point, not an exhaustive checklist.
> Expand the question list based on answers received.
> The goal: log what you need, protect it, and be able to use it when it matters.

---

## Log Configuration Dilemma — Requirements vs Aspirations

### The Core Dilemma
Finding balance between:
```
Requirements (must have) ↔ Aspirations (want to have)
         ↕
    Resources available
         ↕
    Budget constraints
```

Stakeholders involved: System admins, legal advisors, financial advisors, managers.

---

### Main Meeting Objective
> Meet specific operational and security requirements (non-negotiable)
> WHILE considering feasibility of additional capability improvements.

---

### Requirements vs Aspirations

| Base Requirements (Reactive) | Aspirations for Better Insights (Proactive) |
|------------------------------|---------------------------------------------|
| What happened? | Is it possible to have more data? |
| When did it happen? (with time data) | More details on the event |
| Where did it happen? (network, system, path) | How sure can I be this is true? |
| Who/what caused it? | What is affected? |
| From which log source? | What will happen next? |
| | Is there anything else requiring attention? |
| | What should I do about the incident? |

---

### Two Distinct Mindsets

| | Base Requirements | Aspirations |
|-|------------------|------------|
| **Mindset** | Incident detection | Threat hunting |
| **Approach** | Reactive | Proactive |
| **Resources needed** | Standard | Higher |
| **Effective against** | Known threats | Advanced + sophisticated threats |
| **Foundation** | ✓ Solid starting point | Builds on top of base |

---

### Recommended Approach

```
Start with BASE REQUIREMENTS (non-negotiable)
    ↓
Solid incident detection + response foundation
    ↓
Gradually ADD ASPIRATIONS where resources allow
    ↓
Move from reactive → proactive security posture
    ↓
More resilient against advanced threats
```

---

### Risk Assessment Framework

```
1. Identify non-negotiable requirements (compliance, legal, security baselines)
2. Prioritize security + compliance needs
3. Assess available resources (budget, workforce, tools)
4. Identify aspiration gaps
5. Implement aspirations incrementally where feasible
6. Review regularly — threat landscape evolves
```

---

### Key Takeaway
> Base logging = reactive — good against known threats.
> Aspirational logging = proactive — good against advanced threats.
> Neither alone is sufficient in today's threat landscape.
> The goal: meet requirements first, then incrementally build toward aspirations.
> Balance is the objective — perfect is the enemy of good.

---

## Logging Principles & Challenges

### Core Logging Principles

#### Collection
```
✓ Define logging purpose before collecting
✓ Collect only what you will need and use
✗ Do not collect irrelevant data
✗ Avoid log noise
```

#### Format
```
✓ Log at correct level and detail
✓ Implement consistent log format across all sources
✓ Ensure timestamps are accurate and NTP-synchronized
```

#### Archiving & Accessibility
```
✓ Define and implement log retention policies
✓ Store logs with important data available for analysis
✓ Create backups of log data and management systems
```

#### Monitoring & Alerting
```
✓ Create alerts for important/noteworthy events
✓ Focus on actionable alerts only
✗ Avoid alert noise
```

#### Security
```
✓ Implement access controls on logs
✓ Encrypt logs if required
✓ Use dedicated log management solution
```

#### Continuous Change
```
✓ Logging sources/types/messages constantly evolve — stay adaptable
✓ Train personnel regularly
✓ Review and update logging configurations
```

---

### Logging Challenges

| Category | Key Challenges |
|----------|---------------|
| **Data Volume & Noise** | Multiple sources, varying log volumes, insufficient or massive logs, non-essential data masking real events |
| **System Performance** | Collection slows systems, legacy/sensitive systems can't be touched, agent version sync in large networks |
| **Process & Archive** | Multiple formats, parsing is time-consuming + error-prone, balancing retention across compliance standards |
| **Security** | Protecting log data is a challenge in itself |
| **Analysis** | Correlating multi-source data is resource-intensive, real-time analysis is hard, false positives/negatives |
| **Misc** | No planning/roadmap, budget gaps, no playbooks, lack of technical skills, collecting more than analyzing, ignoring human error |

---

### Common Pitfall to Avoid
> **Focusing on log collection instead of the analysis phase.**
> Logs that are collected but never analyzed provide zero security value.
> Collection is step one — analysis is the actual goal.

---

### Principles vs Challenges — Quick Map

| Principle | Related Challenge |
|-----------|-----------------|
| Collect what you need | Data volume + noise |
| Consistent format | Multiple formats, parsing errors |
| Retention policies | Compliance regulation conflicts |
| Actionable alerts | False positives/negatives |
| Protect logs | Security of log data |
| Train personnel | Lack of technical skills |
| Adapt to change | Version sync, evolving sources |

---

### Key Takeaway
```
Plan → Collect → Format → Store → Monitor → Analyze → Improve
         ↑                                              ↓
         └──────────────── Continuous loop ─────────────┘

Adhering to principles + proactively addressing challenges
= effective, efficient, and sustainable logging operation
```

---

## Logging — Common Mistakes & Best Practices

### Critical Reminder
> "If it works, don't touch it!" = UNACCEPTABLE for logging.
> Threats evolve. Technology changes. Configurations must keep up.

---

### Real-World Example — EternalBlue (CVE-2017-0144)

```
Vulnerability:  MS17-010 (EternalBlue) — used by WannaCry
OS affected:    Windows 7 (default logging config)
Problem:        Default logging = zero/insufficient logs when exploited
Result:         No significant events in System, Security, or Application logs
                Full system compromise with no forensic trail
CVSS Score:     8.1 (High)
Lesson:         Default logging configs are NOT enough
                Must be tested and updated as threats evolve
```

---

### Common Mistakes vs Best Practices

| ❌ Mistakes (Don'ts) | ✅ Best Practices (Dos) |
|---------------------|------------------------|
| Logging sensitive information (PII, passwords) | **Exclude** sensitive information from logs |
| Creating logs manually/ad-hoc | Create a proper log configuration plan |
| Having uncollected logs (logs exist but not gathered) | Ensure all logs are collected |
| Collecting everything but not analyzing | Focus on actionable, impactful results |
| Collecting without planning/configuration | Plan before implementing |
| Systems missing required log configuration | Audit all systems for log coverage |
| Skipping scale, testing, and functionality checks | Test on scale + functionality + stability |
| Only analyzing perimeter — ignoring internal systems | Include internal systems in analysis scope |
| "Searching for what you want to find" | Investigate what you actually see |
| Forgetting: logging = planning + management + analysis | Treat it as a continuous operation |
| | Secure your logs (access control + encryption) |
| | Create meaningful alerts — not just noise |
| | Train analysts continuously |
| | Update/maintain configs and assets regularly |

---

### Self-Assessment & Improvement Actions

```
1. Learn from mistakes and failures (yours + industry)
2. Track threat dynamics for your sector
3. Conduct regular scope + resilience testing
4. Follow best practices from industry leaders
5. Use consultancy services if resources are limited
```

---

### Key Takeaway
```
Logging ≠ set and forget
Logging = continuous planning → implementation → testing → analysis → improvement

Best log config + no analysis = wasted resources
Perfect analysis + poor config = blind spots
Both together + regular maintenance = effective security posture
```

> The EternalBlue example proves: even major vendors ship insufficient default configs.
> Never assume defaults are adequate — always test and validate your logging coverage.
