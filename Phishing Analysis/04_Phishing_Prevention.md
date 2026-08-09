## SPF — Sender Policy Framework

### What is SPF?
DNS TXT record listing IP addresses authorized to send email on behalf of a domain.
Receiving mail server checks SPF to verify sender is legitimate.

🔗 [SPF Record Syntax](https://dmarcian.com/spf-syntax-table/)
🔗 [SPF Surveyor](https://dmarcian.com/spf-survey/)

---

### SPF Verification Results

| Result | Action | Meaning |
|--------|--------|---------|
| **Pass** | Accept | Sender is authorized |
| **Neutral** | Accept | Domain makes no assertion |
| **None** | Accept | No SPF record found |
| **SoftFail** | Flag (allow but suspicious) | Sender not authorized but not hard fail |
| **PermError** | Flag | Permanent error in SPF record |
| **Fail** | Reject | Sender explicitly not authorized |
| **TempError** | Reject | Temporary DNS lookup error |

---

### SPF Record Breakdown

```
v=spf1 ip4:127.0.0.1 include:_spf.google.com -all
```

| Part | Meaning |
|------|---------|
| `v=spf1` | Start of SPF record |
| `ip4:127.0.0.1` | Specific IPv4 authorized to send |
| `include:_spf.google.com` | Authorize all IPs from this domain's SPF |
| `-all` | Reject all unauthorized senders (hard fail) |

**Common `all` mechanisms:**
| Mechanism | Result |
|-----------|--------|
| `-all` | Fail — reject unauthorized |
| `~all` | SoftFail — flag but accept |
| `?all` | Neutral — no policy |
| `+all` | Pass — allow all (not recommended) |

---

### TryHackMe SPF Example
Authorized sending domains (no direct IPs):
```
_spf.google.com
email.chargebee.com
7168674.spf05.hubspotemail.net
```
All IPs authorized by those domains = legitimate TryHackMe senders.

---

### SPF in Email Header Analysis

**SoftFail example:**
```
SPF: softfail (IP Unknown)
→ Sending IP not in authorized list
→ Email flagged as suspicious but still delivered
→ Red flag during phishing investigation
```

---

### SPF Workflow
```
Email sent
    ↓
Receiving server extracts sender domain from Return-Path
    ↓
DNS lookup → retrieves domain's SPF TXT record
    ↓
Checks if sending IP is in authorized list
    ↓
Pass → deliver | SoftFail → flag | Fail → reject
```

---

### Tools

| Tool | Link |
|------|------|
| SPF Surveyor | [dmarcian.com/spf-survey](https://dmarcian.com/spf-survey/) |
| Google Messageheader | [toolbox.googleapps.com](https://toolbox.googleapps.com/apps/messageheader/analyzeheader) |
| MXToolbox SPF Check | [mxtoolbox.com/spf](https://mxtoolbox.com/spf.aspx) |

---

## DKIM — DomainKeys Identified Mail

### What is DKIM?
Digital signature standard for email authentication.
Sending server signs email with **private key** → receiving server verifies with **public key** from DNS.

**Key advantage over SPF:** Survives email forwarding (signature travels with the email).

🔗 [What is DKIM](https://dmarcian.com/what-is-dkim/)
🔗 [DKIM Selectors](https://dmarcian.com/dkim-selectors/)
🔗 [DKIM Record Checker](https://dmarcian.com/dkim-inspector/)
🔗 [DKIM Validator](https://dmarcian.com/dkim-validator/)

---

### DKIM Workflow
```
Sender composes email
    ↓
Sending server signs email with PRIVATE key
    ↓
DKIM signature added to email header
    ↓
Email travels to recipient
    ↓
Receiving server looks up PUBLIC key from sender's DNS DKIM record
    ↓
Signature verified?
    Yes → authentic, deliver
    No  → flag or reject
```

---

### DKIM Record Format
```
v=DKIM1; k=rsa; p=<public_key>
```

| Part | Meaning |
|------|---------|
| `v=DKIM1` | DKIM version (optional) |
| `k=rsa` | Key type — RSA is standard |
| `p=` | Public key — matched against private key to verify signature |

---

### DKIM Results in Email Headers

| Result | Meaning |
|--------|---------|
| **Pass** | Signature verified — email authentic |
| **Fail** | Signature invalid — possible tampering |
| **PermError** | Permanent failure — invalid signature, missing/incorrect DNS record, forwarding modification, or misconfiguration |
| **TempError** | Temporary DNS lookup failure |
| **None** | No DKIM signature present |

---

### SPF vs DKIM

| | SPF | DKIM |
|-|-----|------|
| **What it checks** | Sending IP authorized? | Email signature valid? |
| **Location** | DNS TXT record | DNS TXT record |
| **Survives forwarding** | ✗ (IP changes) | ✓ (signature travels with email) |
| **Protects against** | Unauthorized sending servers | Email tampering/forgery |

---

### PermError — Common Causes
```
→ Invalid or malformed DKIM signature
→ Missing or incorrect DNS DKIM record
→ Forwarding server modified the email (broke the signature)
→ DKIM misconfiguration on sending server
```

> A DKIM PermError in a spam email = strong phishing/spoofing indicator.
> Legitimate senders rarely have DKIM misconfigurations.

---

## DMARC — Domain-Based Message Authentication, Reporting & Conformance

### What is DMARC?
Open standard that ties SPF and DKIM together using **alignment**.
Ensures the sender's domain in the `From` header matches the domains verified by SPF and DKIM.
Tells receiving server **what to do** when SPF/DKIM checks fail.

🔗 [Getting Started with DMARC](https://dmarcian.com/getting-started-with-dmarc/)
🔗 [DMARC Record Info](https://dmarcian.com/what-is-a-dmarc-record/)
🔗 [Domain Checker Tool](https://dmarcian.com/domain-checker/)

---

### DMARC Record Format
```
v=DMARC1; p=quarantine; rua=mailto:postmaster@website.com
```

| Part | Meaning |
|------|---------|
| `v=DMARC1` | DMARC version — required |
| `p=` | Policy — what to do on DMARC failure |
| `rua=mailto:` | Optional — send aggregate reports to this email |

---

### DMARC Policies (p=)

| Policy | Action on Failure |
|--------|------------------|
| `p=none` | Do nothing — monitor only (report only mode) |
| `p=quarantine` | Move to spam/junk folder |
| `p=reject` | Reject email entirely — never delivered |

---

### How DMARC Works

```
Email received
    ↓
SPF check: sending IP authorized?
DKIM check: signature valid?
    ↓
DMARC Alignment check:
  Does From domain match SPF domain? 
  Does From domain match DKIM domain?
    ↓
Aligned + Pass → deliver
Fail → apply DMARC policy (none/quarantine/reject)
    ↓
Send report to rua address (if configured)
```

---

### SPF + DKIM + DMARC Together

| Protocol | Checks | Protects Against |
|----------|--------|-----------------|
| **SPF** | Sending IP authorized? | Unauthorized sending servers |
| **DKIM** | Email signature valid? | Email tampering/forgery |
| **DMARC** | From domain aligned with SPF+DKIM? | Domain spoofing + ties it all together |

```
SPF + DKIM pass but From domain doesn't match = DMARC FAIL
All three must align for full email authentication
```

---

### Microsoft.com Example
```
DMARC record: p=reject
→ Any email failing DMARC check = rejected immediately
→ Strongest possible policy
```

---

### Tools

| Tool | Link |
|------|------|
| Domain Checker (DMARC+SPF+DKIM) | [dmarcian.com/domain-checker](https://dmarcian.com/domain-checker/) |
| DMARC Record Inspector | [dmarcian.com/dmarc-inspector](https://dmarcian.com/dmarc-inspector/) |
| MXToolbox DMARC Check | [mxtoolbox.com/dmarc](https://mxtoolbox.com/dmarc.aspx) |

---

## S/MIME — Secure Email Standard

### What is S/MIME?
Standard protocol for **digitally signed and encrypted** email messages.
Based on **public key cryptography** (asymmetric encryption).

🔗 [Microsoft S/MIME Docs](https://learn.microsoft.com/en-us/exchange/security-and-compliance/smime-exo/smime-exo)

---

### Two Core Features

#### Digital Signature
Sender signs with **private key** → recipient verifies with sender's **public key**.

| Security Property | What it provides |
|------------------|-----------------|
| **Authentication** | Confirms sender's identity via digital certificate |
| **Non-repudiation** | Sender cannot deny sending the message |
| **Data Integrity** | Detects any changes made after signing |

#### Encryption
Sender encrypts with **recipient's public key** → only recipient decrypts with **their private key**.

| Security Property | What it provides |
|------------------|-----------------|
| **Confidentiality** | Content readable only by intended recipient |

---

### Key Concept
```
Private key → never shared → used to SIGN (outgoing) and DECRYPT (incoming)
Public key  → shared openly → used to VERIFY signatures and ENCRYPT messages
```

---

### S/MIME Workflow — Bob to Mary

```
Bob wants to securely email Mary:

SIGNING (Integrity + Auth):
1. Bob creates digital certificate
2. Bob signs email with his PRIVATE key
3. Bob shares his PUBLIC key with Mary
4. Mary verifies email using Bob's PUBLIC key ✓

ENCRYPTION (Confidentiality):
5. Bob gets Mary's PUBLIC key
6. Bob encrypts email with Mary's PUBLIC key
7. Mary decrypts email with her PRIVATE key ✓

REPLY:
8. Mary repeats same process in reverse
9. Both now have each other's certificates for future use
```

---

### S/MIME vs SPF/DKIM/DMARC

| | SPF/DKIM/DMARC | S/MIME |
|-|----------------|--------|
| **Purpose** | Verify sending domain/server | Verify individual sender + encrypt content |
| **Where** | Server-level DNS records | Certificate on sender's device |
| **Encryption** | No | Yes |
| **Non-repudiation** | No | Yes |
| **End-to-end** | No | Yes |

---

### Phishing Relevance
> S/MIME signed emails are much harder to spoof. If a suspicious email claims to be from someone who uses S/MIME but has no digital signature → strong phishing indicator.
> A valid S/MIME signature = high confidence the sender is who they claim to be.

---
## Email Security Defenses

### Technical Defenses (Server-Side)

| Defense | What it does | Link |
|---------|-------------|------|
| **Email Filtering** | Blocks/quarantines based on IP + domain reputation | [Spamhaus](https://www.spamhaus.org/resource-hub/ip-domain-reputation/) |
| **Secure Email Gateway (SEG)** | Scans for impersonation, spoofing, phishing techniques missed by basic filters | [Cloudflare SEG](https://www.cloudflare.com/learning/email-security/secure-email-gateway-seg/) |
| **Link Rewriting** | Replaces suspicious URLs with safe redirects — scans link before user reaches it | [MS Safe Links](https://learn.microsoft.com/en-us/defender-office-365/safe-links-about) |
| **Sandboxing** | Detonates suspicious links/attachments in isolated VM — checks for malicious behavior | [MS Safe Attachments](https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-about) |

---

### Defense Layers — How They Stack

```
Email arrives
    ↓
Email Filtering     → block known bad IPs/domains
    ↓
SEG                 → scan for spoofing/impersonation
    ↓
Link Rewriting      → replace URLs → scan before click
    ↓
Sandboxing          → detonate attachments safely
    ↓
Delivered to inbox with warning banners
    ↓
User sees warning → reports or ignores
    ↓
Phishing reporting button → SOC investigates
```

---

### User-Facing Defenses

| Defense | Purpose |
|---------|---------|
| **Trust & Warning Indicators** | Visual banners — "External Sender", "Suspicious Link", trusted org badge |
| **Phishing Reporting** | In-email button to report suspicious messages directly to SOC |
| **User Awareness Training** | Teach employees to identify phishing, social engineering, safe email practices |
| **Phishing Simulation Exercises** | Controlled fake phishing campaigns to test + reinforce training |

---

### Why Both Layers Are Needed

```
Technical defenses alone:
→ Sophisticated phishing bypasses filters
→ Zero-day links not yet in reputation databases
→ Well-crafted impersonation passes SEG

User training alone:
→ Humans make mistakes under stress/urgency
→ AI-generated phishing now has no grammar errors
→ One click = full compromise

Both together = defense-in-depth for email
```

---

### SOC Analyst Relevance
> Technical defenses reduce volume — but some always get through.
> Phishing reports from users are high-value alerts.
> A user clicking "Report Phishing" = potential true positive.
> Treat every reported email as a real investigation until proven otherwise.
