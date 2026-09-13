# Network Discovery: Attackers vs. Defenders

**Core idea:** Both attackers and defenders run the same discovery/scanning activity — the SOC's real challenge isn't detecting scanning, it's telling *whose* scan it is.

## Attacker's Discovery Goals (Attack Surface Mapping)
- What assets are internet-accessible?
- What IPs, ports, OS, and services are running on them?
- What service **versions** are running, and are any exploitable?

In short: find an opening to exploit.

## Defender's Discovery Goals (Attack Surface Reduction)
- Inventory all assets — nothing undocumented/shadow IT
- Close any unnecessary open IP/port/service
- Patch exploitable vulnerabilities

In short: shrink the attack surface before an attacker can map it.

## The Detection Problem
Attackers, defenders, security researchers, and search engine crawlers (Google, Shodan, Censys) **all generate similar-looking scan traffic**. A SIEM rule that just fires on "port scan detected" will drown you in false positives from legitimate scanners.

## How SOC Teams Handle This

| Technique | How it works | Trade-off |
|---|---|---|
| Allowlisting | Known internal/benign scanners (vuln scanners, monitoring tools, known research crawlers) excluded from alerts | Simple, low noise — but if an attacker spoofs/compromises an allowlisted source, it's invisible |
| Threat Intel–gated alerting | Only alert when the source IP matches known-malicious/suspicious TI feeds | Cuts noise a lot — but misses *new* attacker infrastructure with no reputation yet (zero-day scanners) |
| TI as severity modifier + generic detection | Keep generic "scanning behavior" rules running for everyone, but use TI to bump severity/priority when the source is already known-bad | Best coverage — catches unknown scanners too, and still prioritizes known threats — but requires tuning the generic rule to avoid alert fatigue |

**Why option 3 is generally the mature approach:** option 1 is exclusion-based (bet on knowing the good guys), option 2 is match-based (bet on already knowing the bad guys) — both bet on someone being on a list. Option 3 assumes anyone *could* be malicious, keeps the generic detection running as a safety net, and uses TI only to help you triage faster, not as a gate that lets unlisted traffic through unnoticed.

## Real-World Anchor
This is the exact reasoning behind why Shodan/Censys scans usually don't trip your average IDS rule set (they're allowlisted or reputation-scored as benign researchers), while an identical-looking scan from a fresh VPS in an unusual ASN gets flagged — same behavior, different context, different treatment.

---

# External vs. Internal Scanning

**Core idea:** Same behavior (scanning), but source/destination location tells you which MITRE ATT&CK phase you're in — and that phase determines severity and response.

## External Scanning

| Attribute | Detail |
|---|---|
| Source IP | External (public internet) |
| Destination IP | Organization's public-facing asset |
| MITRE phase | Reconnaissance (TA0043) |
| Severity | Low |
| Meaning | Attacker has **no foothold yet** — probing from outside for a way in |
| Response | Block offending IP at perimeter firewall |
| Limitation | Attacker can just come back on a new/masked IP — blocking is a speed bump, not a fix |

## Internal Scanning

| Attribute | Detail |
|---|---|
| Source IP | Internal (private range) |
| Destination IP | Internal (private range) |
| MITRE phase | Discovery (TA0007) — a.k.a. "internal reconnaissance" in some frameworks |
| Severity | High |
| Meaning | Attacker **already has a foothold** and is mapping the internal network to plan lateral movement |
| Response | Not just IP block — escalate to full Incident Response, deeper investigation, root cause analysis |

**Why the severity gap is so large:** external scanning is a stranger checking if your front door is locked. Internal scanning is someone already standing in your hallway checking which rooms have valuables. The second one means containment already failed once — blocking an IP doesn't undo that, it just stops them from calling more friends in.

## Reading Real Log Data (Zeek/SIEM Export Example)

Real exported logs are messy — nested JSON inside a CSV field, nothing like the clean textbook examples. Preview with:

    head -n2 log-session-1.csv

Example row (Zeek `conn.log` exported to CSV):

    "Sep 7, 2025 @ 17:16:42.944","203.0.113.25",39120,"192.168.230.145",5922,...,"{...""id.orig_h"":""203.0.113.25"",""id.resp_h"":""192.168.230.145"",""conn_state"":""S0""...}","zeek.conn"

Key fields buried in that JSON blob:
- `id.orig_h` / `id.orig_p` — source IP/port
- `id.resp_h` / `id.resp_p` — destination IP/port
- `conn_state` — connection outcome (`S0` = connection attempt seen, no reply — classic scan behavior, since a real service would respond)

**Why this matters practically:** `203.0.113.25` (public) → `192.168.230.145` (private) = external scanning by IP range alone, no need to even read the JSON. That's the fastest triage check — before parsing anything else, just classify source/destination as public vs. private.

Since the timestamp field itself contains a comma (`"Sep 7, 2025 @ ..."`), a naive `cut -d','` will miscount columns — you have to account for the embedded comma when picking field numbers, or you'll grab the wrong column entirely.

---

# Horizontal vs. Vertical Scanning

**Core idea:** Same scanning activity, but the *axis* of the scan (one port across many hosts, vs. many ports on one host) tells you the attacker's intent.

## Horizontal Scanning

| Attribute | Detail |
|---|---|
| Pattern | Same port, scanned across **many destination IPs** |
| Goal | Find *which hosts* have a specific port/service open |
| Attacker intent | Already knows which exploit/vulnerability they want to use — just needs to find targets running that service |
| Real example | WannaCry — scanned entire networks for port 445 (SMB) open, then exploited EternalBlue (SMBv1 vuln) on every host it found |

**Why this pattern matters:** horizontal scans are usually the sign of a *known* exploit being deployed at scale — the attacker already picked their weapon (e.g., an SMB exploit) and is just hunting for anything vulnerable to it. This is the pattern behind most worm-style/self-propagating malware.

## Vertical Scanning

| Attribute | Detail |
|---|---|
| Pattern | One destination IP, scanned across **many ports** |
| Goal | Footprint a single host — find all open ports/services on it |
| Attacker intent | This specific machine is a valuable/chosen target; attacker needs full visibility into what's running on it before deciding how to attack |
| Real example | An org exposes exactly one internet-facing server — an attacker targeting that org will vertical-scan it first to map every open port/service before picking an attack vector |

**Why this pattern matters:** vertical scans signal targeted interest in *one specific asset*, not opportunistic exploitation. If you see a vertical scan against your crown-jewel server specifically, that's a much more deliberate, higher-intent signal than random horizontal noise hitting your whole subnet.

## Quick Distinction

| | Horizontal | Vertical |
|---|---|---|
| Axis | 1 port → many hosts | 1 host → many ports |
| Answers | "Who has this open?" | "What does this machine expose?" |
| Typical actor | Worm / opportunistic mass exploitation | Targeted attacker footprinting a specific asset |

---

# Scan Techniques: Ping Sweep, TCP SYN, UDP

**Core idea:** Different scan techniques probe hosts/ports differently, trading off speed, reliability, and stealth. Recognizing which technique produced a log helps you gauge attacker sophistication and detection difficulty.

## Ping Sweep

| Attribute | Detail |
|---|---|
| Method | Send ICMP echo request; online host replies with ICMP echo reply |
| Purpose | Identify which hosts are online (not port-specific) |
| Detectability | Easy — very noisy, single-packet-per-host signature |
| Limitation | Many orgs now block ICMP at the firewall — a non-response doesn't mean "offline," it might mean "ICMP blocked" |

**Why it's declining in effectiveness:** ICMP blocking has become a default hardening step, so ping sweeps increasingly give false negatives (host is up but silent). Attackers who know this skip straight to TCP/UDP scans instead.

## TCP SYN Scan

| Attribute | Detail |
|---|---|
| Method | Send SYN; if SYN-ACK comes back, host is online **and** that port is open. Scanner doesn't complete the handshake (never sends the final ACK) |
| Purpose | Identify online hosts + specific open ports |
| Detectability | **Stealthy** — blends into normal traffic since half-open connections look similar to normal connection attempts, and no full session is ever established |

**Why it's called a "half-open" scan:** by never sending the final ACK, no full TCP session is logged by many basic tools — this is literally the "stealth scan" (`-sS`) mode in Nmap, and it's the default for a reason: it's fast and quieter than a full connect scan.

## UDP Scan

| Attribute | Detail |
|---|---|
| Method | Send (often empty) UDP packet |
| Closed port | Host replies **ICMP port unreachable** |
| Open port | Either silence (ambiguous — could be open, could be a dropped packet) or, rarely, an actual UDP response |
| Detectability/Reliability | Slow and unreliable — "open" is often inferred only from *timeout with no response*, which is weak evidence |

**Why UDP scanning is painful in practice:** unlike TCP, UDP has no handshake — there's no "connection succeeded" signal in the protocol itself, so the *absence* of a reply is your best (weak) evidence of an open port. This is why full UDP scans of a large range take dramatically longer than TCP scans — the scanner has to wait out a timeout for every ambiguous port instead of getting an instant answer.

## Comparison Table

| Scan type | Detects | Speed | Stealth | Reliability |
|---|---|---|---|---|
| Ping Sweep | Host online/offline | Fast | Low (noisy) | Low (ICMP often blocked) |
| TCP SYN | Host + open ports | Fast | High | High |
| UDP | Host + open ports | Slow | Medium | Low (ambiguous results) |

## Analyst Note: Internal Scans Aren't Always Attacks
Organizations routinely run their own internal scans (vuln management, asset inventory, rogue-device detection). A SOC analyst needs to know:
- The IP(s) these authorized scans originate from
- What scan type they use
- Their schedule

...so these can be **allowlisted/excluded** from detection rules. Otherwise you're generating false-positive alerts on your own vulnerability scanner every single scheduled run — which trains analysts to ignore alerts, which is exactly how a real attacker's scan gets missed in the noise.
