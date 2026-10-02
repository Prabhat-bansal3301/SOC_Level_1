# Denial-of-Service (DoS) & DDoS — Application Layer

**Core idea:** DoS attacks aim to make a service unavailable, not to steal data. This note focuses on Layer 7 (application layer) — where websites and web apps themselves get targeted, not just the network pipe.

## DoS — Single Source

- Success = service stops functioning as intended, regardless of attack scale
- Doesn't require brute traffic volume — a single malformed or oversized request can crash/hang an app if input handling is weak

**Example:** an e-commerce search form that queries a database without proper validation — malformed input can hang/crash the app, or the same form flooded with requests (or one massive request) can take the site down.

## DDoS — Distributed

- Basic DoS is capped by one machine's CPU/memory/bandwidth/network
- DDoS scales past that using a **botnet** — compromised computers, IoT devices, servers under attacker control
- Bots flood the target simultaneously on command, far exceeding what one machine could generate

**Example:** a popular site built for steady daily traffic gets swarmed by a botnet generating millions of requests in a short window — resources exhausted, site goes down.

## Types of DoS/DDoS Attacks

| Type | Description |
|---|---|
| Slowloris | Many partial HTTP requests, tying up server resources without completing them |
| HTTP Flood | Large volume of HTTP requests overwhelming the server |
| Cache Bypass | Bypasses CDN edge caching, forces the origin server to handle every request directly |
| Oversized Query | Forces the server to process large, resource-intensive requests |
| Login/Form Abuse | Overloads authentication logic via login attempts or password resets |
| Faulty Input Validation Abuse | Exploits poorly handled input to hang/crash the app |

- All of these can run as DoS (single attacker) or DDoS (botnet-distributed) — the technique is the same, only the scale differs
- Connects directly to the earlier WAF note: rate-limiting rules (e.g. "5 login attempts/min per IP") exist specifically to blunt Login/Form Abuse and HTTP Flood patterns

---

# DoS/DDoS Attack Motives

**Core idea:** Not all DoS/DDoS attacks share the same goal — the motive shapes what the attack actually looks like (duration, target choice, timing) and how a SOC should prioritize response.

## Possible Motives

| Motive | Description | Example |
|---|---|---|
| [Financial Loss](https://en.wikipedia.org/wiki/Denial-of-service_attack) | Disrupt sales/revenue | Flooding an e-commerce site during holiday sales |
| Extortion | Demand payment to stop an ongoing attack | Ransom DDoS against a bank |
| Hacktivism | Protest-driven disruption | Attacking government sites during elections |
| Distraction | Pull defender attention away from a second attack | DDoS launched while breaching other infrastructure |
| Competition | Disrupt a rival, drive up their costs | Competitor DDoS during a product launch |
| Denial of Wallet | Force victim to rack up cloud usage costs | Repeated S3 access generating per-request charges |
| Reputational Damage | Erode customer trust | Game servers crashing on launch day |

- List isn't exhaustive — motives can combine, or be something else entirely

## Real-World Examples

**BBC (New Year's Eve, 2015)**
- DDoS took the site offline for several hours — timeouts and internal errors for readers
- Claimed by New World Hacking, stated motive: simply testing their own capability

**Microsoft (2023)**
- Large-scale Layer 7 DDoS hit Azure, OneDrive, and Outlook
- Claimed by hacktivist group Anonymous Sudan
- Techniques used: HTTP flooding and Slowloris (both covered in the previous note) — real-world confirmation these aren't just theoretical attack types

## Why Motive Matters for a SOC

- Distraction-motivated DDoS means: don't just fight the flood, check what else is happening on the network at the same time
- Extortion-motivated DDoS often comes with direct communication — worth preserving as evidence
- Hacktivism/reputational attacks often target public-facing, highly visible services first — prioritize monitoring there during high-risk periods (elections, product launches, sales events)

---

# Detecting DoS/DDoS in Web Server Logs

**Core idea:** DoS attacks either flood a target with volume or abuse expensive logic with crafted requests. Logs reveal both — the trick is layering multiple weak signals into one picture, since no single indicator confirms an attack alone.

## Key Indicators

| Indicator | Example | Why it matters |
|---|---|---|
| High request rate | `10.10.10.100 → 1000 GET /login` | Expensive endpoints like login overwhelm auth/DB logic fast |
| Odd User-Agents | `curl/7.6.88` repeated on `/index` | Real browsers rarely show tool-based UAs at volume |
| Geographic anomalies | IPs scattered worldwide | Legit traffic usually clusters by region; global spread suggests a botnet |
| Burst timestamps | 50 requests in 1 second to `/search` | Unnatural density = automation, not human browsing |
| Server errors (5xx) | Spike in `503 Service Unavailable` | Resources maxed out, service struggling |
| Logic abuse | `GET /products?limit=999999` | Crafted request forces expensive processing on a single call |

- Analysts should look for **layered** signals together, not one indicator in isolation
- Botnet traffic may vary User-Agents deliberately to look more legitimate — don't rely on UA consistency alone

## Commonly Targeted Endpoints

| Endpoint | Why it's expensive |
|---|---|
| `/login` | Authentication processing |
| `/search` | Complex database queries |
| `/api` | Critical for dynamic content |
| `/register`, `/signup` | Database writes + validation |
| `/contact`, `/feedback` | DB entries, can trigger emails |
| `/cart`, `/checkout` | Session management, inventory checks, payment processing |

- Attackers target cost-per-request, not popularity — a cheap static page is a poor DoS target even if high-traffic

## Reading a Sample Attack in Logs

| Phase | What the log shows |
|---|---|
| Normal traffic | Occasional requests, expected responses, spaced seconds apart |
| Attack begins | One IP (e.g. `203.0.113.55`) starts repeated GETs to `/login.php` |
| Service degraded | Other users' requests start returning `503` |

- Real incidents produce hundreds/thousands of requests — this sample is heavily condensed for teaching purposes
- The pivot pattern is the same as earlier notes: find the one IP breaking the baseline, then trace its full request history

## Log Limitations (Carried Over from Earlier Notes)
- Access logs confirm the request happened and its method/endpoint/status, but not payload body content
- For logic-abuse attacks using query strings (like `?limit=999999`), the query is visible in the log — but a POST-body-based resource exhaustion attempt would not be

---

# Detecting DoS/DDoS with SIEM (Splunk)

**Core idea:** SIEM platforms replace manual log-scrolling with filterable, sortable queries across combined log sources — turning "scan thousands of lines by eye" into "filter by IP/UA/status and look at the shape of a graph."

## Why SIEM Helps Here

- Combines multiple log sources into one searchable place
- Filter/sort by IP address, User-Agent, response code
- Pattern recognition becomes visual instead of manual

## Example: Timechart Over 10 Minutes

| Phase | Pattern |
|---|---|
| Normal traffic | A few requests to various pages per minute |
| DoS attack | 1,000 requests to `/login.php` within a single one-minute window |

- A timechart makes this spike immediately visible — same principle as the earlier `timechart span=30m` note, just applied specifically to DoS detection
- The sudden single-endpoint spike is the tell: normal traffic spreads across pages, an attack concentrates on one expensive endpoint

---

# DoS/DDoS Prevention & Mitigation

**Core idea:** Defense is layered — application-level input hygiene, bot-filtering challenges, CDN load absorption, and WAF rule enforcement. Attackers specifically target the gaps between these layers.

## Application-Level Defense

**Secure development practices**
- Input validation on forms/search fields prevents abuse by design
- Analogy: a librarian with "only titles under 50 characters" rules responds fast; without rules, an oddball request slows everyone down
- Same principle as the SQLi/input-validation notes — bad input handling is a recurring root cause across attack types

**Challenges**
- CAPTCHA — trivial for humans, blocks/slows most bots
- JavaScript challenges — run silently in background, confirm real browser behavior; legit users don't notice, automated tools often fail

## Network/Infrastructure Defense

**CDN**
- Caches/serves from edge servers closest to users — reduces load reaching the origin
- Absorbs the bulk of DDoS traffic before it hits the backend
- Also load-balances across servers, reroutes if one goes down

Example (Cloudflare dashboard, 16 TB DDoS):
- Total bandwidth (30 days) — baseline vs. abnormal spike (a few hundred GB normal → 16 TB signals attack)
- Cached bandwidth by edge servers — near-total cache coverage means the CDN absorbed it before the origin was hit
- Visible traffic spike — the attack's signature on the graph

- CDNs also give visibility: breakdown by geography, volume, source pattern — useful for distinguishing malicious vs. legitimate traffic

**WAF**
- Usually bundled with CDNs
- Allow/challenge/block based on rules + threat intel
- Rate-limiting example: cap `/login.php` to 5 requests/min per IP — exceed it, get blocked or challenged
- Directly reuses the rate-limiting rule type from the earlier WAF note

## Large-Scale Mitigation (Real Examples)

- [Google (2023)](https://cloud.google.com/blog/products/identity-security/google-cloud-mitigated-largest-ddos-attack-peaking-above-398-million-rps) — mitigated a DDoS peaking at 398 million requests/sec
- [Cloudflare](https://thehackernews.com/2025/09/cloudflare-blocks-record-breaking-115.html) — claims largest DDoS mitigated, 11.5 Tbps peak, lasted 35 seconds
- Both rely on global distributed infrastructure to absorb and filter at scale

## Bypassing These Defenses

- **Cache-busting via query params** — `/products` is cached, but `/products?a=abcd` forces a cache miss, hitting the origin server directly
- Changing User-Agents, spoofing referrers, or distributing requests across geographic regions to evade WAF pattern-matching

**Why this matters:** every defense in this note has a corresponding bypass technique — CDN caching is beaten by cache-busting, WAF signature rules are beaten by UA/referrer rotation. Defense-in-depth exists because no single layer is bypass-proof on its own.
