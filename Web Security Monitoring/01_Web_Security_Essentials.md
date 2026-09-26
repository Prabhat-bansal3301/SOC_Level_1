# Web Applications: Why They're Prime Targets

**Core idea:** The shift from desktop to web/cloud apps traded security for convenience — web apps are always exposed, always online, and usually connected to high-value backend systems (databases, infrastructure). That combination makes them a favorite attacker entry point.

## Evolution of Web Applications

| Era | State |
|---|---|
| 1990s | Desktop apps dominant — speed/connectivity limitations |
| 2000s | Dynamic web apps rise — email, social media, banking |
| 2010s | Cloud computing / SaaS explosion |
| Today | Nearly everything runs in-browser |

## Security Tradeoffs

Benefits: accessibility, faster updates, cross-platform compatibility, lower local resource use.

Cost: web apps are **always online and exposed**, connect directly to backend infrastructure, and are reachable by anyone globally at any time — turning convenience into permanent attack surface.

## Risk Comparison

| As a Web App Owner | As a Web App User |
|---|---|
| App must be secured 24/7, always online | Data stored in the app, potentially insecurely |
| Reachable from anywhere in the world | Browser compromise puts all linked accounts at risk |
| Hard to keep pace with emerging threats | Breach = identity theft / financial loss |
| Responsible for securing all user data | Privacy can be permanently compromised |

## Real-World Examples

- **Equifax (2017)** — Apache Struts vulnerability exploited to access internal databases; ~150 million Americans' data compromised
- **Capital One (2019)** — misconfigured WAF exposed internal cloud infrastructure/databases; 100+ million customers' personal/financial data exposed

---

# Web Service Architecture & Web Servers

**Core idea:** Every web service runs on three components, and the request-response cycle between browser and server is the thing attackers abuse — by overwhelming it, bypassing its access controls, or tricking it into executing commands.

## Request-Response Cycle

1. Browser sends a request to a web server
2. Server processes it, checks access
3. Server returns a response — webpage, image, search results, account data

## Components of a Web Service

| Component | Role |
|---|---|
| Application | Code, images, styles, icons — how the site looks/functions |
| Web Server | Listens for requests, returns responses; sits in front of the app |
| Host Machine | Underlying OS (Linux/Windows) running the server + app |

## Web Servers

Publicly exposed, handling every incoming request — a natural high-value target.

| Server | Common Use |
|---|---|
| Apache | Popular for simple sites/blogs, most commonly WordPress |
| Nginx | Industry standard for high-performance apps — used by Netflix, Airbnb, GitHub |
| IIS (Internet Information Services) | Microsoft's web server, common in enterprise environments |

- Knowing which server type is running matters for triage — each has different known CVEs, config quirks, and log formats
- A web server being publicly exposed by design is exactly why it sits at the top of most attack surfaces — it has to accept connections from anyone, which is also what makes it abusable

---

# Web Security Best Practices & Access Logging

**Core idea:** Security controls map to the three components of a web service (application, web server, host machine) — plus baseline practices that apply across all three. Access logs are the evidence trail for reconstructing what happened.

## Protecting the Application

- Secure coding — avoid insecure functions, proper error handling, no leaked sensitive info
- Input validation & sanitization — prevent injection attacks
- Access control — restrict by user role

## Protecting the Web Server

- Logging — detailed access logs of every request
- WAF — filters/blocks malicious traffic by rule
- CDN — reduces direct server exposure, often bundles a WAF

## Protecting the Host Machine

- Least privilege — services run as low-privilege users
- System hardening — disable unnecessary services, close unused ports
- Antivirus — endpoint-level malware blocking

## Applies to All Three

- Strong authentication — restrict access to code, admin panels, host machine
- Patch management — keep app dependencies, web server, host machine up to date

## Access Logs

Recorded per request, typically capturing:
- Client IP address
- Timestamp
- Requested page/resource
- Response status code
- User agent

## Example: Benign Session (Baseline Pattern)

| Step | Action |
|---|---|
| 1 | Client `10.10.10.100` visits `/index.html` (GET) |
| 2 | Navigates to `/login.html` (GET) |
| 3 | Submits credentials (POST) |
| 4 | Accesses `/myaccount.html` (GET) |

- GET = retrieve a resource
- POST = submit data to the server

**Why this baseline matters:** this is the exact "normal" pattern you compare against when hunting for abnormal sequences — e.g., a client jumping straight to `/myaccount.html` with no prior login POST, or hundreds of POSTs to `/login.html` from one IP, would immediately stand out against this expected flow.

---

# CDN, WAF, and Antivirus

**Core idea:** These three sit at different layers of defense — CDN in front of the server, WAF inspecting individual requests, AV protecting the host filesystem — and no single one covers what the others catch.

## CDN (Content Delivery Network)

Caches/serves content from edge servers closer to users, reducing latency and acting as a buffer between user and origin server.

Security benefits:
- IP masking — hides origin server IP, harder to directly target
- DDoS protection — absorbs large traffic volumes
- Enforced HTTPS — TLS by default on most CDNs
- Integrated WAF — Cloudflare, Amazon CloudFront, Azure Front Door bundle one in

## WAF (Web Application Firewall)

Inspects incoming HTTP traffic, blocks/logs requests based on rules. Analogy: a bouncer checking every request before it's let in.

### WAF Deployment Types

| Type | Description |
|---|---|
| Cloud-based (reverse proxy) | Sits in front of the web server; easy to deploy, scales well |
| Host-based | Software on the web server itself; per-application control |
| Network-based | Physical/virtual appliance at network perimeter; enterprise-scale |

### Detection Methods

| Method | How it works | Example |
|---|---|---|
| Signature-based | Matches known attack patterns/payloads | User-Agent matching a known tool, e.g. `sqlmap/1.8.1` |
| Heuristic-based | Analyzes context/behavior of a request | Long query string with special chars: `search?q=%3Cscript%20(1)` |
| Anomaly/behavioral | Flags deviation from normal traffic | One IP making repeated login attempts fast |
| Location/IP reputation | Blocks based on geo/threat intel | Request from a region outside normal business activity |

- Detection methods evolve constantly; custom rules can be built per application's needs
- Cloudflare's security dashboard shows blocked/allowed requests over time, giving direct visibility into what the WAF caught

## Antivirus (AV)

Protects endpoints (desktops, laptops, servers) from known malicious files — not the web application layer itself.

- Mostly signature-based — compares files against a known-malware database
- Web attacks target the application layer, but AV still matters at the host level
- Catches malicious file uploads: web shells, post-exploitation tools, other malware
- One layer of defense-in-depth — not sufficient alone

## Why Layering Matters

- CDN stops volumetric/network-level threats and hides the real server
- WAF stops malicious requests at the application layer
- AV catches malicious files that land on the host after something gets through
- None of these substitutes for the others — a WAF won't catch a malicious file already uploaded, AV won't stop a SQLi payload in an HTTP request, a CDN won't inspect request content at all
