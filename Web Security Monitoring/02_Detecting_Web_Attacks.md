# Client-Side Attacks

**Core idea:** Attacks that abuse user behavior or the user's browser/device instead of the server. Public-facing web apps sit in front of databases and infrastructure, and more third-party plugins mean a wider browser attack surface.

## Example Scenario (Clickjacking-Style)

- User clicks a product image on an e-commerce site
- Attacker has hidden an invisible window inside the page, loading another site in the background
- Hidden site runs malicious code and steals the user's session cookies
- Nothing looks abnormal, but the attacker can now impersonate the user

## SOC Limitations

- Server-side logs and network captures show little to nothing of what happens inside a browser
- Malicious code can run, steal data, or manipulate the environment with no suspicious HTTP requests visible to the SOC
- Detection is often hard or impossible without browser-side security controls or endpoint monitoring
- Blind spot to know about: a clean web/proxy log doesn't prove a client-side attack didn't happen

## Common Client-Side Attacks

| Attack | Description |
|---|---|
| [Cross-Site Scripting (XSS)](https://tryhackme.com/room/axss) | Malicious scripts run in a trusted site and execute in the user's browser. [Most common](https://www.hackerone.com/blog/how-cross-site-scripting-vulnerability-led-account-takeover) client-side attack |
| [Cross-Site Request Forgery (CSRF)](https://tryhackme.com/room/csrfV2) | Browser is tricked into sending unauthorized requests as the trusted, logged-in user |
| Clickjacking | Invisible elements overlaid on legitimate content, so users think they're interacting with something safe |

### XSS Example

Unfiltered comment box, attacker posts:

    Hello <script>alert('You have been hacked');</script>

- Every visitor who loads the page runs the script in their browser
- Harmless pop-up here, but a real attack would steal cookies or session data instead

---

# Server-Side Attacks

**Core idea:** Attacks that exploit the web server, application code, or backend, not the user's browser. Any form that takes user input (login, search) is a potential entry point if input handling is flawed.

## Why Defenders Have the Advantage Here

- Every request is processed by the server and recorded in logs/monitoring
- Requests also cross the network, so traffic captures can reveal suspicious behavior
- Unlike client-side attacks, the evidence trail exists, if you know where to look

## Common Server-Side Attacks

| Attack | How it works | Real-world example |
|---|---|---|
| [Brute-force](https://tryhackme.com/room/passwordattacks) | Automated tools repeatedly try usernames/passwords from large lists | [T-Mobile (2021)](https://www.fierce-network.com/operators/t-mobile-ceo-says-hacker-used-brute-force-attacks-to-breach-it-servers) — PII of 50M+ customers |
| [SQL Injection (SQLi)](https://tryhackme.com/room/sqlinjectionlm) | App builds queries via string concatenation instead of parameterized queries, letting attackers alter the SQL command | [MOVEit (2023)](https://www.akamai.com/blog/security-research/moveit-sqli-zero-day-exploit-clop-ransomware) — 2,700+ orgs affected, incl. US gov agencies, BBC, British Airways |
| [Command Injection](https://tryhackme.com/room/oscommandinjection) | User input passed to the system unchecked; attacker sneaks in OS commands run with the app's permissions | [Common attack](https://krishnag.ceo/blog/the-2024-cwe-top-25-understanding-and-mitigating-cwe-78-os-command-injection/) (CWE-78) |

## Key Points Per Attack

**Brute-force**
- Detection signal: high volume of failed logins from one source (same pattern as the VPN brute-force earlier)

**SQL Injection**
- Root cause: string concatenation instead of parameterized queries
- Fix: parameterized queries / prepared statements

**Command Injection**
- Runs with the same permissions as the web application — this is why least privilege on the host matters

---

# Web Attacks in Access Logs

**Core idea:** Every request to a web server leaves evidence in access/error logs. Patterns across entries reveal scanning, exploitation, and brute-force. Real logs are mostly benign traffic, so the skill is spotting the malicious pattern inside the noise.

## Access Log Fields

| Field | What to look for |
|---|---|
| Client IP | Known-malicious or outside expected geo range |
| Timestamp + requested page | Unusual hours, or repeated requests in a short window |
| Status code | Repeated `404` = someone hunting for pages that don't exist |
| Response size | Much smaller or larger than normal |
| Referrer | Referring pages that don't fit normal site navigation |
| User-Agent | Outdated browsers, or attack tools (`sqlmap`, `wpscan`) |

- Not all servers use this exact format, but most carry these fields

## Attack Sequence in Logs

| Stage | What the log shows |
|---|---|
| 1. Directory fuzzing | Rapid requests to many paths; `200` responses = valid finds for the attacker (e.g. `login.php`) |
| 2. Brute-force | Repeated `POST` to `login.php` in quick succession; last one returns `302 Found` = successful login, redirect to `/account` |
| 3. SQL injection | Payloads on `/search`: `' OR '1'='1` and `1' OR 'a'='a` |

- Directory fuzz → `404` flood with a few `200`s
- Brute-force → burst of `POST`s, then one different status code = success
- SQLi → payloads visible in the query string, so they're readable in the log
- If the app builds SQL dynamically (no parameterized queries), these payloads can dump the database

## Log Limitations

Example entry:

    10.10.10.100 [12/Aug/2025:14:32:10] "POST /login HTTP/1.1" 200 532 "/home.html" "Mozilla/5.0"

- Shows method, page, and status code, but **not** the submitted credentials or payload
- Access logs don't record `POST` body data, so you only know the request happened, not what was sent
- `GET` requests may log full paths and query strings, but some formats omit them
- What gets logged depends on the server software and its logging configuration
- Blind spot: a `POST`-based injection (e.g. SQLi in a form body) won't show its payload here, so you'd need a WAF log or packet capture to see it

## Quick Detection Cheat Sheet

| Pattern | Likely activity |
|---|---|
| Many `404`s from one IP | Directory fuzzing / scanning |
| Burst of `POST`s to a login page | Brute-force |
| `POST` burst followed by a `302` | Brute-force succeeded |
| Attack-tool User-Agent | Automated scanner/exploit tool |
| SQL syntax in query string | SQL injection attempt |

---

# Web Attacks in Network Traffic (Wireshark)

**Core idea:** Packet captures show what access logs can't: full HTTP headers, POST bodies, cookies, and transferred files. Same attack sequence as the access-log note, but now with the actual evidence.

## Logs vs. Packet Captures

| | Access Logs | Packet Capture |
|---|---|---|
| Request line, status code | Yes | Yes |
| POST body (credentials, payloads) | No | Yes |
| Full headers and cookies | Partial | Yes |
| Server response content | No | Yes |
| Uploaded/downloaded files | No | Yes |

- Captures are far more verbose, so they're best for confirming and detailing an attack you already suspect
- Encrypted protocols (HTTPS, SSH) hide the payload without decryption keys
- Focus here is plain HTTP

## Useful Wireshark Filters

| Filter | Purpose |
|---|---|
| `ip.dst == 10.10.20.200` | Traffic to the web server |
| `http.user_agent` | Show/filter User-Agent field (spot attack tools) |
| `http.request.method == "POST"` | Isolate form submissions (login attempts) |
| `http contains "OR '1'='1"` | Search for SQLi payload strings |

## Attack Sequence (Same Attacker as Access Log Note)

1. Directory fuzz: find valid directories/forms
2. Brute-force on `login.php`: packet 13 is the successful login
3. SQL injection attempts
<img width="1386" height="465" alt="brute force on login php" src="https://github.com/user-attachments/assets/a3566520-1ff5-49d6-9612-a253ded7e322" />

## Evidence Recovered

**Brute-force (packet 13)**
- POST body shows the exact credentials tried
- Successful login used password `password123` on an admin account
- Weak password on a privileged account is the root cause

<img width="1388" height="621" alt="http stream follow of brute force packet" src="https://github.com/user-attachments/assets/2eb34bb8-f35e-44e9-b7e9-c4883eabc6d5" />


**SQL injection (`' OR '1'='1`)**
- Packet shows the exact payload used
- Response shows the result: the Users table was dumped
- First name and Surname visible in cleartext to the attacker

<img width="1392" height="698" alt="tcp stream follow of sqli" src="https://github.com/user-attachments/assets/91a38b80-7b4c-45c1-ac3a-e01d93c308d5" />


## Log vs. Packet: What Each Told Us

| Stage | Access log showed | Packet capture added |
|---|---|---|
| Brute-force | Repeated POSTs, one `302` | Actual usernames/passwords, the winning password |
| SQLi | Payload in query string | Full payload plus the data returned to the attacker |

- Logs prove the attack happened; captures prove what was stolen
- Impact assessment (which data left) usually needs the packet-level view

## Extra Notes

- MySQL protocol traffic can also be analyzed in Wireshark, showing the query and the returned result
- Follow a suspicious packet with right-click, then **Follow, TCP Stream** to read the full request/response
- Cleartext credentials in captures mean the affected account must be treated as compromised and reset

---

# WAF Rules & Mitigation

**Core idea:** A WAF inspects full HTTP requests (like Wireshark, but it can decrypt TLS) and allows, blocks, or challenges them **before** they reach the server. It's the mitigation counterpart to the detection work in earlier notes.

## Rule Categories

| Rule type | Description | Example |
|---|---|---|
| Block common attack patterns | Known malicious payloads/indicators | Block User-Agent `sqlmap` |
| Deny known malicious sources | IP reputation, threat intel, geo-blocking | Block IPs from recent botnet campaigns |
| Custom-built rules | Tailored to your app | Allow only GET/POST to `/login` |
| Rate-limiting & abuse prevention | Caps request frequency | Max 5 login attempts/min per IP |

## Example: Blocking SQLMap

- Observed: repeated GET requests to `/changeusername`, User-Agent `sqlmap/1.9`
- Traffic review confirms SQLi payloads in the requests
- Rule:

        If User-Agent contains "sqlmap"
        then BLOCK

- Modern WAFs already block known tool User-Agents automatically
- Custom rules let you target your specific app/threat without hitting normal traffic
- Weakness: User-Agent is attacker-controlled, and sqlmap can change it (`--user-agent`, `--random-agent`), so this rule alone is easy to bypass
- Stronger: pair it with payload-pattern rules and rate-limiting, not UA matching alone

## Challenge-Response

- WAF can challenge a request (e.g. CAPTCHA) instead of blocking outright
- Verifies a real user vs. a bot
- Best for rules with a higher false-positive risk, since a real user can still pass
- Matters because malicious bots make up ~37% of global web traffic ([Thales](https://www.thalesgroup.com/en/worldwide/defence-and-security/press_release/artificial-intelligence-fuels-rise-hard-detect-bots))

## Threat Intelligence & Known Indicators

- Built-in rule sets cover the [OWASP Top 10](https://owasp.org/www-project-top-ten/) risks
- Threat intel feeds auto-block known malicious IPs and suspicious User-Agents
- Regular updates cover new threats: APT group activity, newly disclosed CVEs
- Example: [Cloudflare's curated IP lists](https://blog.cloudflare.com/new-waf-intelligence-feeds) built from botnets, VPNs, anonymizers, and malware sources

## Action Options per Rule

| Action | Use when |
|---|---|
| Block | High-confidence malicious (known tool, known bad IP) |
| Challenge (CAPTCHA) | Suspicious but could be legitimate |
| Log only | New/untested rule, checking for false positives first |
| Rate-limit | Abuse patterns like brute-force |

- New rules are often run in log-only mode first to check for false positives before switching to block
