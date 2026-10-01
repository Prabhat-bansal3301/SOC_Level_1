# Web Shells — Overview & Deployment

**Core idea:** A web shell is malicious code uploaded to a server, giving an attacker remote command execution through the web interface itself. Serves double duty: initial access (via upload flaw) and persistence (long-term backdoor).

## MITRE ATT&CK Mapping

| Phase | Technique |
|---|---|
| Initial Access | [File upload exploitation (T1190)](https://attack.mitre.org/techniques/T1190/) |
| Persistence | [Server software component: web shell (T1505.003)](https://attack.mitre.org/techniques/T1505/003/) |

After deployment, a web shell enables the rest of the kill chain: [Reconnaissance](https://attack.mitre.org/tactics/TA0043/), [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/), [Lateral Movement](https://attack.mitre.org/tactics/TA0008/), [Exfiltration](https://attack.mitre.org/tactics/TA0010/).

## Example

- Web shell: `awebshell.php`
- Location: `/uploads` directory on `10.10.10.100`
- Runs attacker-supplied commands remotely via the web interface

## How Web Shells Get Deployed

- Requires: file upload vulnerability, misconfiguration, or prior access
- Root cause: app fails to validate file type, extension, content, or destination
- Can be the initial foothold, or planted after compromise to maintain access

**Classic scenario:** a pet-photo upload site with no real validation — attacker uploads `shell.php` or `mydog.aspx` instead of an image, gets command execution.

## Real-World Examples

### Hafnium (ProxyLogon)

- [APT group](https://attack.mitre.org/groups/G0125), China-based
- Uploaded `.aspx` web shells to Exchange servers, e.g. `\inetpub\wwwroot\aspnet_client\`
- Also modified existing `.aspx` files, e.g. `\install_path\FrontEnd\HttpProxy\owa\auth\`
- Post-shell actions: command execution, recon, credential dumping, new-account persistence, lateral movement, exfiltration, anti-forensics

### Conti Ransomware

- [Threat actor](https://attack.mitre.org/software/S0575/), abused a similar Exchange vulnerability
- Uploaded `aspnetclient_log.aspx` to the same `\aspnet_client\` directory as Hafnium
- Uploaded a backup web shell within minutes of the first
- Rapidly mapped network computers, domain controllers, and domain admins

## Key Takeaway
Two separate APT groups exploited the **same directory path** on Exchange servers. Knowing common web shell drop locations for widely-used software (Exchange, WordPress, etc.) is itself a practical detection lead — checking known-abused paths is cheap and high-yield.

---

# Anatomy of a Web Shell

**Core idea:** Web shells don't rely on exotic exploits — they abuse legitimate language functions meant for system execution, just invoked on attacker-supplied input instead of trusted code.

## Abused Legitimate Functions (PHP)

- `shell_exec()`
- `exec()`
- `system()`
- `passthru()`

- These are normal, documented PHP functions — the vulnerability isn't the function, it's passing **unvalidated user input** into it

## How a Simple PHP Web Shell Works

1. Checks for a `cmd` parameter in the URL: `?cmd=whoami`
2. Stores the user-supplied command in `$cmd`
3. Executes it via `shell_exec()`
4. Displays the output
5. HTML provides a basic UI
6. The command itself gets executed
7. Result is returned to the attacker

## Complexity Spectrum

| Type | Capability |
|---|---|
| One-liner | Executes a command straight from a URL parameter |
| Full-featured | GUI, password protection, built-in file manager |

- Detection implication: a "sophisticated" web shell and a one-line shell both ultimately call the same handful of execution functions — searching for calls to `shell_exec`/`exec`/`system`/`passthru` in uploaded files catches both ends of the complexity spectrum

---

# Detecting Web Shells: Logs

**Core idea:** Web shells live in and interact through the web server, so access logs, error logs, and OS-level audit logs (auditd) each catch a different part of the picture. Correlating them confirms the full chain: upload → write → execute.

## Standard Access Log Quirks

- "Remote log name" field — legacy, almost always `-`
- "Authenticated user" field — `-` unless the server required prior auth, in which case it shows the actual username

## HTTP Methods: Normal vs. Abuse

| Method | Normal Use | Possible Abuse |
|---|---|---|
| GET | Retrieve a resource | Recon, interacting with a web shell |
| POST | Submit data | Upload or interact with a web shell |
| PUT | Upload/replace a file | Upload a web shell directly |
| DELETE | Remove a resource | Cleanup to cover tracks |
| OPTIONS | List supported methods | Reconnaissance |
| HEAD | Headers only, no body | Detect file existence |

## Request Pattern Indicators

- Repeated GETs in quick succession — probing for an upload point
- POST to a valid upload location right after repeated GETs — likely the actual upload
- Repeated GET/POST to the same file — ongoing shell interaction
- Same client IP + User-Agent across the whole sequence is a strong linking signal
- Track response codes and timestamps across the sequence to reconstruct the chain

## Suspicious User-Agents & IPs

- Altered: `Mozilla/4.0+(+Windows+NT+5.1)` truncated to `Mozilla/4.0`
- Outdated: `MSIE 6.0` (released 2001) — no legitimate reason to see this today
- Blacklisted/tool-based: `curl/1.XX.X`, `wget/1.XX.X`
- IP from outside the network's expected traffic pattern (e.g. external IP on an internal-only service)

## Query Strings

- Abnormally long or containing keywords like `cmd=`, `exec=`
- Encoded payloads — `?query=whoami` → `?query=d2hvYW1p` (Base64)
- [CyberChef](https://gchq.github.io/CyberChef/) — decode Base64 and other obfuscation

## Missing Referrer

- Can indicate direct/non-navigational access (consistent with web shell interaction)
- Not definitive alone — browsers can block referrers for privacy, or a user may type a URL directly

## Sample Suspicious Request — Indicator Checklist

1. Known-malicious or untrusted IP
2. Abnormal timestamp (outside business hours)
3. POST with a search-style query string to a suspicious file
4. No referrer (direct access)
5. Suspicious User-Agent not matching a real browser

## Auditd (Linux)

- Native Linux utility tracking system events into `audit.log`
- Rules can target specific conditions — program execution, file modification in a given directory

Example:

    ausearch -k web_shell

Output:

    time->Wed Jul 23 06:20:36 2025
    "name = /uploads/webshell.php"
    "OGID = www-data"

## Correlating Web Logs + Auditd

- Web logs show the suspicious `POST`
- Auditd shows the actual filesystem/process evidence: a `creat` syscall (file written) or `execve` syscall (command run)
- Linking the two confirms: request → file written → file executed, by which user/process

## SIEM Benefits

- Centralized collection/correlation across log types
- Targeted queries to surface web shell indicators specifically
- More efficient search/analysis than manually cross-referencing log files

# Detecting Web Shells: File System & Network Traffic

**Core idea:** A web shell has to live somewhere (file system) and has to communicate somehow (network). Logs give you the "what happened," but these two layers give you the actual artifact and the actual payload.

## File System Analysis

**Note:** Platforms like WordPress/Django often store content in a database, not the filesystem — malicious code can hide in posts/themes/settings and won't show up in a normal file search.

### Common Web Shell Drop Locations

| Server | Default Root |
|---|---|
| Apache | `/var/www/html/` |
| Nginx | `/usr/share/nginx/html/` |

- Even with a custom root, attackers scan/guess common upload paths: `/uploads/`, `/images/`, `/admin/`
- `/tmp` can be abused too if permissions are loose

### Suspicious File Names

- Executable extensions in unexpected places: `.php`, `.jsp`
- Double extensions to disguise type: `image.jpg.php`
- Names deviating from the app's normal file-naming pattern

### Useful Commands

Find recently modified PHP files in a date range:

    find /var/www -type f -name "*.php" -newerct "2025-07-01" ! -newerct "2025-08-01"
    /var/www/html/uploads/awebshell.php

Search for suspicious function calls (e.g. `eval(`):

    grep -r "eval(" wp-content
    /wp-content/uploads/awebshell2.php :eval(b64_dd($['cmd']));

- `find` narrows by modification time — useful once you have a suspected compromise window
- `grep` hunts for the abused functions from the earlier "Anatomy of a Web Shell" note directly in the codebase

## Network Traffic Analysis

Same indicator categories as log analysis, extended with packet-level detail:

- Unusual HTTP methods & request patterns
- Suspicious User-Agents & IPs
- Encoded payloads
- Malicious code/commands in request bodies
- Unexpected protocols or ports
- Unexpected resource usage
- Web server process spawning command-line tools (strong host-level indicator)

### Useful Wireshark Filters

| Filter | Purpose |
|---|---|
| `http.request.method == "METHOD"` | Hunt repeated/unusual requests by method |
| `http.request.uri contains ".php"` | Find suspicious/modified PHP files |
| `http.user_agent` | Spot unusual or outdated User-Agents |

[Full list of Wireshark HTTP filters](https://www.wireshark.org/docs/dfref/h/http.html)

### Why Packet Captures Matter Here

- A log shows `POST /upload.php` happened
- A packet capture can show the **actual PHP web shell source code** in the request body
- This is the difference between "something was uploaded" and "here is exactly what was uploaded" — direct confirmation, not inference

## Combining the Two Layers

- File system search finds the artifact (the dropped shell file itself)
- Network capture finds the delivery (how it got there, and what it does on each subsequent interaction)
- Same correlate-across-sources pattern as every earlier investigation in this repo: no single source tells the whole story alone
