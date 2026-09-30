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
