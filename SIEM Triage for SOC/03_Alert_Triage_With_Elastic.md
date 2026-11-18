# SOC Investigation – Multi-Stage Attack in Elastic/Kibana (ProxyLogon → Web Shell → RDP → Backdoor User)

**Scenario:** five related alerts on the same server (`winserv2019.s ome.corp`), all tied to one client IP (`203.0.113.55`). Instead of treating each alert on its own, the task is to **correlate them into one attack timeline** and decide whether they are True Positives.

## Alerts Received

| Alert ID | Time (Jul 20, 2025) | Severity | Alert | Trigger |
|---|---|---|---|---|
| SOC-20250720-0012 | 04:38:40 | High | Web requests indicating file upload | WAF: multiple POSTs to `proxyLogon.ecp` |
| SOC-20250720-0013 | 04:45:31 | High | GET requests to ASPX file with query parameters | WAF: GETs to `errorEE.aspx` with `cmd=` |
| SOC-20250720-0014 | 05:11:22 | High | Administrator access outside business hours | EDR: Administrator authentication outside expected hours |
| SOC-20250720-0015 | 05:13:10 | **Critical** | New user account created | EDR: user account management, new user created |
| SOC-20250720-0016 | 05:13:15 | **Critical** | Unusual command-line behavior: privilege changes | EDR: `cmd.exe` usage |

**Index and log sources used:**
- `weblogs`: web/WAF requests
- **Windows Security** logs: logons, account and group changes
- **Sysmon**: process creation
- **PowerShell** logs: script content

---

## Stage 1: ProxyLogon Exploitation (Alert 0012)
**Goal:** see every web request from the suspicious IP.

```
_index:weblogs and client.ip:203.0.113.55 and http.request.method:POST
```

<img width="1901" height="642" alt="POST requests" src="https://github.com/user-attachments/assets/3ac465dc-7754-427a-bd93-29e42f5b3de9" />


**Table columns to add** (hit the `+` next to a field): `client.ip`, `user.agent`, `http.request.method`, `url.path`, `http.response.status_code`

**Findings:**
- Repeated POSTs to `proxyLogon.ecp`
- The **user-agent** shows the requests are **automated** (scripted tooling, not a browser)
- The page name relates to the [ProxyLogon](https://proxylogon.com/) vulnerability, which targets Microsoft Exchange servers
- Already a red flag, even without knowing the exact exploit

### Stage 2: Web Shell Activity (Alert 0013)
Same IP, seven minutes later. The **`cmd=`** parameter is a hallmark of **web shell** activity, because attackers append commands to it (e.g. `cmd=id`).

```
_index:weblogs and client.ip:203.0.113.55 and http.request.method:GET and errorEE.aspx
```

<img width="1902" height="666" alt="GET requests" src="https://github.com/user-attachments/assets/ba7328bb-a914-4a13-b9c4-fa4af3e6f536" />


- Sort **Old-New** so the earliest requests appear first
- The executed commands are visible in the **`url.path`** field
- This confirms a breach, so **both web alerts are True Positives and get escalated**

## Stage 3: Administrator Logon (Alert 0014)
**Pivot from network evidence to host evidence.** Confirm *when, how and from where* the Administrator logged on, using Security Event ID **4624** (successful logon).

```
@timestamp >= "2025-07-20T05:11:22" and winlog.event_id:4624 and host.name:winserv2019.some.corp and winlog.event_data.TargetUserName:Administrator
```

<img width="1911" height="472" alt="Security Event ID 4624" src="https://github.com/user-attachments/assets/4ef89502-bc30-4d4f-a298-8441765bfc24" />


| Field | Meaning |
|---|---|
| `winlog.event_id` | Windows event ID |
| `host.name` | Host where the logon happened |
| `winlog.event_data.TargetUserName` | Account that logged in |
| `winlog.logon.type` | **How** the user logged in (e.g. remotely via RDP) |
| `winlog.event_data.IpAddress` | **Source IP** of the logon (very important) |

**Finding:** the Administrator logon came from the **same IP `203.0.113.55`**, linking the web attack to the host logon.

**Correlate with Sysmon** (Event ID **1** = process creation):
```
@timestamp >= "2025-07-20T05:11:22" and winlog.event_id:1 and user.name:Administrator
```

<img width="1912" height="692" alt="Sysmon Event ID 1" src="https://github.com/user-attachments/assets/66c61aa5-f753-4dd3-b2f5-f479cb8115bd" />


Columns: `user.name`, `process.parent.name`, `process.command_line`

- The process chain matched **normal Windows session initialization**
- So far this proves the logon but **not malicious intent**. Maybe the admin just started early. The next alerts settle it

## Stage 4: Backdoor User Created (Alert 0015)
```
@timestamp >= "2025-07-20T05:13:10.000" and winlog.channel:Security and winlog.task:User Account Management
```

- `winlog.task` gives a human-readable category of the event
- Table columns: `winlog.event_id`, `winlog.task`, `message`
- Sort **Old-New** to see the first events at the top
- Shows a **new account created** shortly after the odd-hours logon

## Stage 5: Privilege Changes via CMD (Alert 0016)
**L1 steps:**
1. **Scope:** find the child processes launched by `cmd.exe`
2. **Origin:** who launched `cmd.exe`, and why
3. **Privilege changes:** look for `net` commands adding users to groups
4. **Correlate** Sysmon and Security logs

```
@timestamp >= "2025-07-20T05:13:15" and process.parent.name:cmd.exe and user.name:Administrator
```

<img width="1897" height="515" alt="parent process cmd exe" src="https://github.com/user-attachments/assets/e4692828-62a2-44ed-9078-9966fb2f69f9" />


Columns: `process.command_line`, `process.name`, `process.parent.name`

**Correlate with Event ID 4732** (member added to a security-enabled group):
```
@timestamp >= "2025-07-20T05:13:15" and (winlog.event_id:4732 or process.parent.name:cmd.exe)
```

<img width="1897" height="602" alt="Windows Security Event ID 4732" src="https://github.com/user-attachments/assets/b85b878b-8c6e-4e46-8362-20da620aade0" />


- The new account was added to **three groups**
- Sysmon (what command ran) and Security **4732** (what changed) confirm each other

### Stage 6: PowerShell Activity
The attack didn't stop at the backdoor user. Check PowerShell **script block logging** (Event ID **4104**).

```
@timestamp >= "2025-07-20T05:13:15" and event.module:powershell and event.code:4104
```

<img width="1902" height="667" alt="results are whoami" src="https://github.com/user-attachments/assets/c19a4b4d-b6dc-4cd6-b1dc-104088486ae6" />


- Add column `powershell.file.script_block_text` to see commands in **plaintext**
- First commands: **`whoami`** and **`whoami /priv`**, classic **discovery** commands to learn the current account and its privileges

## Stage 7: Activity With No Alert (Rar.exe)
Not everything is covered by an alert. The new account used **`Rar.exe`** (a compression tool). No alert fired because it's legitimate software the client uses.

```
process.name: "Rar.exe"
```
**Questions to decide if it's malicious:**
- Is there enough evidence to call it malicious or benign?
- Which **account** ran it, **when** and **how** (correlate across logs)?
- Do the **timing** and **parent process** suggest abuse?

Compressing files is a common step before **data exfiltration**, so check what was archived and where it went.

---

## Attack Timeline

| Time | Stage | Evidence |
|---|---|---|
| 04:38 | **Initial access:** ProxyLogon exploitation | POSTs to `proxyLogon.ecp` |
| 04:45 | **Execution:** web shell commands | GETs to `errorEE.aspx?cmd=` |
| 05:11 | **Lateral/Valid account:** Administrator logon (4624) from same IP | Logon outside business hours |
| 05:13 | **Persistence:** new user created | User Account Management event |
| 05:13 | **Privilege escalation:** user added to groups via `cmd` | Sysmon + Event 4732 |
| After | **Discovery:** `whoami`, `whoami /priv` | PowerShell 4104 |
| After | **Collection:** `Rar.exe` use by new account | Sysmon process creation |

## Event IDs and Fields Cheat Sheet

| Item | Meaning |
|---|---|
| Security **4624** | Successful logon |
| Security **4732** | Member added to a security-enabled group |
| Sysmon **1** | Process creation |
| PowerShell **4104** | Script block logging (commands in plaintext) |
| `winlog.logon.type` | How the logon happened (RDP, etc.) |
| `process.parent.name` | Parent process, key for process chains |

## Key Takeaways
- **Correlate alerts into a timeline.** One IP across web, logon, account and command alerts shows a single attack
- **Pivot from network to host evidence.** Web logs show the entry point. Windows and Sysmon logs show what happened after
- A **normal-looking event** (an admin logon) only becomes suspicious in context: same attacker IP, odd hours, followed by account creation
- **Sort Old-New** to read events in order, and add only the fields you need as columns
- **`cmd=` in a URL** points to a web shell
- **Legitimate tools** (`Rar.exe`, `cmd.exe`, PowerShell) can be abused. Judge them by **who ran them, when and from which parent process**
- Escalate with confidence once you can show **which account, when and how**
