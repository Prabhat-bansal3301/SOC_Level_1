# SOC Alert Investigation – Brute Force Detection (Splunk, Linux SSH Logs)

**Scenario:** first shift as a SOC L1 analyst at an MSSP (Managed Security Service Provider). An alert fired for possible brute force activity. The job is to decide whether it's a **True Positive** or a **False Positive**.

| Alert field | Value |
|---|---|
| Alert name | Brute Force Activity Detection |
| Time | 17/09/2025, 9:00:21 AM |
| Target host | `tryhackme-2404` |
| Source IP | `10.10.242.248` |

**Log location:** Splunk index `linux-alert` (sourcetype `linux_secure`, which holds SSH/auth logs).

## Step 1: Triage the Alert Fields

| Field | Observation | What it suggests |
|---|---|---|
| **Source IP** | Private (internal) IP | The attacker may already be **inside the network** (compromised VPN or another entry point) |
| **Hostname** | Nothing obvious | No asset inventory, so can't tell what the system is. Probably an organisational server |
| **Time** | 9 AM, normal working hours | Timing alone doesn't look suspicious |

Takeaway: an **asset inventory** would help here. Without it, a hostname tells you very little.

## Step 2: Look at All Login Activity from the IP
Searches for successful logins, failed logins and **invalid user** attempts together.

```
index="linux-alert" sourcetype="linux_secure" 10.10.242.248
| search "Accepted password for" OR "Failed password for" OR "Invalid user"
| sort + _time
```

<img width="1233" height="618" alt="large number of events" src="https://github.com/user-attachments/assets/5985f179-b526-4a99-98b8-55971426dc90" />


- Large number of events from this one IP
- Several attempts for **non-existent users**, which is suspicious
- Invalid user attempts are often **account enumeration**: the attacker guesses usernames before brute forcing one

## Step 3: Count Attempts per User
Uses `rex` to pull fields out of the raw log, then `stats` to count by username.

```
index="linux-alert" sourcetype="linux_secure" 10.10.242.248
| rex field=_raw "^\d{4}-\d{2}-\d{2}T[^\s]+\s+(?<log_hostname>\S+)"
| rex field=_raw "sshd\[\d+\]:\s*(?<action>Failed|Accepted)\s+\S+\s+for(?: invalid user)? (?<username>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| eval process="sshd"
| stats count values(src_ip) as src_ip values(log_hostname) as hostname values(process) as process by username
```

<img width="1817" height="793" alt="IP targeted four different users" src="https://github.com/user-attachments/assets/e5928bf1-bf61-4a1b-923a-048eccfb02b2" />

<img width="1687" height="801" alt="Strong evidence of brute force attempt" src="https://github.com/user-attachments/assets/9c46880d-c170-4ccc-9f2b-f3de52b14fc8" />


**Result:**
- The IP targeted **4 different users**
- Only `john.smith` had a very high count: **503 attempts**
- That is a clear **brute force** indicator

**Query pieces explained:**

| Part | What it does |
|---|---|
| `rex` | Extracts fields (hostname, action, username, source IP) from the raw log text using regex |
| `eval process="sshd"` | Creates a field with a fixed value |
| `stats count ... by username` | Counts events and groups them per user |
| `values(...)` | Lists the distinct values of a field in each group |

## Step 4: Did the Attack Succeed?
Same search with `values(action)` added, so each user shows whether they had **Failed** and/or **Accepted** logins.

```
... | stats count values(action) values(src_ip) as src_ip values(log_hostname) as hostname values(process) as process by username
```

- A **successful login** appears only for `john.smith`
- So the brute force **worked**, and the attacker got into `tryhackme-2404`

## Verdict: True Positive
- Many failed attempts followed by a success on the same account
- Attacker has **access to the host**
- **Action:** escalate immediately to **SOC L2**, with possible involvement of the **Incident Response (IR)** team

## Investigation Workflow (Reusable)
1. Triage the alert fields (IP type, host, time)
2. Pull **all** related events for the source IP
3. Check for **invalid users** (enumeration)
4. **Count attempts per user** to spot the target
5. Check whether any attempt was **Accepted**
6. Decide TP or FP, then escalate with the evidence

## What L1 Hands Over (Open Questions for L2/IR)
- Why does the attacker have an **internal IP**? Are they already inside the network, and for how long?
- How did they get the **usernames**?
- What did they do **after** logging in to `tryhackme-2404`?

IR then handles **containment and remediation**.

## Key Takeaways
- **Many failed logins + one success = successful brute force**
- **Invalid user** events point to enumeration before the attack
- An **internal source IP** doesn't mean safe. It can mean a compromised internal host or VPN
- L1's job: **detect, validate and escalate** with clear evidence, not full response
- Useful SSH log strings: `Failed password for`, `Accepted password for`, `Invalid user`

---

# SOC Alert Investigation – Scheduled Task Persistence (Splunk, Windows Logs)

**Scenario:** L1 SOC analyst at an MSSP. An alert fired for a possible **scheduled task persistence** attempt. The job is to decide whether it is a True Positive or a False Positive.

| Alert field | Value |
|---|---|
| Alert name | Potential Task Scheduler Persistence Identified |
| Time | 30/08/2025, 10:06:07 AM |
| Host | `WIN-H015` |
| User | `oliver.thompson` |
| Task name | `AssessmentTaskOne` |

**Log location:** Splunk index `win-alert`

## Step 1: Triage Before Opening the SIEM
Pause and read the alert details first. Context decides how suspicious the activity is.

| Check | Finding | Why it matters |
|---|---|---|
| **Host type** | `WIN-H015` suggests a **workstation** | Tasks created on user workstations deserve more scrutiny than on servers |
| **User role** | Oliver Thompson is a **System Engineer** | Creating tasks can be normal for IT staff |
| **Time and location** | Check working hours and location | Activity outside normal hours or places is a red flag |

**Tips:**
- Use an **Asset Inventory** (Confluence, Notion, etc.) to identify hosts. If none exists, use **naming conventions**
  - Servers: `SRV`, `WEB`, `MSQL`
  - Workstations: `WIN`, `HOST`
- Use the **identity table** to check whether the activity fits the user's job. For example, an HR user creating scheduled tasks would be odd, but IT staff doing it is normal

## Step 2: Search for the Task Creation Event
Searches by Event ID **4698** (scheduled task created) and the task name. The host is **not** filtered at first, to see whether the activity is isolated or spread across machines.

```
index="win-alert" EventCode=4698 AssessmentTaskOne
| table _time EventCode user_name host Task_Name Message
```

<img width="2934" height="1356" alt="Single event" src="https://github.com/user-attachments/assets/13e2110d-b2f1-47ee-82ce-385b52af892f" />

<img width="922" height="660" alt="Message field" src="https://github.com/user-attachments/assets/f544c942-5ddc-4a75-9dd1-570998ceafe6" />

<img width="1232" height="578" alt="Message field 2" src="https://github.com/user-attachments/assets/a0703f53-152b-4ac1-a102-8f7825d53a7e" />

**Findings:**
- Only **one event**, so the activity is isolated to a single host
- The task runs **every day at the same time** on a user workstation, which is unusual
- The **Message** field holds the task details. Focus on the **Exec** (what runs) and **Principals** (which account) sections

## Step 3: Analyse the Task Contents
The Exec section showed the first clear signs of malicious activity:

| Element | What it did |
|---|---|
| `certutil` | Downloaded `rv.exe` from a suspicious domain (`tryhotme`) |
| Saved to the **Temp** folder | Renamed to `DataCollector.exe` |
| PowerShell `Start-Process` | Launched the downloaded file |
| Principal | Ran under `oliver.thompson` |

**Why this is malicious:**
- **`certutil`** is a legitimate Windows tool abused to download files (a LOTL technique)
- **Renaming** `rv.exe` to a harmless-sounding `DataCollector.exe` is **masquerading**
- Running from the **Temp** folder is common for malware
- A **daily scheduled task** keeps re-running the payload, which is **persistence**

## Verdict: True Positive
- A scheduled task downloads and executes an external file
- Clear **persistence** behavior
- **Action:** escalate to **SOC L2**
- Extra step: check the domain on **Threat Intelligence platforms**, since it may be linked to known attacker infrastructure

## Reusable Investigation Workflow
1. Read the alert fields and work out the **host type** and **user role**
2. Search for **EventCode 4698** and the task name
3. Leave the host filter off first to check how widely it spreads
4. Read the **Message** field (Exec and Principals)
5. Look for **LOTL tools** (`certutil`, PowerShell), downloads and odd file locations
6. Check domains and hashes on threat intel platforms
7. Decide TP or FP, then escalate with evidence

## Open Questions for L2
- How was the scheduled task **created**?
- How did the attacker get onto `WIN-H015`?
- How was the `oliver.thompson` account **compromised**?

## Key Takeaways
- **Event ID 4698** = scheduled task created (also watch **4699** for deleted)
- Always check **host type and user role** before judging the activity
- A **legitimate user can still be the one running malicious activity** if the account was compromised, so a normal role alone doesn't make an alert benign
- **certutil downloading an executable** into a temp folder, followed by `Start-Process`, is a classic persistence chain
- L1's job: **validate, document and escalate**, not full remediation

---

# SOC Alert Investigation – Web Shell Upload (Splunk, Web Server Logs)

**Scenario:** L1 SOC analyst on shift. This alert is web-related: possible **web shell** activity on the organisation's website. The job is to decide whether it is a True Positive or a False Positive.

| Alert field | Value |
|---|---|
| Alert name | Potential Web Shell Upload Detected |
| Time | 14/09/2025, 09:31:51 AM |
| Resource | `http://web.trywinme.thm` (company website on the web server) |
| Suspicious IP | `171.251.232.40` |

**Log location:** Splunk index `web-alert` (the task text also mentions `win-web`, but the queries use `web-alert`).

## Step 1: Triage the Alert Details
- The **resource** is the public-facing website, so it is exposed to the internet
- Check the **suspicious IP** on a threat intel platform. On [AbuseIPDB](https://www.abuseipdb.com/check/171.251.232.40) it was reported as malicious **3000+ times**
- Write this down as evidence before moving into the SIEM

## Step 2: See Everything the IP Did
```
index=web-alert 171.251.232.40
| table _time clientip useragent uri_path method status
| sort + _time
```

<img width="1602" height="800" alt="brute force attempts" src="https://github.com/user-attachments/assets/bfff8b83-aa30-404a-8f91-763028281a92" />


**Findings:**
- A **large number of requests** from this one IP
- The **User-Agent is `Hydra`**, a well-known brute force tool
- Requests targeted **`wp-login.php`** (the WordPress login page)
- This alone is clear evidence of an attempt to gain unauthorized access

But the alert is about a web shell, so there may be more.

## Step 3: Remove the Hydra Noise
Excluding the Hydra User-Agent shows what else the IP did.

```
index=web-alert 171.251.232.40 useragent!="Mozilla/5.0 (Hydra)"
| table _time clientip useragent uri_path referer referer_domain method status
```

<img width="1772" height="792" alt="POST request" src="https://github.com/user-attachments/assets/921be3c4-b3ba-4c1d-baa6-9ad1210978cd" />


**What stood out:**
- A **POST** to `admin-ajax.php`
- Its **referer** was `theme-editor.php?file=b374k.php`
- The theme editor shouldn't reference an arbitrary file like `b374k.php`, so this strongly suggests a web shell was uploaded or is being used

## Step 4: Focus on the Suspicious File
```
index=web-alert 171.251.232.40 b374k.php
| table _time clientip useragent uri_path referer referer_domain method status
| sort + _time
```

<img width="1536" height="622" alt="b374k php" src="https://github.com/user-attachments/assets/e10702c4-395f-4d71-988a-0df7c6ba93cd" />


**Findings:**
- The attacker **successfully accessed** `b374k.php`
- **4 successful POST requests** followed, meaning commands or actions were executed through it
- The logs **don't show how the shell was uploaded**
- A web search for **"b374k.php web shell"** confirmed it is a known, popular web shell. Attackers often keep the default filename

## Attack Chain Summary

| Stage | Evidence |
|---|---|
| **Brute force** | Hydra User-Agent against `wp-login.php` |
| **Web shell** | `b374k.php` accessed via the theme editor referer |
| **Execution** | 4 successful POST requests to the shell |
| **Source** | `171.251.232.40` (Vietnamese IP, flagged 3000+ times) |

## Verdict: True Positive
- **Action:** escalate to **SOC L2**. This will likely involve the **Incident Response (IR)** team

## Open Questions for L2
- Was the **Hydra brute force successful**?
- **How was the web shell uploaded**, since L1 found no trace of it?
- What **commands** did the attacker run through the shell?

After that: **containment and remediation**.

## Key Terms
- **Web shell:** a malicious script placed on a web server that gives the attacker remote control through the browser (here, a `.php` file)
- **Hydra:** an open-source brute force tool. Its name often appears in the User-Agent
- **Referer:** the page that led to a request. Here it exposed the link to the web shell
- **`wp-login.php`:** the WordPress login page, a common brute force target

## Reusable Investigation Workflow
1. Read the alert and check the **IP reputation** (AbuseIPDB, etc.)
2. Pull **all requests** from the IP, sorted by time
3. Look at **User-Agent** values for attack tools
4. **Exclude the noisy pattern** (Hydra) to find other activity
5. Look for **odd files, POST requests and referers**
6. **Research the file name** online
7. Decide TP or FP, then escalate with evidence

## Key Takeaways
- A **tool name in the User-Agent** (Hydra, Nmap, sqlmap) is a strong sign of attack activity
- Brute force on a login page can lead to **admin access, then web shell upload**
- Filtering out noise (`useragent!=...`) often reveals the second stage of an attack
- A **POST to a theme or plugin file with an odd referer** can point to a web shell
- A **known web shell name** can be confirmed with a quick search
- L1's job: **identify, document and escalate**
