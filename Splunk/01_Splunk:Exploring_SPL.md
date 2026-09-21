# Splunk Basics: Search & Reporting App, SPL, Fields Sidebar

**Core idea:** Splunk is a SIEM that ingests log data; SPL (Search Processing Language) is how you turn raw volume into answers. Everything in Splunk starts with picking an index and a time range.

## Search & Reporting App — Interface

<img width="1770" height="770" alt="Search and report" src="https://github.com/user-attachments/assets/d43519b4-fdbf-439c-a17a-9030011b809e" />

| Component | Purpose |
|---|---|
| Search Head | Where you type SPL queries to filter/aggregate log data |
| Time Picker | Selects the timeframe of the search |
| Search History | Previously run queries — reusable |
| Data Summary | Summary of available hosts, sources, and sourcetypes |

**Why the Time Picker trips people up constantly:** Splunk defaults to a narrow recent window (often "Last 24 hours"). If your lab data was ingested weeks ago, a perfectly correct query returns zero results and you'll waste time debugging syntax that was never broken. Set **All time** first when working with static lab datasets, then narrow down.

**Why Data Summary is worth checking early:** before writing any query, it tells you what hosts/sourcetypes actually exist in the data. Guessing a sourcetype name and getting no results looks identical to "no malicious activity found" — which is a dangerous confusion in a real investigation.

## Your First Search

    index=windowslogs

- `index` = a Splunk database/container that organizes ingested data
- Both `index=windowslogs` and `index = windowslogs` are valid syntax (whitespace around `=` doesn't matter)
- Set time range to **All time** for lab data

**Practical habit:** always scope by index first. Searching without an index filter makes Splunk scan everything it has — slow in a lab, potentially a serious performance problem on a real production SIEM with terabytes of data.

## Fields Sidebar (left panel)

<img width="1661" height="777" alt="Field bar" src="https://github.com/user-attachments/assets/b2ba7ef8-f772-4122-84eb-bc1a53e8c872" />

| Section | What it shows |
|---|---|
| Selected Fields | Default extracted fields shown with each event. Click any field and toggle **Selected** to add it here |
| Interesting Fields | Fields Splunk auto-identified in your results — good starting point for exploration |
| More available fields | Additional fields not currently listed |

### Field Type Symbols

| Symbol | Meaning |
|---|---|
| `#` | Numeric field (numerical values) |
| `α` | Alpha-numeric field (string/text values) |

Each field also shows a **Count** — the number of events containing that field.

**Why the sidebar is the fastest recon tool in Splunk:** clicking a field shows its **top values** immediately. In an investigation, clicking `src_ip` and seeing one IP responsible for 80% of events answers "who's the suspect?" before you write a single `stats` command. The `#` vs `α` distinction also matters practically — numeric fields can be used with math/stats functions (`avg`, `sum`, `max`); string fields can't.

---

# SPL Basics: Free Text, Operators, Order of Evaluation

**Core idea:** SPL combines commands, functions, and operators to filter, transform, and analyze ingested log data. Filters only work on **parsed fields** — if data isn't parsed into fields yet, field-based operators won't match anything.

## Free Text Search

    index=windowslogs alice

Returns all events containing the keyword `alice` (case-insensitive), regardless of which field it appears in.

**When to use it:** you don't know the field names yet, or you're hunting for a unique string (a hash, a rare username, a suspicious domain). It's the fastest way to confirm "does this thing exist in my data at all?" before writing a precise query.

**When it fails you:** free-text can't distinguish `alice` the username from `alice` inside a filepath like `C:\Users\alice\`. For anything beyond a quick check, move to field-based filtering.

## Relational Operators

| Operator | Example | Meaning |
|---|---|---|
| `=` | `UserName=Mark` | Field equals value |
| `!=` | `UserName!=Mark` | Field does not equal value |
| `<` | `Age<10` | Less than |
| `<=` | `Age<=10` | Less than or equal to |
| `>` | `Outbound_Traffic>50` | Greater than |
| `>=` | `Outbound_Traffic>=50` | Greater than or equal to |

## Logical Operators

| Operator | Example | Meaning |
|---|---|---|
| `NOT` | `NOT UserName=*` | Returns events where the field **does not exist** |
| `AND` | `UserName=David AND IPAddress=10.10.10.10` | Both conditions must be true |
| `OR` | `UserName=David OR UserName=John` | Either condition true |
| `IN` | `UserName IN(David, John)` | Cleaner alternative to long OR chains |

### `NOT` vs `!=` — The Trap
These are **not** the same thing:
- `UserName!=Mark` → field exists, but its value isn't Mark
- `NOT UserName=Mark` → includes events where `UserName` doesn't exist at all

**Why this matters in an investigation:** if you hunt with `UserName!=admin` expecting "everything not done by admin," you silently drop every event that has no `UserName` field — which could be exactly where the suspicious activity is hiding. Missing events because of an operator choice is the kind of mistake that doesn't announce itself.

## Wildcards and CIDR

| Syntax | Example | Matches |
|---|---|---|
| `*` (mid-value) | `status=*fail*` | `failed`, `failure`, `appfail` |
| `*` (prefix) | `DestinationIp=172.*` | `172.90.0.0.1`, `172.18.5.22` |
| CIDR | `DestinationIp=172.18.0.0/16` | Any IP inside the `172.18.0.0/16` subnet |

**Prefer CIDR over wildcards for IPs.** `172.*` is sloppy — it string-matches, so it'll also catch things you didn't intend. CIDR does actual subnet math, which is what you actually mean when you say "traffic to our internal range."

## Quotes — Exact Phrases and Escaping

| Query | Behavior |
|---|---|
| `index=windowslogs failed login` | Events containing both `failed` and `login`, **any order** |
| `index=windowslogs "failed login"` | Exact phrase, **word order matters** |
| `index=windowslogs "TO BE OR NOT TO BE"` | Quotes escape the `OR`/`NOT` keywords so they're treated as literal text |

That third example is the key use: quotes stop Splunk from interpreting words like `OR`, `AND`, `NOT` as operators.

## Parentheses — Order of Evaluation

**`OR` is evaluated before `AND`** in Splunk. Without parentheses, your query may do something different from what you intended.

| Your Search | How Splunk Actually Evaluates It |
|---|---|
| `index=windowslogs alice AND bob OR charlie` | `alice AND (bob OR charlie)` ← **wrong**, not what you meant |
| `index=windowslogs (alice AND bob) OR charlie` | `(alice AND bob) OR charlie` ← **correct** |

**Practical rule:** any time you mix `AND` and `OR` in the same query, use explicit parentheses. Don't rely on remembering precedence — this bug is silent, your query runs fine and just returns the wrong result set, which is far worse than a syntax error that stops you.

---

# SPL Filtering Commands: fields, dedup, rename, regex

**Core idea:** Commands are chained with the pipe `|` — each pipe passes one command's output into the next, letting you refine results step by step instead of writing one monster query.

## fields — Include/Exclude Columns

    index=windowslogs | fields host User SourceIp

- Listing fields after `fields` **includes** only those fields (default behavior)
- `+` explicitly includes (optional, rarely needed)
- `-` **excludes**: `| fields - _raw` drops that field from results

**Why it matters:** Windows logs can carry hundreds of fields per event. Without `fields`, your results table is unreadable noise. Trimming to 3–5 relevant columns is usually the first thing you pipe after the base search.

**Performance bonus:** `fields` early in a pipeline also reduces the data Splunk carries through subsequent commands — not just a readability win.

## dedup — Remove Duplicate Values

    index=windowslogs
    | fields EventID User Image Hostname SourceIp
    | dedup SourceIp

Returns one event per unique value of the specified field. If `SourceIp` has 7 distinct IPs across 10,000 events, you get 7 rows.

**Real use cases:**
- Building a quick unique-asset/unique-IP list for an investigation
- Cleaning noisy sources — Microsoft 365 commonly emits ~50 near-identical events for a single user activity
- Subsearches, where you need a clean list of values to feed into another query

**Caution:** `dedup` keeps the *first* matching event and discards the rest. If you dedup before checking timestamps, you may throw away the event that actually mattered. Use it to enumerate values, not to summarize activity — for counting, `stats` is the correct tool.

## rename — Change Field Names

    index=windowslogs
    | fields EventID User Image Hostname SourceIp
    | rename User as Employee

**Two practical uses:**

1. **Readability in SOC reports** — raw field names are often long/cryptic and look bad in a screenshot pasted into a formal incident report.

2. **Flattening nested JSON/XML subfields.** A log like:

        {"request": {"path": "/admin", "ip": "10.0.0.2"}}

   becomes fields `request.path` and `request.ip` in Splunk. Strip the prefix with a wildcard rename:

        index=jsondata
        | rename request.* as *
        // request.path -> path ; request.ip -> ip

That wildcard rename is a genuine time-saver on deeply nested cloud/API logs where prefixes can be several levels deep.

## regex — Pattern-Based Filtering

    index=windowslogs | regex Image = "\.exe$"

Returns only events where the `Image` field **ends with** `.exe` (`$` anchors to end of string). Splunk regex is **PCRE** (Perl Compatible Regular Expressions, via the PCRE C library).

**When regex is irreplaceable:** custom or poorly-parsed data sources where fields weren't extracted properly, and format-based hunting where there's no fixed keyword to search — e.g. finding anything executing out of a temp directory, or matching a filename pattern rather than a specific filename.

**Cost warning:** `regex` filters *after* events are retrieved, so it's slower than narrowing with `index=`, field comparisons, or wildcards up front. Filter as much as possible with cheap operators first, then pipe to `regex` for the pattern work — never lead with it on a wide time range.

---

# SPL Structuring Commands: table, head/tail/sort/reverse, subsearches

**Core idea:** Once you've filtered results down, structuring commands control *how* you view them — as a clean table, a chronological timeline, or a correlated result across multiple log sources.

## table — Clean Column Display

    index=windowslogs | table _time EventID Hostname SourceName

Displays only the named fields in a readable table, ordered by the fields you list (not just filtering like `fields` — `table` is specifically about presentation/layout).

<img width="1915" height="585" alt="table command" src="https://github.com/user-attachments/assets/f0f77ec4-198d-4b31-9542-bdd2bd63a6d9" />

**Why use `table` over `fields`:** `fields` just trims which fields exist in the result set; `table` actually renders them as a formatted table and lets you control column order — critical when building a timeline where the sequence of columns tells the story (e.g. always put `_time` first).

## head / tail / sort / reverse

| Command | Example | Effect |
|---|---|---|
| `head` | `\| head 20` | First (newest) 20 events — speeds up search when you don't need everything |
| `tail` | `\| tail 20` | Last (oldest) 20 events |
| `sort` | `\| sort User` | Alphabetical sort by field |
| `reverse` | `\| reverse` | Flips current result order (e.g. newest-first → oldest-first) |

**Why `head`/`tail` matter for performance, not just display:** Splunk stops processing once it has enough results for `head` — so `| head 20` on a huge search can return dramatically faster than pulling the full result set and trimming client-side. Use it while iterating on a query before running the full unrestricted version.

## Building a Timeline with table + reverse

    index=windowslogs Hostname=Salena.Adam
    | table _time Hostname EventID Category
    | reverse

Splunk returns newest-first by default — `reverse` flips it to **chronological order**, which is what you actually want when reconstructing "what happened, in what sequence" on a host during an investigation.

**Practical habit:** any time you're building an attack timeline (like the perimeter-logs investigation earlier), reach for `table ... | reverse` immediately — chronological order is non-negotiable for timeline reconstruction, and it's a one-command fix if you forget it.

## Subsearches — Correlating Across Data Sources

**The problem:** Sysmon Process Creation (`EventID=1`) doesn't include `LogonType` or `IpAddress` — that context lives in the Security log's Logon event (`EventID=4624`). The two logs share a `LogonId` field, which is your join key.

    index=windowslogs EventID=1
    | join LogonId
        [ search index=windowslogs EventID=4624
        | rename TargetLogonId as LogonId
        | fields LogonId LogonType IpAddress]
    | table _time Image User LogonType IpAddress

**How it executes:**
1. Subsearch (in `[...]`) runs first — finds all `EventID=4624` logon events, renames `TargetLogonId` → `LogonId` to match Sysmon's field name, keeps only `LogonId`, `LogonType`, `IpAddress`
2. Main search runs — pulls all `EventID=1` process creation events
3. For each main-search event, Splunk matches its `LogonId` against the subsearch's saved tuples and enriches the row with `LogonType`/`IpAddress` if found

**Why this specific example matters practically:** this is exactly how you'd distinguish "process was launched via RDP session" (LogonType 10) vs. "process was launched by a Windows service" (LogonType 5) — a distinction you can't make from Sysmon alone. This pattern (enrich source A using source B via a shared ID field) is one of the most common real SOC correlation tasks, not just a Splunk trick.

---

# SPL Transforming Commands: top/rare, stats, chart, timechart, enrichment

**Core idea:** Transforming commands convert raw events into aggregated summaries — counts, statistics, visualizations — instead of reading events one by one.

## top / rare

| Command | Example | Returns |
|---|---|---|
| `top` | `\| top User limit=5` | Most frequent values |
| `rare` | `\| rare User limit=5` | Least frequent values |

- `top` = find your busiest user/host, baseline normal activity
- `rare` = find the outlier — a one-off login, a rarely-seen process
- Attackers usually show up as `rare`, not `top`

## highlight

    index=windowslogs | highlight User EventID Image "Process accessed"

- Visually marks specified values in raw log view
- Requires switching display: **List → Raw**
- Good for fast eyeball scanning before building a full query

## stats — Core Aggregation

| Function | Example | Purpose |
|---|---|---|
| Average | `stats avg(ProcessCount)` | Mean |
| Max | `stats max(Price)` | Highest |
| Min | `stats min(UserAge)` | Lowest |
| Sum | `stats sum(Cost)` | Total |
| Count | `stats count by SourceIp` | Occurrences per group |

    index=windowslogs | stats count by EventID | sort EventID

- Fastest way to see "what's actually in this dataset"
- Replaces subsearch+join in most cases — much better performance on large data
- The real workhorse command for investigations

## chart

    index=windowslogs | chart count by User

- Same functions as `stats`, formatted for visualization instead of raw table
- Use `chart` → next step is a graph
- Use `stats` → next step is more analysis

## timechart

    index=windowslogs Image!="" | timechart span=30m count by Image limit=5

- `Image!=""` — drops nulls first
- `span=30m` — buckets into 30-min intervals
- `limit=5` — top 5 values only

Why it matters:
- A flat count hides *when* something happened
- A sudden spike from 10 → 200 events/30min is invisible in a total, obvious on a timechart
- This is how you visually catch a brute-force burst or beaconing pattern

## iplocation — Geo-Enrichment

    index=windowslogs | iplocation SourceIp | stats count by Country

- Adds `City`, `Region`, `Country` via Splunk's built-in geo tables
- Piped into `stats count by Country` → instantly flags logins from countries with no legitimate business reason to appear
- Classic impossible-travel/geo-anomaly check

## lookup — External Data Enrichment

    index=windowslogs
    | lookup user_roles Hostname OUTPUT UserRole
    | stats count by Hostname UserRole

- Matches a field against an external CSV/lookup table
- Adds business context logs don't have on their own
- Example: turns "activity on WORKSTATION-60" into "activity on the Finance Director's laptop" — same log, very different urgency
- This is how asset-criticality tables (like the Initech one) get built into Splunk instead of living in a separate spreadsheet

## eval — Create/Modify Fields

    index=windowslogs
    | eval LogonTypeDesc = case(LogonType == 3, "Network Logon", LogonType == 5, "Service")
    | stats count by LogonType LogonTypeDesc

- `case()` maps numeric codes to readable labels
- Windows LogonType codes (2/3/4/5/7/8/9/10/11) are meaningless without translation
- `eval` bakes the translation into the query output — no separate lookup table needed for reports
- General use: any derived field — risk scores, flags, readable labels, string manipulation

---

# SPL Anomaly Detection: eventstats, where, statistical outliers

**Core idea:** Anomalies often don't show up in simple field statistics — you need per-user baselines and frequency math to catch a login that's rare *for that specific person*, even if it looks unremarkable in the raw aggregate.

## eventstats vs. stats

- `stats` — aggregates and collapses raw events into summary rows
- `eventstats` — calculates the same aggregates, but **keeps the original raw events**, adding the stat as a new field on each one
- `where` — like `search`, but supports more complex expressions/comparisons (needed for filtering on calculated fields like `country_freq`)

Why this distinction matters:
- You need the raw event still attached to its per-user stat so you can filter individual logins against a group-level baseline
- `stats` alone would just give you one row per user — losing the individual login you actually want to flag

## Detecting Outliers by Country

    index=vpnlogs
    | eventstats count as logins_by_user by user
    | eventstats count as logins_by_user_country by user src_country
    | eval country_freq=logins_by_user_country/logins_by_user
    | where country_freq < 0.1
    | table _time user src_ip src_country country_freq

| Line | What it does |
|---|---|
| 2 | Total logins per user (e.g. `kbrown` → 200) |
| 3 | Logins per user **per country** (e.g. `kbrown`+Austria → 1) |
| 4 | `country_freq` = how often that user logs in from that country |
| 5 | Keep only rare pairs — `country_freq < 0.1` is the sensitivity threshold |
| 6 | Table the outliers |

- A user logging in from a country once out of 200 logins = 0.5% frequency — far below the 10% threshold
- Out of 2,000 login events, only 2 outliers surfaced this way
- Threshold (0.1) is tunable — lower it to catch fewer/more-extreme outliers, raise it to be more sensitive

## Detecting Outliers by Hour

    index=vpnlogs
    | eval hour=tonumber(strftime(_time, "%H")) + tonumber(strftime(_time, "%M"))/60
    | eventstats avg(hour) as typical_hour stdev(hour) as stdev_hour by user
    | eval zscore=abs(hour - typical_hour) / stdev_hour
    | where zscore > 3
    | eval hour=round(hour, 2), typical_hour=round(typical_hour, 2)
    | eval stdev_hour=round(stdev_hour, 2), zscore=round(zscore, 2)
    | table _time user src_ip src_country hour typical_hour stdev_hour zscore
    | sort - hour_zscore

Key fields:
- `typical_hour` — average login hour for that user (e.g. 13:30 UTC)
- `stdev_hour` — how consistent that user's login time normally is (low = predictable)
- `zscore` — how many standard deviations the current login is from that user's norm

Why per-user baselining matters here:
- A flat "flag logins outside 9–5" rule breaks for night-shift or cross-timezone employees
- Per-user `typical_hour` + `stdev_hour` accounts for individual habits instead of one global rule
- `zscore > 3` = statistically rare for *that specific person*, regardless of what's normal company-wide
- Example: `jsmith` normally logs in ~13:30 with low deviation, but shows a login at 18:30 → high zscore, worth investigating

## ML, Impossible Travel, and Beyond

- Built on the same SPL foundations: `eval`, `eventstats`, `where`, statistical math
- Enriched further with `iplocation` (geo data) or `lookup` (threat intel feeds)
- Splunk's `fit`/`apply` commands let you train ML models on your data to improve outlier detection over time
- Impossible Travel detection (e.g. login from India, then Russia 10 minutes later) is this same pattern — baseline + deviation — just with geolocation/time-distance math added instead of frequency/hour math
