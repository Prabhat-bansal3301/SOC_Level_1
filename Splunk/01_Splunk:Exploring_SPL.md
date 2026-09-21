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

