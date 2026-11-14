# Filepath and Filename Analysis

Human-readable strings like file paths and names are the earliest heuristics an analyst has on a suspicious file (e.g. `Setup.exe`). On their own they don't prove maliciousness, but they reveal attacker tradecraft when viewed with scepticism.

## Filepath Analysis

Paths and names are like crime scene clues. Attackers pick disk locations to hide actions and reduce visibility.

| Path | Why attackers use it |
|---|---|
| `C:\` (system drive root) | Common target for persistence mechanisms |
| `C:\Users\Public` | Lets other users access the detonated tool (cross-user access) |
| `C:\Users\Public\Public Downloads` | High-traffic folder that often escapes strict monitoring |

### Other Staging Patterns

| Path | Use |
|---|---|
| `C:\Windows\Temp\` | Temporary directory for ephemeral payloads |
| `C:\ProgramData\` | Writable system path for stealthy persistence |

- Seen in earlier notes: `C:\ProgramData\r.exe` (LNK payload), `C:\Users\Public\payload.exe` (BAT downloader), `C:\Temp` (Collection staging)

## Filename Heuristic Indicators

Attackers alter filenames to escape detection:

| Technique | Example | How it works |
|---|---|---|
| Double extension | `invoice.pdf.exe` | Windows hides known extensions by default, so it looks like a PDF |
| System binary impersonation | `scvhost.exe` | Abuses familiarity with core process names |
| High-entropy string | `jh8F21.exe` | Suggests automated packing or polymorphic generation, common in high-churn phishing |
| Masquerading | `backup-2300.exe` | Blends in with routine files; also single-character substitution that looks legitimate |

- Defender tip from the source: allowlist the **legitimate locations** of system processes, not standalone filenames (a name alone is easy to fake)
- Always flag and investigate alerts with these characteristics

## Quick Triage Questions

| Check | Question |
|---|---|
| Path | Is it running from `Public`, `Temp`, `ProgramData`, or `Downloads`? |
| Extension | Is there a double extension? |
| Name | Is it a near-miss of a system binary? |
| Randomness | Does the name look machine-generated? |

---

# File Hashes and VirusTotal Analysis

Filename and path analysis is inconclusive because attackers constantly rename files. A **file hash** is a cryptographic fingerprint that identifies the same binary whatever it is called, so it is an immutable, actionable identifier (SHA256 and MD5 are the common ones).

- Work with potentially malicious binaries only in an isolated environment (see the malware analysis safety note)

## Generating a Hash

| Platform | Command |
|---|---|
| Windows (CMD) | `certutil -hashfile bl0gger.exe SHA256` |
| Windows (PowerShell) | `Get-FileHash -Algorithm SHA256 bl0gger.exe` |
| Linux | `sha256sum bl0gger.exe` |

- Swap `SHA256` for `MD5` in the Windows commands, or use `md5sum` on Linux, to get an MD5

## Hash Handling Tips

- Store hashes in **lowercase**, to avoid needless mismatches
  - `Get-FileHash` prints uppercase, so convert before comparing (general knowledge)
- Hash what matters: if malware sits in a ZIP, hash **both** the archive and the extracted binary
- Never keep a bare hash string: note **where and when** you found it
- **Any byte change** produces a completely different hash

## VirusTotal Analysis

[VirusTotal](https://www.virustotal.com/) aggregates scan results from dozens of antivirus vendors into one report. In a production SOC, searching the hash there is the usual next step.

| Item | What it tells you |
|---|---|
| Detection score | Crowdsourced verdict shown as a ratio; higher means higher confidence it is a threat |
| Threat labels and categories | Vendor classifications; agreement across vendors helps confirm attribution |
| Detection rules | Signatures AV engines use: YARA rules, heuristic patterns, behavioural triggers |
| Properties | File metadata: type, size, compilation timestamp |
| Contained domains and IPs | The malware's network infrastructure |
| Contained files | Files embedded in the sample or dropped when it runs |

- The domains, IPs, and dropped files give you new indicators to pivot on (see the CTI notes)

---
# Dynamic Analysis with Sandboxes

Static properties (hashes, strings, sections) tell you a file's identity. To see its **impact**, you run it safely in a controlled environment. A sandbox is a disposable, instrumented VM that records every process, registry write, and network packet the malware causes.

## What Analysts Use Sandboxes For

| Goal | Why |
|---|---|
| Confirm execution | If nothing happens, the alert may be a decoy |
| Extract runtime IOCs | Domains, mutexes, dropped payloads, for feed hunts and detections |
| Map to ATT&CK | Most sandboxes auto-label behaviour with technique IDs, which speeds up reporting |

- **L1 role:** use the sandbox's lookup feature to find information about a hash
- **Senior analysts:** run the more sophisticated detonation and analysis tasks

## Sandboxing Tools

| Tool | Strength | Best for |
|---|---|---|
| Hybrid Analysis (HA) | Behaviour trees, clean MITRE ATT&CK heatmap | Fast executive summary |
| Joe Sandbox (JS) | Deep detail: system calls, strings, memory dumps | Reverse engineers and detection engineers |

- Other sandboxes mentioned earlier in this series: Any.Run (CTI notes)

## Reading a Hybrid Analysis Report

- Search by **file hash**, then read the generated report
- In the lesson's example the file is confirmed malicious, with a threat score of **100/100**
- The report also lists the file's risky behaviours and the ATT&CK techniques observed
- The lesson's screenshots and the "TryDetectThis" lab ingest weren't included in the paste

## Sandboxing Limitations

Trusting sandbox results blindly leads to false negatives, missed detections, or wrong conclusions.

### 1. Sandbox Evasion

Attackers build payloads that detect and avoid sandboxes.

- **Environment awareness checks:** malware looks for signs of a virtual or sandboxed environment
- **Anti-debugging and anti-sandboxing:** debugger detection, checks for unique hardware IDs
- In practice malware shows a benign path, as covered in the malware analysis note

### 2. Limited Execution Time and Coverage

- Most sandboxes stop after **2 to 5 minutes**
- Multi-stage malware may not fully run
- Time-delayed attacks escape detection
- Cross-reference other threat intel sources

### 3. Encrypted and Obfuscated Traffic

- Many sandboxes can't decrypt SSL/TLS, creating blind spots
- HTTPS C2 shows up with no visible payload
- Malware may hide data in DNS queries (DNS tunnelling, see the exfiltration notes)

### 4. Fileless and Living-off-the-Land Malware

- Some threats never touch disk, so traditional sandbox analysis misses them
- Examples: PowerShell attacks, WMI persistence (see the LOTL note)

## Limitations Summary

| Limitation | Result | What to do |
|---|---|---|
| Evasion | Clean report on malicious file | Treat "clean" as inconclusive; check static and intel |
| Short runtime | Late stages never seen | Look for sleep or delay behaviour, cross-check other sources |
| Encrypted traffic | Hidden C2 content | Use network logs and metadata (domains, ports, timing) |
| Fileless | Little to analyse | Use endpoint logs (Sysmon, PowerShell history) |
