# SOC Level 1

## My TryHackMe Blue-Team Learning Path

This repository documents my progress through the **SOC Level 1 path on
[TryHackMe](https://tryhackme.com/)**. It is not intended to be a collection
of disconnected notes. Each section represents a skill area I am building as
I work toward becoming a more effective junior security analyst.

The goal is to connect theory with investigation: understand how attacks work,
recognize the evidence they leave behind, investigate alerts with the right
tools, and communicate findings clearly.

> **Learning disclaimer:** These are personal study notes and investigation
> write-ups created while working through the path. They are not a replacement
> for the official TryHackMe rooms or documentation.

## What This Repository Covers

| Area | Focus |
| --- | --- |
| [Junior Security Analyst Intro](./Junior%20Security%20Analyst%20Intro) | SOC structure, analyst responsibilities, and common attack vectors |
| [Core SOC Solutions](./Core%20SOC%20Solutions) | EDR, SIEM platforms, Elastic Stack, and SOAR |
| [Cyber Defense Framework](./Cyber%20Defense%20Framework) | Pyramid of Pain, Cyber Kill Chain, Unified Kill Chain, MITRE ATT&CK, and Snort |
| [Windows Security Monitoring](./Windows%20Security%20Monitoring) | Windows logging, Sysmon, and threat detection |
| [Linux Security Monitoring](./Linux%20Security%20Monitoring) | Linux logs and Linux-based threat detection |
| [Network Traffic Analysis](./Network%20Traffic%20Analysis) | Wireshark, NetworkMiner, packet operations, and traffic analysis |
| [Network Security Monitoring](./Network%20Security%20Monitoring) | Network discovery, data exfiltration, MITM, and related detections |
| [SIEM Triage for SOC](./SIEM%20Triage%20for%20SOC) | Log analysis, alert triage, normalization, and benign activity |
| [Splunk](./Splunk) | SPL fundamentals and incident handling with Splunk |
| [Phishing Analysis](./Phishing%20Analysis) | Email artifacts, investigation workflow, tools, and prevention |
| [Threat Analysis Tools](./Threat%20Analysis%20Tools) | Threat intelligence for files, hashes, IPs, and domains |
| [Malware Concepts for SOC](./Malware%20Concepts%20for%20SOC) | Malware classification, analysis concepts, and living-off-the-land attacks |
| [Web Security Monitoring](./Web%20Security%20Monitoring) | Web attacks, web shells, and DDoS detection |
| [Team Internals](./Team%20Internals) | Alert triage, reporting, metrics, and analyst workbooks |
| [SOC Level 1 Capstone Challenges](./SOC%20Level%201%20Capstone%20Challenges) | End-to-end incident investigations and attack-chain reconstruction |
| [EXTRAS](./EXTRAS) | Supporting topics such as Windows events, regular expressions, TShark, Volatility, and malware fundamentals |

## Learning Progression

The folders are organized to follow the way a SOC analyst develops practical
skills:

1. **Understand the SOC** - Learn the junior analyst role, team structure, and
   the ways attackers use people and systems.
2. **Learn the defensive frameworks** - Use the Cyber Kill Chain, MITRE ATT&CK,
   and the Pyramid of Pain to describe and prioritize adversary activity.
3. **Read the evidence** - Build familiarity with Windows and Linux logs,
   Sysmon, network traffic, DNS, HTTP, and web application activity.
4. **Investigate alerts** - Practice SIEM searches, Splunk and Elastic triage,
   phishing analysis, threat intelligence, and endpoint investigation.
5. **Communicate the result** - Apply reporting, escalation, metrics, and
   analyst workbooks to turn technical findings into useful actions.
6. **Bring everything together** - Complete capstone investigations by building
   timelines, identifying indicators of compromise, and reconstructing attack
   chains.

## Investigation Skills Practiced

- Alert triage and severity assessment
- Log collection, normalization, filtering, and correlation
- Windows Event Log and Sysmon analysis
- Linux logging and threat detection
- Network packet and protocol analysis with Wireshark and TShark
- SIEM investigation with Splunk and Elastic
- Phishing email and header analysis
- File, hash, IP, and domain threat intelligence
- Malware behavior and living-off-the-land analysis
- MITRE ATT&CK technique mapping
- Timeline creation and attack-chain reconstruction
- IOC handling, including safe defanging
- Incident reporting and escalation

## Tools and Technologies

The notes include practical work with:

- Splunk
- Elastic Stack and Kibana
- Wireshark and TShark
- NetworkMiner
- Sysmon and Windows Event Logs
- Linux logging tools
- CyberChef
- VirusTotal and other threat intelligence sources
- Volatility
- Snort
- MITRE ATT&CK

## Capstone Investigations

The capstone section contains longer-form investigations instead of isolated
topic notes. These reports focus on:

- Establishing the scope of an incident
- Preserving and validating evidence
- Correlating endpoint, Windows, and network telemetry
- Identifying the initial access method
- Tracking execution, persistence, discovery, privilege escalation, and C2
- Extracting and safely documenting IOCs
- Mapping attacker behavior to a recognizable attack lifecycle

## How to Use This Repository

If you are following a similar path, start with **Junior Security Analyst
Intro**, then move through the monitoring, analysis, and triage sections.
Use the **EXTRAS** directory whenever a topic needs additional background.
Finish with the capstone challenges to practice combining multiple evidence
sources in one investigation.

The notes are most useful when paired with hands-on labs. Read a topic, repeat
the investigation yourself, and then compare your findings with the relevant
write-up.

## Repository Status

This is an actively evolving learning repository. New room notes, practical
investigations, and improvements to existing documentation may be added as I
continue my SOC Level 1 journey.
