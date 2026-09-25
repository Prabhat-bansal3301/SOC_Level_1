# Man-in-the-Middle (MITM) Attacks

**Core idea:** Attacker secretly positions themselves between two communicating parties to intercept, modify, or redirect traffic — without either party knowing. Detection needs network monitoring + certificate validation + behavioral analysis together, not one signal alone.

## How MITM Works

1. **Interception** — attacker inserts into the communication stream, typically via ARP, DNS, or IP spoofing
2. **Manipulation/Decryption** — attacker reads or alters traffic, decrypts data, or injects malicious content (fake login forms, altered responses)

## Common Types

| Type | Description |
|---|---|
| Packet sniffing | Capturing unencrypted packets, often on open Wi-Fi |
| Session hijacking | Stealing/reusing session tokens to impersonate a user |
| SSL stripping | Downgrading HTTPS → HTTP to steal/alter data in transit |
| DNS spoofing | Redirecting traffic to fraudulent domains via manipulated DNS responses |
| IP spoofing | Crafting packets that appear to come from a trusted system |
| Rogue Wi-Fi AP | Fake network created to intercept user traffic |

## MITM and the Cyber Kill Chain

Seven phases:
1. Reconnaissance
2. Weaponization
3. Delivery
4. Exploitation
5. Installation
6. Command & Control (C2)
7. Actions on Objectives

MITM maps to two phases specifically:

- **As Exploitation** — abuses trust/design weaknesses in protocols (ARP, DNS) to intercept a channel; the interception itself violates network integrity and gives the attacker their initial foothold
- **As an Installation vector** — once positioned, the attacker can inject a browser exploit, malware dropper, or RAT into unencrypted traffic/downloads passing through them — establishing persistence

**Why this matters operationally:** catching a MITM in progress means you've caught an attacker mid-intrusion, before Actions on Objectives (exfil, destruction, lateral movement) — this is a genuine intervention point, not just an IoC to log.

---

