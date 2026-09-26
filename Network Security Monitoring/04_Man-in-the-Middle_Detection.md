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

---

# ARP Spoofing (MITM)

**Core idea:** ARP has zero authentication — any device can claim to own any IP. Attackers abuse this to make victims send their traffic straight through the attacker's machine.

## ARP Basics

- Maps IP addresses → MAC addresses on a local network
- Device asks "who has this IP?" (`who-has`), owner replies with its MAC (`is-at`)

## How ARP Spoofing Works

- Attacker sends fake ARP replies claiming to own an IP — usually the **default gateway**
- No authentication exists, so any device can send unsolicited `is-at` messages
- Example: attacker broadcasts `192.168.10.100 is at 02:fe:BB:cd:55:55` while claiming to be the gateway
- Result: victim's ARP cache is poisoned → gateway-bound traffic flows through the attacker first (MITM)

## Indicators of Attack

- Duplicate MAC-to-IP mappings — multiple MACs claiming the same IP
- Unsolicited ARP replies (gratuitous ARP) — replies with no matching request
- Abnormal ARP traffic volume in short intervals
- Traffic unexpectedly routed through the attacker's MAC
- Multiple destination MACs for the same gateway IP
- ARP probe/reply loops — repeated `who-has` patterns

## Network Info (This Case)

| Role | IP | Notes |
|---|---|---|
| Gateway | 192.168.10.1 | Legitimate router |
| Attacker | — | Identified via investigation |
| Victim | — | Identified via investigation |
| Domain | corp-login.acme-corp.local | |

## Investigating via Wireshark

Target file: `network-traffic.pcap`

**Tip:** Ctrl+Alt+1 fixes the displayed time format.

| Filter | Purpose |
|---|---|
| `arp` | All ARP traffic — baseline view |
| `arp.opcode == 1` | ARP requests (`who-has`) only |
| `arp.opcode == 2` | ARP responses (`is-at`) only — check for gratuitous/unsolicited ones |
| `arp.isgratuitous` | Isolate gratuitous (unsolicited) ARP replies directly |
| `arp && arp.src.proto_ipv4 == 192.168.10.1 && eth.src == 02:aa:bb:cc:00:01` | ARP traffic tied to the legitimate gateway's known IP+MAC |
| `arp.opcode == 2 && arp.src.proto_ipv4 == 192.168.10.1` | All replies claiming to be the gateway — reveals multiple MACs for one IP |
| `arp.opcode == 2 && _ws.col.info contains "192.168.10.1 is at"` | Confirms which MAC(s) are claiming the gateway's IP |
| `arp.opcode == 2 && arp.src.proto_ipv4 == 192.168.10.1 && eth.src == 02:fe[ATTACKER_MAC]` | Confirms attacker MAC specifically spoofing the gateway |
| `arp.duplicate-address-detected \|\| arp.duplicate-address-frame` | Wireshark's built-in duplicate-IP detection — final confirmation |

## Investigation Logic

1. Baseline all ARP traffic → note volume/pattern
2. Split into requests vs. responses — gratuitous responses are the strongest single tell
3. Anchor on the known-good gateway IP/MAC to spot impersonators
4. Confirm: multiple MACs claiming the same gateway IP = spoofing confirmed
5. Cross-check with Wireshark's native duplicate-address detection as final confirmation

---

# SSL Stripping

**Core idea:** Attacker sits in the traffic path and removes TLS between victim and server. Attacker keeps a real HTTPS session with the actual server, but relays plain HTTP to the victim — victim types credentials into what looks like a normal page, but it's plaintext.

## How It Works

1. Victim initiates an HTTPS request
2. Attacker intercepts (via ARP spoofing or a rogue AP)
3. Attacker connects to the real site over HTTPS, but relays the response to the victim over HTTP
4. Victim unknowingly interacts entirely in plaintext

## Indicators of SSL Stripping

- Request starts as HTTPS (443), but subsequent packets for the same domain shift to HTTP (80)
- Persistent redirects (301/302) pushing an HTTPS request back to an HTTP resource
- TLS handshake failures or self-signed certs, if the attacker proxies more directly

## Investigating via Wireshark

Target: same `network-traffic.pcap` as the ARP spoofing case (this is one continuous attack chain).

| Filter | Purpose |
|---|---|
| `tls \|\| ssl` | Isolate all SSL/TLS traffic — baseline |
| `tls.handshake.type == 1 && tls.handshake.extensions_server_name == "corp-login.acme-corp.local"` | Confirms the domain normally uses TLS |
| `dns.flags.response == 1 && ip.src == 192.168.10.55 && dns.qry.name == "corp-login.acme-corp.local"` | Confirms attacker sent spoofed DNS responses pointing the domain to their own IP |
| `http && ip.src == 192.168.10.10 && ip.dst == 192.168.10.55` | Shows plaintext HTTP traffic (including credentials) between victim and attacker |

## What Confirms the Attack

- Domain normally does TLS (confirmed via handshake filter)
- Attacker's IP sent forged DNS responses redirecting the domain
- After the spoof, **no TLS handshake occurs** to the real server — traffic drops straight to HTTP
- Credentials observed in cleartext HTTP POST — direct proof of capture

## Full Attack Chain (Correlating All Three Notes)

1. **ARP Spoofing** — attacker sends unsolicited `is-at` claiming the gateway IP, poisoning the victim's ARP cache
2. **DNS Spoofing** — victim's DNS query for the target domain gets a forged response pointing to the attacker's IP
3. **SSL Stripping** — victim connects to that IP over HTTP instead of HTTPS; attacker relays to the real server over HTTPS, captures credentials in plaintext along the way

**Why this matters as a chain, not three separate techniques:** each stage enables the next. ARP spoofing gets the attacker in the traffic path; DNS spoofing gets the victim to send the attacker a request to hijack; SSL stripping is what turns that hijacked request into stolen credentials. Same pivot-and-correlate investigative pattern as the earlier perimeter-log walkthrough — one anchor (a known IP, a known domain) at a time.
