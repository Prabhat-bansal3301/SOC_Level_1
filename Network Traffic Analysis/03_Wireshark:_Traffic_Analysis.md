## Wireshark — Nmap Scan Detection

### TCP Flag Filters Reference

```wireshark
tcp.flags == 2              # SYN only
tcp.flags.syn == 1          # SYN set (other bits don't matter)

tcp.flags == 16             # ACK only
tcp.flags.ack == 1          # ACK set

tcp.flags == 18             # SYN + ACK
(tcp.flags.syn==1) and (tcp.flags.ack==1)

tcp.flags == 4              # RST only
tcp.flags.reset == 1        # RST set

tcp.flags == 20             # RST + ACK
(tcp.flags.reset==1) and (tcp.flags.ack==1)

tcp.flags == 1              # FIN only
tcp.flags.fin == 1          # FIN set
```

---

### TCP Connect Scan (`nmap -sT`)

**How it works:** Completes full 3-way handshake.
**Who uses it:** Non-privileged users (only option without root).
**Window size:** > 1024 bytes (expects data).

<img width="1566" height="318" alt="open tcp port" src="https://github.com/user-attachments/assets/b42ad2bb-ab87-4d5e-a5e6-4c1baa408c4a" />

<img width="1567" height="256" alt="closed tcp port" src="https://github.com/user-attachments/assets/1d7c76c9-6a1f-4fdf-90bf-7b71bb5f5c51" />

```
Open port:    SYN → | ← SYN,ACK | ACK →
Closed port:  SYN → | ← RST,ACK
```

**Detection filter:**

<img width="1561" height="415" alt="TCP Connect scan patterns" src="https://github.com/user-attachments/assets/2503a899-da17-4daa-ae62-2681ec35bdb7" />

```wireshark
tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024
```

---

### SYN Scan (`nmap -sS`)

**How it works:** Half-open scan — never completes handshake.
**Who uses it:** Privileged/root users only.
**Window size:** ≤ 1024 bytes (doesn't expect data).

<img width="1568" height="283" alt="Open TCP port (SYN)" src="https://github.com/user-attachments/assets/2f240b12-12ff-438d-8e8a-dc69d8c4d50f" />


<img width="1568" height="259" alt="Closed TCP port (SYN)" src="https://github.com/user-attachments/assets/70b68b7f-5f56-4671-b21d-af12e5ad3700" />

```
Open port:    SYN → | ← SYN,ACK | RST →
Closed port:  SYN → | ← RST,ACK
```

**Detection filter:**

<img width="1568" height="440" alt="TCP SYN scan patterns" src="https://github.com/user-attachments/assets/51220acd-6d4f-4c1e-b18a-9646f860055e" />

```wireshark
tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024
```

---

### UDP Scan (`nmap -sU`)

**How it works:** No handshake — sends UDP packet.
**Open port:** No response (silence = open).
**Closed port:** ICMP Type 3, Code 3 (Destination/Port Unreachable).

<img width="1568" height="275" alt="Closed (port no 69) and open (port no 68) UDP ports" src="https://github.com/user-attachments/assets/1094a1e5-abf6-4c1f-80d8-7525badc0d0a" />


```
Open port:    UDP → (no response)
Closed port:  UDP → | ← ICMP Type 3 Code 3
```

**Detection filter:**

<img width="1568" height="375" alt="UDP scan patterns" src="https://github.com/user-attachments/assets/976155a9-61fa-4510-8392-36d6fe99d4c9" />

```wireshark
icmp.type==3 and icmp.code==3
```

> ICMP error contains encapsulated original UDP request.
> Expand ICMP section in packet details → see original request details.

<img width="1565" height="1089" alt="encapsulated data and the original request" src="https://github.com/user-attachments/assets/011912be-d7ea-4ebc-b5da-022bb7d6db1e" />


---

### Scan Type Comparison

| | TCP Connect | SYN Scan | UDP Scan |
|-|-------------|----------|---------|
| **Command** | `nmap -sT` | `nmap -sS` | `nmap -sU` |
| **Handshake** | Full 3-way | Half (no ACK) | None |
| **Privileges** | Non-root OK | Root required | Root required |
| **Window size** | > 1024 | ≤ 1024 | N/A |
| **Open indicator** | SYN,ACK received | SYN,ACK received | No response |
| **Closed indicator** | RST,ACK | RST,ACK | ICMP Type 3 Code 3 |
| **Stealth** | Low | Medium | Medium |

---

### Quick Detection Summary

```wireshark
# TCP Connect Scan
tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024

# SYN Scan
tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024

# UDP Scan
icmp.type==3 and icmp.code==3

# General port scan (many SYNs, no established connections)
tcp.flags.syn==1 and tcp.flags.ack==0
```
