# TShark: Command-Line Packet Analysis Basics

TShark is the text-based version of Wireshark. It suits data carving, in-depth packet analysis, and scripting, because its output can be piped into other tools.

## Helper Tools

| Tool | Purpose |
|---|---|
| `capinfos` | Details of a capture file; view the summary **before** investigating |
| `grep` | Search plain-text data |
| `cut` | Cut parts of lines from a data source |
| `uniq` | Filter repeated lines or values |
| `nl` | Number the lines shown |
| `sed` | Stream editor |
| `awk` | Scripting language for pattern search and processing |

- Usage examples are in the Zeek room (link in the source)
- Practice files: `cd Desktop/exercise-files/`

## capinfos

    capinfos demo.pcapng

| Field | Example value | Why it matters |
|---|---|---|
| File type / encapsulation | pcap, Ethernet | Confirms the format |
| Number of packets | 4... (cut off) | Size of the investigation |
| Capture duration | 30.39 seconds | Time window |
| First / last packet time | 2004-05-13 10:17:07 to 10:17:37 | Match against alert times |
| Data byte rate | 825 bytes/s | Traffic volume |
| Average packet size | 583.51 bytes | Quick sanity check |
| SHA256, SHA1, RIPEMD160 | hashes | Identify the capture file |
| Strict time order | True | Packets are in sequence |

- The SHA256 is useful for evidence handling: record it before analysis, as in the file hash note

## Common Parameters

| Parameter | Purpose | Example |
|---|---|---|
| `-h` | Help page | `tshark -h` |
| `-v` | Version info | `tshark -v` |
| `-D` | List sniffing interfaces | `tshark -D` |
| `-i` | Pick an interface for live capture | `tshark -i 1`, `tshark -i ens55` |
| (none) | Sniff like `tcpdump` | `tshark` |

- Learn the parameters so you keep control of the output and aren't flooded with detail
- Live sniffing and listing interfaces need **superuser** privileges (`sudo`)

## Version Check

    tshark -v

    TShark (Wireshark) 3 (Git v3. packaged as 3.)
    Copyright 1998-2020 Gerald Combs and contributors. License GPLv2+

## Sniffing

A host can have several interfaces, each tied to a task. Choosing the right one decides what traffic you see.

    sudo tshark -D

    1. ens5
    2. lo (Loopback)
    3. any
    4. bluetooth-monitor
    5. nflog

| Interface | Meaning |
|---|---|
| `ens5` | Main network card (interface 1) |
| `lo` | Loopback: traffic inside the host |
| `any` | All interfaces together (general knowledge) |
| `bluetooth-monitor` | Bluetooth traffic (general knowledge) |
| `nflog` | Netfilter/firewall log packets (general knowledge) |

### Default vs Chosen Interface

- No interface argument = `-i 1`, usually the first listed
- TShark prints the interface name at the start of a capture

    tshark
    Capturing on 'ens5'
    1  0.000000 aaa.aaa.aaa.aaa → bbb.bbb.bbb.bbb TCP 3372 → 80 [SYN] Seq=0 Win=8760 Len=0 MSS=1460 SACK_PERM=1
    2  0.911310 ... TCP 80 → 3372 [SYN, ACK] Seq=0 Ack=1 ...
    3  0.911310 ... TCP 3372 → 80 [ACK] Seq=1 Ack=1 ...
    100 packets captured

    tshark -i 2
    Capturing on 'Loopback: lo'

- The sample shows a TCP three-way handshake: `SYN`, `SYN-ACK`, `ACK` (see the TCP SYN scan note)
- IPs are masked (`aaa.aaa.aaa.aaa`) in the source
- The source shows `?` where the arrow `→` should be (an encoding issue); I restored the arrows

---

# TShark Parameters II: Reading, Writing, and Verbosity

These parameters let you read saved captures, cut out the packets that matter, and control how much detail you see.

## Parameters

| Parameter | Purpose | Example |
|---|---|---|
| `-r` | Read a capture file | `tshark -r demo.pcapng` |
| `-c` | Stop after a packet count (capturing, filtering, or reading) | `tshark -c 10` |
| `-w` | Write packets to a file | `tshark -w sample-capture.pcap` |
| `-V` | Verbose: full details per packet, like Wireshark's Packet Details pane | `tshark -V` |
| `-q` | Silent mode: hides packet output on the terminal | `tshark -q` |
| `-x` | Show packet bytes in hex and ASCII | `tshark -x` |

## Read Capture Files (`-r`, `-c`)

    tshark -r demo.pcapng
    tshark -r demo.pcapng -c 2

    1  0.000000 145.254.160.237 → 65.208.228.223 TCP 3372 → 80 [SYN] Seq=0 Win=8760 Len=0 MSS=1460 SACK_PERM=1
    2  0.911310 65.208.228.223 → 145.254.160.237 TCP 80 → 3372 [SYN, ACK] Seq=0 Ack=1 Win=5840 Len=0 MSS=1380 SACK_PERM=1
    3  0.911310 145.254.160.237 → 65.208.228.223 TCP 3372 → 80 [ACK] Seq=1 Ack=1 Win=9660 Len=0

- `-c 2` shows only the first two packets
- The sample is a TCP three-way handshake between `145.254.160.237` (client, port 3372) and `65.208.228.223` (server, port 80)

## Write Data (`-w`)

    tshark -r demo.pcapng -c 1 -w write-demo.pcap
    ls
    demo.pcapng  write-demo.pcap
    tshark -r write-demo.pcap

- Reads the first packet of `demo.pcapng` and saves it to `write-demo.pcap`
- Use: separate specific packets from a big capture
- Use: share only the suspicious packets with higher-level investigators (see the evidence-handling point in the capinfos note)

## Show Packet Bytes (`-x`)

    tshark -r write-demo.pcap -x

    0000  fe ff 20 00 01 00 00 00 01 00 00 00 08 00 45 00   .. ...........E.
    0010  00 30 0f 41 40 00 80 06 91 eb 91 fe a0 ed 41 d0   .0.A@.........A.
    0020  e4 df 0d 2c 00 50 38 af fe 13 00 00 00 00 70 02   ...,.P8.......p.
    0030  22 38 c3 0c 00 00 02 04 05 b4 01 01 04 02         "8............

- Shows **every** packet in hex and ASCII, so anomalies are hard to spot at a glance
- Best used **after** reducing the number of packets (filter first, then `-x`)
- Left column = offset, middle = hex bytes, right = ASCII

## Verbosity (`-V`)

Default output is one line per packet, which makes it easy to follow the packet count. `-V` gives the full Packet Details view.

    tshark -r demo.pcapng -c 1 -V

    Frame 1: 62 bytes on wire (496 bits), 62 bytes captured (496 bits)
    Ethernet II, Src: 00:00:01:00:00:00, Dst: fe:ff:20:00:01:00
    Internet Protocol Version 4, Src: 145.254.160.237, Dst: 65.208.228.223
        0100 .... = Version: 4
        .... 0101 = Header Length: 20 bytes (5)
        Total Length: 48
        Identification: 0x0f41 (3905)
        Flags: 0x4000, Don't fragment
        Fragment offset: 0
        Time to live: 128
        Protocol: TCP (6)
        Source: 145.254.160.237
        Destination: 65.208.228.223
    Transmission Control Protocol, Src Port: 3372, Dst Port: 80, Seq: 0, Len: 0

- Long and complex per packet, so use it on **specific packets**, not a series
- Best after filtering
- Still valuable for in-depth analysis and **scripting, carving, and correlation**, which is where TShark stands out
- The source compares this to a Wireshark screenshot that wasn't included

## Reading the Hex Dump (general knowledge, not in the source)

| Bytes | Meaning |
|---|---|
| `08 00` | EtherType: IPv4 |
| `45` | IPv4, header length 20 bytes (matches the verbose output) |
| `00 30` | Total length 48 |
| `80` | TTL 128 |
| `06` | Protocol TCP |
| `0d 2c` / `00 50` | Source port 3372 / destination port 80 |
| `70 02` | TCP header length and the SYN flag |

- Ties the three views together: the hex, the one-line summary, and the verbose tree describe the same packet

## Workflow

| Step | Command |
|---|---|
| 1. Summarise the capture | `capinfos demo.pcapng` |
| 2. Skim the first packets | `tshark -r demo.pcapng -c 10` |
| 3. Isolate what matters, save it | `tshark -r demo.pcapng -c 1 -w out.pcap` |
| 4. Inspect in depth | `tshark -r out.pcap -V` or `-x` |

---

# TShark Capture Conditions: Autostop (`-a`) and Ring Buffer (`-b`)

These parameters control **live captures**: when to stop, and how to split the output into files.

## Parameters

| Option | Mode | Behaviour |
|---|---|---|
| `-a` | **Autostop** | Define conditions for a single run; **stops** when a condition is met |
| `-b` | **Ring buffer** | Define conditions for multiple runs/loops; **infinite loop** |

### Autostop (`-a`)

| Condition | Purpose | Example |
|---|---|---|
| `duration` | Stop after X seconds | `tshark -w test.pcap -a duration:1` |
| `filesize` | Stop after the file reaches X KB | `tshark -w test.pcap -a filesize:10` |
| `files` | Stop after X output files | `tshark -w test.pcap -a filesize:10 -a files:3` |

### Ring Buffer (`-b`)

| Condition | Purpose | Example |
|---|---|---|
| `duration` | After X seconds, start a new file | `tshark -w test.pcap -b duration:1` |
| `filesize` | After X KB, start a new file | `tshark -w test.pcap -b filesize:10` |
| `files` | Keep at most X files; **overwrite the oldest** | `tshark -w test.pcap -b filesize:10 -b files:3` |

- `-a files` **stops** after X files; `-b files` **rotates** and overwrites the oldest

## Rules and Cautions

- These only work in **capture mode**; using them with `-r` (reading a file) gives an error
- Purpose: save live captures in controlled sizes for different uses
- To pull packets out of an existing capture, use the read and write options (`-r`, `-w`)
- You can combine `-a` and `-b`
- Ring buffer runs forever, so use **at least one autostop** (`-a`) condition to end it
- Use infinite-loop options carefully

## Sample: Autostop With Multiple Files

    tshark -w autostop-demo.pcap -a duration:2 -a filesize:5 -a files:5

    Capturing on 'ens5'
    13

    ls
    autostop-demo_..1_2022.pcap
    autostop-demo_..2_2022.pcap
    autostop-demo_..3_2022.pcap
    autostop-demo_..4_2022.pcap
    autostop-demo_..5_2022.pcap

| Part | Meaning |
|---|---|
| `-w autostop-demo.pcap` | Output file base name |
| `-a duration:2` | Stop after 2 seconds |
| `-a filesize:5` | Each file up to 5 KB |
| `-a files:5` | Stop after 5 files |

- The `13` is the packet count shown during capture
- File names get a number and timestamp added automatically
- Capture ends at whichever condition is met **first**

## When to Use Which

| Goal | Use |
|---|---|
| One quick sample, then stop | `-a duration:N` |
| Cap the total size of evidence | `-a filesize:N` |
| Continuous monitoring without filling the disk | `-b filesize:N -b files:M` (keeps the latest M files) |
| Monitor for a fixed window, split into chunks | `-a duration:N` with `-b filesize:M` |

---

# TShark Packet Filtering: Capture (`-f`) vs Display (`-Y`)

TShark filters traffic in two places: **while capturing** and **after capturing**. Both use filter syntax you may know from Wireshark.

## Two Filter Types

| | Capture filter | Display filter |
|---|---|---|
| When | Live, **before and during** capture | **After** capture |
| Purpose | Save only a specific part of the traffic | Investigate by reducing the visible packets |
| Changeable? | **No**, fixed once capture starts | **Yes**, change it anytime while investigating |
| Syntax | BPF (Berkeley Packet Filter) | Wireshark display filter syntax |
| Power | Limited: scope by **range, protocol, direction** | In-depth, many protocol fields |
| Effect on packets | Dropped packets are never saved | Packets aren't modified or deleted |
| TShark parameter | `-f` | `-Y` |

## Parameters

| Parameter | Purpose | Syntax |
|---|---|---|
| `-f` | Capture filter | Same as BPF and Wireshark capture filters |
| `-Y` | Display filter | Same as Wireshark display filters |

## Capture Filters

- Keep a specific type of traffic in the capture file instead of everything
- Coarse filtering (range, protocol, direction), but gives organised capture files of reasonable size
- Dropped traffic is **lost for good**, so be careful with how narrow you go

## Display Filters

- Examine capture files in depth without changing the packets
- Fine-grained, so you can narrow down a big capture step by step

## Examples (general knowledge, not in the source)

| Goal | Command |
|---|---|
| Capture only traffic to or from one host | `tshark -f "host 10.10.10.10"` |
| Capture only port 80 | `tshark -f "tcp port 80"` |
| Capture only one network range | `tshark -f "net 192.168.1.0/24"` |
| Show only HTTP in a saved file | `tshark -r demo.pcapng -Y "http"` |
| Show only SYN packets | `tshark -r demo.pcapng -Y "tcp.flags.syn == 1"` |
| Show only DNS queries | `tshark -r demo.pcapng -Y "dns.flags.response == 0"` |

## When to Use Which

| Situation | Use |
|---|---|
| Disk space is limited, long capture needed | `-f` to keep only relevant traffic |
| Unsure what you'll need later | Capture broadly, then use `-Y` (you can't recover what `-f` dropped) |
| Investigating a saved file | `-Y`, or the Wireshark filters from the earlier notes (`dns`, `http`, `arp.opcode == 2`) |

- `-f` filters at capture time and so works only in capture mode (like `-a` and `-b` in the previous note)
- The display filters used in the earlier Wireshark notes work with `-Y` unchanged

---

# TShark Capture Filters (`-f`) in Practice

Capture filters use BPF syntax, set **before** capture starts. Filters combine three qualifier types, and Boolean operators (`and`, `or`, `not`) work too.

## Qualifiers

| Qualifier | Options | Default if omitted |
|---|---|---|
| **Type** | `host`, `net`, `port`, `portrange` | `host` |
| **Direction** | `src`, `dst` | Either direction (both) |
| **Protocol** | `arp`, `ether`, `icmp`, `ip`, `ip6`, `tcp`, `udp` | All |

### Type

| Goal | Command |
|---|---|
| Host | `tshark -f "host 10.10.10.10"` |
| Network range | `tshark -f "net 10.10.10.0/24"` |
| Port | `tshark -f "port 80"` |
| Port range | `tshark -f "portrange 80-100"` |

### Direction

| Goal | Command |
|---|---|
| Source address | `tshark -f "src host 10.10.10.10"` |
| Destination address | `tshark -f "dst host 10.10.10.10"` |

### Protocol

| Goal | Command |
|---|---|
| TCP | `tshark -f "tcp"` |
| MAC address | `tshark -f "ether host F8:DB:C5:A2:5D:81"` |
| IP protocol number (ICMP = 1) | `tshark -f "ip proto 1"` |

- IP protocol numbers are assigned by IANA (the Assigned Internet Protocol Numbers list)
- Combine them: `tshark -f "tcp and src host 10.10.10.10 and port 80"` (general knowledge, not in the source)

## Practising With Two Terminals

Use `terminator` for a split-screen terminal:

1. **Terminal-1:** start sniffing
2. **Terminal-2:** create traffic
3. Watch the packets in Terminal-1

### Example

Terminal-1:

    tshark -f "host 10.10.10.10"
    Capturing on 'ens5'
    1  0.000000000 YOUR-IP → 10.10.10.10  TCP 74 36150 → 80 [SYN] Seq=0 Win=62727 Len=0 MSS=8961 ...
    2  0.003452830 10.10.10.10 → YOUR-IP  TCP 74 80 → 36150 [SYN, ACK] Seq=0 Ack=1 ...
    3  0.003487830 YOUR-IP → 10.10.10.10  TCP 66 36150 → 80 [ACK] Seq=1 Ack=1 ...
    4  0.003610800 YOUR-IP → 10.10.10.10  HTTP 141 GET / HTTP/1.1

Terminal-2:

    curl -v 10.10.10.10

    > GET / HTTP/1.1
    > Host: 10.10.10.10
    > User-Agent: curl/7.68.0
    < HTTP/1.1 200 OK
    < Content-Length: 1220
    < Content-Type: text/html; charset=utf-8

- The capture shows the TCP handshake (`SYN`, `SYN-ACK`, `ACK`), then the HTTP `GET /`
- The `curl` output shows the same request and the `200 OK` response from the client side
- The capture filter kept only traffic involving `10.10.10.10`

## Practice Table

| Category | Generate traffic | Capture filter |
|---|---|---|
| Host | `curl tryhackme.com` | `tshark -f "host tryhackme.com"` |
| IP | `nc 10.10.10.10 4444 -vw 5` | `tshark -f "host 10.10.10.10"` |
| Port | `nc 10.10.10.10 4444 -vw 5` | `tshark -f "port 4444"` |
| Protocol | `nc -u 10.10.10.10 4444 -vw 5` | `tshark -f "udp"` |

Netcat options:
- `-v`: verbose
- `-w 5`: 5-second timeout
- `-u`: UDP instead of TCP

- Port `4444` is the Metasploit default seen in earlier notes; here it is just a practice port
- Practise until the filters feel natural: comfort with the command line comes with repetition

---

# TShark Display Filters (`-Y`) in Practice

Display filters use Wireshark's filter syntax and run on a **saved capture** (or while reading it). Boolean operators work here too. References: the official Display Filter Reference, and Wireshark's built-in "Display Filter Expression" menu, which breaks protocols into fields.

- Use **single quotes** around filters to avoid space and Bash expansion problems (the source says "capture filters" here, but it means filters in general)

## Common Display Filters

| Protocol | Goal | Command |
|---|---|---|
| IP | Either direction | `tshark -Y 'ip.addr == 10.10.10.10'` |
| IP | Network range | `tshark -Y 'ip.addr == 10.10.10.0/24'` |
| IP | Source IP | `tshark -Y 'ip.src == 10.10.10.10'` |
| IP | Destination IP | `tshark -Y 'ip.dst == 10.10.10.10'` |
| TCP | Port | `tshark -Y 'tcp.port == 80'` |
| TCP | Source port | `tshark -Y 'tcp.srcport == 80'` |
| HTTP | All HTTP | `tshark -Y 'http'` |
| HTTP | Response code 200 | `tshark -Y "http.response.code == 200"` |
| DNS | All DNS | `tshark -Y 'dns'` |
| DNS | "A" queries | `tshark -Y 'dns.qry.type == 1'` |

- Practice file: `demo.pcapng`

## Sample 1: IP Filter

    tshark -r demo.pcapng -Y 'ip.addr == 145.253.2.203'

    13  2.55  145.254.160.237 → 145.253.2.203  DNS Standard query 0x0023 A ..
    17  2.91  145.253.2.203 → 145.254.160.237  DNS Standard query response 0x0023 A ..

- Two matches: a DNS query and its response (a pair, same transaction ID `0x0023`)
- The numbers are `13` and `17`, not `1` and `2`

## Packet Numbers vs Match Count

- TShark **doesn't count** the filtered packets
- Each packet keeps the number from its position in the capture; only the matching ones are shown
- With more than a handful of matches, counting from these numbers gets confusing

### Sample 2: HTTP Filter

    tshark -r demo.pcapng -Y 'http'

    4   0.911  145.254.160.237 → 65.208.228.223  HTTP GET /download.html HTTP/1.1
    18  2.984  145.254.160.237 → 216.239.59.99   HTTP GET /pagead/ads?client...
    27  3.955  216.239.59.99 → 145.254.160.237   HTTP HTTP/1.1 200 OK (text/html)
    38  4.846  65.208.228.223 → 145.254.160.237  HTTP/XML HTTP/1.1 200 OK

### Count With `nl`

    tshark -r demo.pcapng -Y 'http' | nl

    1   4   0.911  145.254.160.237 → 65.208.228.223  HTTP GET /download.html HTTP/1.1
    2   18  2.984  145.254.160.237 → 216.239.59.99   HTTP GET /pagead/ads?client...
    3   27  3.955  216.239.59.99 → 145.254.160.237   HTTP HTTP/1.1 200 OK (text/html)
    4   38  4.846  65.208.228.223 → 145.254.160.237  HTTP/XML HTTP/1.1 200 OK

- `nl` adds its own line numbers in the first column
- The last `nl` number is the **total number of matched packets** (4 here)
- The second column is still the original packet number

## Capture vs Display Filter Syntax

| Goal | Capture filter (`-f`) | Display filter (`-Y`) |
|---|---|---|
| One host | `host 10.10.10.10` | `ip.addr == 10.10.10.10` |
| Source host | `src host 10.10.10.10` | `ip.src == 10.10.10.10` |
| Network range | `net 10.10.10.0/24` | `ip.addr == 10.10.10.0/24` |
| Port | `port 80` | `tcp.port == 80` |

- Capture filters use **BPF words**; display filters use **field names with `==`**
- Mixing them up gives an error, which is the most common beginner mistake (general knowledge)


