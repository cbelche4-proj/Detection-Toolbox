# Wireshark for Ethical Hacking & Network Analysis

Wireshark is the de-facto packet analyzer for blue teams, red teams, and troubleshooters. It lets you capture or open pcaps and surgically filter traffic to validate findings, hunt for IOCs, triage incidents, and understand protocols at the byte level.

> ⚠️ Legal/ethical note: Only capture or inspect traffic on networks/systems you’re authorized to test or defend.

---

## Why Wireshark matters (security use-cases)

- **Pentest & Red Team support:** Verify exploit behavior (handshakes, payload delivery), confirm egress paths, and prove impact with protocol-level evidence.  
- **Blue Team & IR:** Triage alerts, follow C2 flows, spot data exfil tactics (DNS, HTTP/S, TLS SNI), and reconstruct sessions (Follow Stream).  
- **Detection engineering:** Prototype rules and playbooks by observing actual field values (flags, headers, metadata) to build precise detections.  
- **Network troubleshooting:** Zero in on retransmissions, handshake failures, MTU issues, and misconfig (e.g., HTTPS on wrong ports).

---

## Capture vs. Display filters (quick contrast)

- **Capture filters** run **before** capture (BPF syntax, fewer operators). Great for reducing file size.  
- **Display filters** run **after** capture (Wireshark syntax, rich operators). Perfect for analysis.

Examples:
- Capture filter: `port 53`
<img width="1195" height="444" alt="capture filter" src="https://github.com/user-attachments/assets/df21b432-128f-4c31-b3ef-2b01f5fce6ac" />

  
- Display filter: `dns` or `dns.qry.name contains "example"`
<img width="938" height="319" alt="display filter" src="https://github.com/user-attachments/assets/0d01f4e5-02d3-466a-becd-fae19293d9a7" />

---

## Display filter operator cheat-sheet

### Logical (you can mix English & C-style)
- `and` / `&&` — both must be true  
- `or` / `||` — either can be true  
- `xor` / `^^` — exactly one is true  
- `not` / `!` — negation  
Use parentheses `()` to control precedence.

### Comparison & pattern
- `==`, `!=`, `>`, `<`, `>=`, `<=`
- `contains` — substring or byte sequence match  
- `matches` ( `~` ) — regex (PCRE)

### Membership & bitwise
- `in { … }` — set membership (supports ranges)  
  - Example: `tcp.port in {80 443 8080}`  
- `&` — bitwise AND for flags  
  - Example: `tcp.flags & 0x02` (SYN bit set)

### Helpful functions
- `len(field)` — length of a string/bytes field  
- `lower()/upper()` — case handling  
- `count(field)` — occurrences in a frame  
- `string(field)` — convert for regex

---

## Useful display filters (cookbook)

### 1) TCP handshakes, scans, and stability
```wireshark
# SYNs (connection attempts)
tcp.flags.syn == 1 and tcp.flags.ack == 0

# SYN+ACKs (server half of handshake)
tcp.flags.syn == 1 and tcp.flags.ack == 1

# Retransmissions (noisy/unstable links or blocked flows)
tcp.analysis.retransmission

# All TCP to/from common web ports
tcp.port in {80 443 8080}

# All HTTP requests
http.request

# Only GET requests
http.request.method == "GET"

# Only POST requests
http.request.method == "POST"

# Host header contains a domain (case-insensitive with lower())
lower(http.host) contains "example.com"

# Basic Auth credentials present (cleartext)
http.authorization or http.authbasic

# All TLS
tls

# ClientHello SNI (Server Name Indication) contains a domain
tls.handshake.extensions_server_name contains "example.com"

# TLS version or cipher checks (depends on pcap & TLS version)
tls.handshake.version
tls.handshake.ciphersuite

4) DNS (great for hunting C2 & exfil)
# All DNS
dns

# Queries for a specific FQDN
dns.qry.name == "malicious.example.com"

# Partial match / families
dns.qry.name contains "example"

# Regex on query name (e.g., multiple controlled domains)
dns.qry.name matches "(example|evil|test)\.com$"

5) ICMP / ARP (reachability & LAN issues)
# ICMP echo (ping)
icmp.type == 8 or icmp.type == 0

# ARP only
arp

# Duplicate IP detection (IP conflict symptoms)
arp.duplicate-address-detected or arp.duplicate-address-frame

6) Credentials & files in clear text (when protocols aren’t encrypted)
# FTP commands & arguments (watch for USER/PASS)
ftp.request or ftp.request.command or ftp.request.arg

# Telnet sessions (insecure)
telnet

# Export Objects (HTTP/SMB/etc.) via menu:
# File → Export Objects → (HTTP/SMB/…)
