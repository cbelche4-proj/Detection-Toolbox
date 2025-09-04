# Snort IDS Basics

Snort is a powerful open-source **Intrusion Detection System (IDS)** and Intrusion Prevention System (IPS.)
This repo provides a structured introduction to Snort, including setup, configuration and example rules, based on foundational training material


---

## 🔎 What is Snort?

- **Network-based IDS/IPS**: Monitors network traffic in real time.  
- **Modes of operation**:
  - **Sniffer Mode** → Displays packets on the console.  
  - **Packet Logger Mode** → Logs packets to files.  
  - **IDS/IPS Mode** → Analyzes traffic against rules and generates alerts (or blocks if IPS).  
- **Rule-driven**: Rules define what traffic to detect, alert, or drop.  
- **Widely used**: By enterprises, labs, and security professionals for learning and production defense.

# 📘 Snort Rule Types and Components

Snort uses a powerful rule-based detection engine. Rules are divided into **community/paid rule sets** and are written using a standard structure consisting of a **header** and **options**.

---

## 🔹 Community Rule Set
- **Free**: No cost or registration required.  
- **License**: Distributed under **GPLv2**.  
- **Daily Updates**: Rules are refreshed once per day.  
- **Subset of Subscriber Rules**: Contains a selection of rules found in the paid VRT set.  
- **Talos Certified**: Certified and maintained by Cisco’s Talos threat intelligence team.  

---

## 🔹 Subscriber Rule Set (VRT Ruleset)
- **Paid Subscription**: Requires an active subscription.  
- **Real-Time Access**: Subscribers get immediate access to new rules.  
- **Semi-Weekly Updates**: Updated **twice per week** (Tuesdays and Thursdays).  
- **Complete Coverage**: Full set of detection rules, including signatures for **emerging threats**.  

---

## ⚙️ Manual Rule Components

Snort rules are made up of two parts:  
1. **Rule Header** → Defines the action, protocol, IPs, ports, and traffic direction.  
2. **Rule Options** → Adds detailed logic for detection, classification, and response.  

---

### 🧩 Rule Header
The header sets the basic conditions for when a rule applies.

- **Action** → What Snort should do (e.g., `alert`, `block`, `drop`, `log`, `pass`).  
- **Protocol** → Protocol type (`tcp`, `udp`, `icmp`, `ip`).  
- **Source/Destination IPs** → IP addresses of the traffic (`any`, `$HOME_NET`, `$EXTERNAL_NET`).  
- **Source/Destination Ports** → Port numbers (`80`, `443`, `22`, or `any`).  
- **Direction Operator** → Traffic flow:
  - `->` one-way (source to destination)  
  - `<>` bidirectional  


📌 **Example Rule Header**:
alert tcp any any -> $HOME_NET 80

swift
Copy code
This triggers an alert on **any TCP traffic** from any IP/port going **to port 80 on HOME_NET**.

---

### 🧩 Rule Options
Options extend detection beyond headers and define what exactly Snort looks for.

- **General Options** → Metadata (e.g., `msg`, `sid`, `rev`, `classtype`).  
- **Payload Options** → Search for content inside the packet (e.g., `content`, `pcre`).  
- **Non-Payload Options** → Match on non-payload data (e.g., `ttl`, `flags`, `fragbits`).  
- **Post-Detection Options** → Specify actions after a match (e.g., `react`, `resp`).  

📌 **Example Full Rule**:
```snort
alert tcp any any -> $HOME_NET 80 (
    msg:"HTTP traffic detected"; 
    content:"GET"; 
    sid:1000001; 
    rev:1;
)

This rule alerts on HTTP GET requests targeting port 80 on the protected network.
