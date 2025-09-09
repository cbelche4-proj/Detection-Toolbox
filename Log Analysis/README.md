# Log Analysis (Beginner-Friendly Guide)

Log analysis is the process of turning machine-generated events (from devices, applications, and systems) into answers—**what happened, when, where, and why**—so you can monitor health and detect security incidents.

## Why it matters
- **Security & IR:** Spot suspicious activity (e.g., brute force → privilege change) and reconstruct incidents.
- **Operations & Reliability:** Find errors and performance issues before they become outages.
- **Compliance:** Produce auditable records for frameworks like GDPR, HIPAA, PCI DSS.

## Core ideas (fast)
- **Timeline:** A chronological view of events. Essential for incident reconstruction and understanding attacker TTPs.
- **Timestamps & Time Zones:** Standardize to a single zone (usually **UTC**) to correlate across sources. Many SIEMs (e.g., Splunk) normalize event time at index/search (e.g., UNIX epoch in `_time`) and let you **display** in local time.
- **Super Timelines:** Consolidate events from many sources (system, app, firewall, network, cloud) into one view to reveal cross-system patterns. Tools like **Plaso (log2timeline)** can parse diverse artifacts and build unified timelines.

## Typical workflow
**Collect → Parse/Normalize → Enrich → Store → Query/Correlate → Visualize → Alert → Investigate → Improve**
- **Parse/Normalize:** Convert raw text/JSON into fields (e.g., `user`, `src_ip`, `action`).
- **Enrich:** Add GeoIP, asset owner, user role, or threat-intel context.
- **Correlate:** Join identity, endpoint, and network data to tell a full story.

## Visualization & Dashboards
Tools like **Splunk** and **Kibana** turn indexed logs into charts and dashboards.
- Example objective: *“Track failed logins over 7 days and flag spikes.”*
- Start with a **line chart** (failed logins per hour/day), then break down by `user` or `src_ip` to find anomalies.

## Monitoring & Alerting
Create alerts for high-risk behaviors:
- Multiple failed logins followed by a success  
- New admin creation / privilege escalation  
- Access to sensitive files or unusual egress behavior  
Define **escalation paths** so the right people are notified quickly.

## Threat Intel (what to look for)
Threat intelligence are attributes tied to malicious activity:
- **IP addresses**, **domains**, **file hashes**, **URLs**, **TTPs**  
Use TI to prioritize events and add context to detections and hunts.

## What are logs?
Logs are recorded events (errors, auth attempts, network connections, API calls, etc.). Each entry typically includes a **timestamp**, **source**, **severity**, and event-specific fields.

**Example (`sample.log`):**
Jul 28 17:45:02 10.10.0.4 FW-1: %WARNING% general: Unusual network activity detected from IP 10.10.0.15 to IP 203.0.113.25. Source Zone: Internal, Destination Zone: External, Application: web-browsing, Action: Alert.

markdown
Copy code
Key fields:
- `Jul 28 17:45:02` – when it happened  
- `10.10.0.4` – device generating the log  
- `%WARNING%` – severity  
- `Action: Alert` – device action/policy result  
- Remaining fields describe the event (internal → external traffic, app category, etc.)

## Common log types
- **Application / Server / System** (errors, boot, kernel, access)  
- **Security / Audit** (auth events, permission changes)  
- **Network / Firewall / WAF / VPN**  
- **Web server** (URLs, methods, response codes, client IPs)  
- **Database** (queries, changes)  
- **Cloud & SaaS** (AWS/Azure/GCP audit, org/app audit logs)

---

## Quick start (do these first)
1. **Normalize time to UTC** at ingestion; display in local time as needed.  
2. Build a **7-day failed-login trend** and alert on spikes.  
3. Create a **timeline** for a small incident (merge auth + VPN + firewall).  
4. Add one **threat-intel feed** and tag matching events.  
5. Document what you did in `playbooks/` so others can repeat it.
