# Common Patterns in Log Data (Security)

Recognizing recurring patterns in logs helps you spot threats quickly and investigate confidently. Below are practical signals and examples you can use as a starter checklist.

---

## Abnormal User Behavior

Unusual user activity compared to a user’s baseline can indicate compromise. Many platforms (e.g., Splunk UBA, IBM QRadar UBA, Azure AD Identity Protection) learn “normal” and alert on deviations—tune them to your environment to reduce false positives.

**Indicators to watch**
- **Multiple failed logins** in a short window (possible brute force).
- **Unusual login times** (outside a user’s normal access hours).
- **Geographic anomalies** (logins from unexpected countries; or *impossible travel*—two far-apart locations within an infeasible time).
- **Frequent password changes** in a short period.
- **Unusual user-agent strings** in HTTP logs (automation/tooling).  
  *Examples:* default strings containing `Nmap Scripting Engine` or `(Hydra)`.

> **Tip:** Always add context (asset owner, user role, known VPN egress IPs) so alerts are meaningful.

---

## Common Attack Signatures

Attack signatures are distinctive traces left in logs during exploitation attempts. Below are concise patterns and sample entries.

### SQL Injection (SQLi)

Look for **malformed queries** or unexpected tokens in app/db logs:
- Single quotes `'`, inline comments `--` / `#`, `UNION SELECT`, or time delays `SLEEP()`, `WAITFOR DELAY`.
- Many attacks are **URL-encoded**—decode before matching.

**Example (`sqli.log`):**
10.10.61.21 - - [2023-08-02 15:27:42] "GET /products.php?q=books' UNION SELECT null, null, username, password, null FROM users-- HTTP/1.1" 200 3122

markdown
Copy code

**What to check**
- Decode query params first.
- Flag requests containing `UNION SELECT`, `--`, `'` where not expected.
- Correlate with auth failures, privilege changes, or DB error spikes.

---

### Cross-Site Scripting (XSS)

Look for **unexpected script or event handlers** in request parameters:
- `<script>...</script>`, `onerror=`, `onmouseover=`, etc.
- Often URL-encoded—decode first.

**Example (`xss.log`):**
10.10.19.31 - - [2023-08-04 16:12:11] "GET /products.php?search=<script>alert(1);</script> HTTP/1.1" 200 5153

markdown
Copy code

**What to check**
- Requests containing `<script>` or suspicious HTML/JS tokens in params.
- Repeated attempts across different endpoints/fields.
- Match to WAF blocks or CSP violations if available.

---

### Path Traversal

Look for **directory traversal sequences** and access to sensitive paths:
- `../` and `../../` patterns; targets like `/etc/passwd`, `/etc/shadow`.
- Commonly **URL-encoded** (e.g., `.` → `%2E`, `/` → `%2F`), sometimes **double-encoded**.

**Example (`path-traversal.log`):**
10.10.113.45 - - [2023-08-05 18:17:25] "GET /../../../../../etc/passwd HTTP/1.1" 200 505

markdown
Copy code

**What to check**
- Normalize/resolve paths after decoding.
- Alert on traversal patterns and known sensitive files.
- Correlate with 5xx responses, WAF events, or unusual file reads.

---

## Tuning & Operations

- **Decode first:** URL-decode (and consider double-decode) before matching signatures.
- **Normalize time:** Ingest as **UTC**; display in local time for analysts.
- **Baseline & allowlists:** Reduce noise by excluding known scanners, health checks, and corporate VPN egress IPs.
- **Context matters:** A single indicator may be benign—**stack evidence** (sequence of failed→success logins, geo anomalies, privilege changes).
- **Feedback loop:** Review alerts weekly; suppress noisy rules, add context enrichments (GeoIP, TI matches), and document decisions.

---

## Quick Pattern Queries (tool-agnostic concepts)

- **Failed→Success Login Chain (10m window):**
  - Group by `user`, find ≥N failures followed by a success from same/different `src_ip`.

- **Impossible Travel:**
  - Sort logins by time per user; flag geodistance/time pairs that exceed a realistic speed threshold.

- **Traversal & Injection in Web Logs:**
  - After URL-decoding, regex-match `(\.\./)+`, `/etc/passwd`, `(<script>|onerror=)`, `UNION\s+SELECT`, `--`.

> Save these as detections and track noise vs. fidelity over time.
