# Detection Toolbox

A curated **knowledge base of detection tools, queries, and playbooks** I’ve used in labs and professional environments.  
This repo is my personal reference library, but also a portfolio of hands-on detection engineering experience.

---

## 🔍 Purpose
- Document **commands, queries, and playbooks** for detection tools I’ve worked with.  
- Provide **cheatsheets** for quick reference during investigations.  
- Share **examples and workflows** that map to MITRE ATT&CK, threat hunting, and SOC analysis tasks.  
- Highlight **real-world experience** from professional and lab environments.  

---

## 🛠️ Tools Covered
- **Angle Grinder** — CLI log analysis with SQL-like syntax.  
- **Splunk** — detection queries, dashboards, and playbooks.  
- **Azure Sentinel** — KQL queries and automated playbooks.  
- **Sigma** — universal detection rules.  
- **Wireshark, Elastic, and others** — packet and log analysis workflows.  

---

## 📂 Repo Structure
- `tools/` → Commands, queries, and detection notes organized per tool.  
- `references/` → External resources and reading lists.  
- `LICENSE` → MIT license (open for learning & sharing).  

---

## 🚀 Example Snippet

**Angle Grinder: Top SSH auth failures from syslog**
```bash
grep "Failed password" /var/log/auth.log \
| agrind '* | parse "* from * port * *" as msg, src, port, rest | count as fails by src | sort -fails'
