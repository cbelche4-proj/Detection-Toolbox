# Angle Grinder (agrind) Toolbox

A personal reference and knowledge base for using [Angle Grinder](https://github.com/rcoh/angle-grinder) (`agrind`) in log analysis and detection engineering.  

This repo captures **commands, workflows, and cheatsheets** I’ve used in labs and professional scenarios to quickly slice & dice logs from the command line.

---

## 🔍 What is Angle Grinder?

Angle Grinder is a fast, interactive log analysis tool.  
It can parse, filter, and aggregate text streams in real time using SQL-like queries.  
It supports structured formats like **JSON** and **logfmt**, as well as custom **parse patterns** and **regex**.

---

## ⚡ Why I Use It

- **Quick triage:** fast way to analyze massive log files on the fly.  
- **Versatility:** works on Apache, syslog, JSON, Windows EVTX (exported), and more.  
- **Detection engineering:** great for building small detection recipes before porting into Splunk, Sentinel, or Sigma.  
- **SOC workflows:** fits naturally in CLI-heavy IR workflows.  

---

## 🛠️ Installation

**macOS (Homebrew):**
```bash
brew install angle-grinder
