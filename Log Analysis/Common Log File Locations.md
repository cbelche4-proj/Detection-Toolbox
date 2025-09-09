# Common Log File Locations

> Paths vary by distro, version, and config (syslog vs. journald, custom app settings, containers). Treat these as common defaults and verify with service configs.

## Web Servers
- **Nginx**
  - Access: `/var/log/nginx/access.log`
  - Error:  `/var/log/nginx/error.log`
- **Apache**
  - Debian/Ubuntu: Access `/var/log/apache2/access.log`, Error `/var/log/apache2/error.log`
  - RHEL/CentOS:   Access `/var/log/httpd/access_log`, Error `/var/log/httpd/error_log`

## Databases
- **MySQL/MariaDB**
  - Error: `/var/log/mysql/error.log` (Debian/Ubuntu) or `/var/log/mysqld.log` (RHEL/CentOS)
- **PostgreSQL**
  - Debian/Ubuntu: `/var/log/postgresql/postgresql-<version>-main.log`
  - RHEL/CentOS: Usually under data dir (e.g., `/var/lib/pgsql/data/log/`), set by `log_directory`

## Web Applications
- **PHP / PHP-FPM**
  - General: `/var/log/php/error.log`
  - FPM pool logs: `/var/log/php*-fpm.log` (e.g., `/var/log/php7.4-fpm.log`)
  - (Check `php.ini`/pool `.conf` for exact paths)

## Operating Systems (Linux)
- Debian/Ubuntu:
  - System: `/var/log/syslog`
  - Auth:   `/var/log/auth.log`
  - Kernel: `/var/log/kern.log`
- RHEL/CentOS/Alma/Rocky:
  - System: `/var/log/messages`
  - Auth/SSH: `/var/log/secure`
- **Auditd** (if enabled): `/var/log/audit/audit.log`
- **Systemd journal** (no plaintext files): view with `journalctl`

## Firewalls / IDS
- **iptables/nftables**
  - Often via kernel facility → `/var/log/kern.log` or `/var/log/messages`
  - Some systems use `/var/log/iptables.log` (custom rsyslog rule)
- **Snort**
  - `/var/log/snort/`
- **Suricata**
  - `/var/log/suricata/`

## Windows (for reference)
- View with **Event Viewer** (Application, Security, System)
- EVTX files: `C:\Windows\System32\winevt\Logs\`

## macOS (for reference)
- Legacy: `/var/log/system.log`, `/var/log/install.log`
- Unified logging: view with `Console.app` or `log show --predicate ...`

## Containers / Kubernetes (for reference)
- Docker: `docker logs <container>`
- K8s: `kubectl logs <pod> [-c container]`
- Node paths often: `/var/log/containers/` or journald

---

## Quick Commands
```bash
# Follow a log
sudo tail -f /var/log/nginx/access.log

# Search rotated logs too
zgrep -i "failed password" /var/log/auth.log*

# Systemd journal for a service, last 1 hour
sudo journalctl -u ssh --since "1 hour ago"

# Top talkers in an access log (simple example)
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -nr | head
