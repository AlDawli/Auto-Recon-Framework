# Auto-Recon-Framework
Auto Recon Framework is built around a pipeline architecture where each module performs a distinct reconnaissance phase, passing enriched data to the next stage. All modules are loosely coupled through the ScanResult data model.

# Installation
One-Line Install
git clone && cd auto-recon && ./setup.sh

# What setup.sh Does
The setup script performs these steps in order:
1.	Checks Python — requires 3.10+
2.	Installs Python packages — from requirements.txt
3.	Installs nmap — via apt/brew
4.	Installs Go tools — subfinder, httpx, nuclei, gowitness via go install
5.	Updates nuclei templates — pulls latest from GitHub
6.	Creates config.yaml — default configuration
7.	Creates output/ — report and screenshot directories
Verify Your Install
which nmap subfinder httpx nuclei gowitness
python3 -c "import yaml, rich; print('Python deps OK')"

# Docker Alternative
No local installs needed:
docker build -f docker/Dockerfile -t auto-recon .
docker run --rm --network host -v $(pwd)/output:/app/output auto-recon -t example.com

Your First Scan
Minimal Scan (fastest)
# HTTP probing + vuln scan only — no port scan, no subdomain enum
python main.py -t example.com --no-nmap --no-subfinder

# Standard Scan
python main.py -t example.com

# This runs all 5 phases:
1.	nmap — finds all open ports with service detection
2.	subfinder — enumerates subdomains passively
3.	httpx — probes all discovered hosts for HTTP/HTTPS
4.	nuclei — scans all live services for vulnerabilities
5.	Screenshots — captures visual record of live web services
IP Target
python main.py -t 192.168.1.100
# Note: subfinder is automatically skipped for IP targets

# With Custom Output Directory
python main.py -t example.com --output /tmp/pentest-2024-01-15

# Severity color guide
Color	Severity	Description
🔴 Red bold	Critical	Direct compromise risk — act immediately
🟠 Orange	High	Significant risk — patch within 7 days
🟡 Yellow	Medium	Moderate risk — next sprint
🔵 Blue	Low	Low risk — track and fix
⚪ Gray	Info	Informational — fingerprinting data

## Scan is very slow
# Use common ports only
python main.py -t example.com --ports "top-1000"

# Skip screenshots (often the slowest part)
python main.py -t example.com --no-screenshots

# Critical/High only
python main.py -t example.com --severity critical,high

# Use the stealth preset
python main.py -t example.com -c config/stealth.yaml

gowitness screenshots are blank
# gowitness needs a browser — check chromium
which chromium chromium-browser google-chrome

# Install chromium
sudo apt install chromium

Debug mode
python main.py -t example.com --debug
# Shows full stack traces and raw tool output

# Understanding the Output

Terminal Output
During the scan you'll see phase-by-phase progress:
  ━━ Phase 1/5: Port Scanning ━━━━━━━━━━━━━━━━━━━━━
  [INFO]   [  NMAP   ]  Starting port scan on example.com
  [INFO]   [  NMAP   ]  Running: nmap -sV -sC -O --open -T4 ...
  [✓]      [  NMAP   ]  Found 12 open ports on example.com
  [INFO]   [  NMAP   ]    80/tcp   http                 nginx 1.18.0
  [INFO]   [  NMAP   ]    443/tcp  https                nginx 1.18.0
  ...

  ━━ Phase 4/5: Vulnerability Scanning ━━━━━━━━━━━━
  [INFO]   [ NUCLEI  ]  Running nuclei on 8 targets
  [HIGH]   [ NUCLEI  ]  [HIGH] CVE-2021-41773 @ https://example.com
  [CRIT]   [ NUCLEI  ]  [CRITICAL] Spring4Shell @ https://app.example.com

# Core Design Principles
Principle	Implementation
Separation of concerns	Each module only handles its tool; reporting is separate
Fail-safe execution	Missing tools → SKIPPED status; scan continues
Data immutability	Each module receives and returns ScanResult; no global state
Structured logging	Every log line carries module context and severity
Config-first	All behaviour controlled by ReconConfig; no hard-coded values

# Exit Codes
The process exits with:
·	0 — No critical or high findings
·	1 — High findings found
·	2 — Critical findings found
Use this in scripts:
python main.py -t "$TARGET" || echo "Vulnerabilities found! Check output/"

# Scan Presets
Four ready-to-use config presets are in config/:
config/default.yaml
Balanced scan — everything enabled with sane defaults.
python main.py -t example.com
## (default.yaml is used automatically)

config/aggressive.yaml
Maximum coverage — all templates, all severities, higher rate limits.
python main.py -t example.com -c config/aggressive.yaml
# ~2–4x slower, more thorough findings

config/stealth.yaml
Slow, quiet — reduced rate limits, common ports only, no screenshots.
python main.py -t example.com -c config/stealth.yaml
# Minimizes detection risk

config/web.yaml
Web-surface focused — HTTP ports only, heavy nuclei web templates.
python main.py -t example.com -c config/web.yaml
# Best for web app pentests



# Component Architecture
┌────────────────────────────────────────────────────────────────────────┐
│                         CLI Layer (main.py)                            │
│  argparse → load_config() → ReconEngine.run(target)                   │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │
                                 ▼
                 ReconEngine (core/engine.py)            

Input: target (str)              Output: ScanResult + reports 
                                                              
Phase 1 ──→ NmapScanner       ──→ result.ports[]                
Phase 2 ──→ SubfinderScanner  ──→ result.subdomains[]        
Phase 3 ──→ HttpxProber       ──→ result.http_probes[]      
Phase 4 ──→ NucleiScanner     ──→ result.vulnerabilities[]     
Phase 5 ──→ ScreenshotCapture ──→ result.screenshots[]   
Reporting → MarkdownReporter, JsonReporter, HtmlReporter        
                                
  CVE Mapper (NVD API) + MITRE ATT&CK Mapper     
└───────────────────────────────────────────────────────────

# Data Flow

Target String
     ▼
validate_target()     ← utils/scope.py
     ▼
ScanResult(target, scan_id)
     ├──▶ nmap XML → parse_xml() → PortInfo[]
     ├──▶ subfinder TXT → SubdomainInfo[]                      │
     ├──▶ httpx JSONL ─────────┤ (enriches subdomains with alive/tech)
     ├──▶ nuclei JSONL → VulnerabilityFinding[]
      │
      ├── cve_ids[] ──→ NVD API → CVEDetail{}
      └── tags[]    ──→ MITRE technique mapping
     └──▶ gowitness PNG → ScreenshotInfo[]
               ▼
          ScanResult (complete)
     ▼         ▼         ▼
  .md         .json      .html
  report      report     report

# Configuration System

CLI flags
    ▼
load_config(path, **overrides)
    ├── config.yaml (file)
    ├── RECON_* env vars
    └── CLI overrides (highest priority)
         ▼
      ReconConfig (dataclass)
       ── NmapConfig
      ── SubfinderConfig
      ── HttpxConfig
      ── NucleiConfig
      ── ScreenshotConfig
      ── OutputConfig

# Priority (highest to lowest):
1.	CLI arguments (--ports, --severity, etc.)
2.	Environment variables (RECON_*)
3.	Config file (config.yaml)
4.	Dataclass defaults

# Error Handling Strategy
Scenario	Behaviour
Tool not installed	SKIPPED status, scan continues
Tool timeout	FAILED status, scan continues
Parse error	Empty result list, warning logged
Network error (CVE API)	CVE details omitted, warning logged
KeyboardInterrupt	Graceful stop, partial report generated
Unhandled exception	FAILED status, traceback in --debug mode

# Extension Points
Adding a New Scanner Module
1.	Create modules/my_scanner.py with the standard interface
2.	Add config dataclass in core/config.py
3.	Register in core/engine.py pipeline
4.	Add CLI flag in main.py
5.	Add tests in tests/test_framework.py
Adding a New Report Format
1.	Create reporting/my_reporter.py
2.	Add to ReconEngine._generate_reports()
3.	Add to OutputConfig.format choices
Custom MITRE Mapping
Edit TEMPLATE_MITRE_MAP in modules/nuclei_scanner.py or reporting/cve_mapper.py.

#  Performance Characteristics
Phase	Typical Duration	Parallelism
nmap (full range)	5–20 min	Single host, internal threads
subfinder	1–5 min	100 concurrent sources
httpx	30s–5 min	50 concurrent requests
nuclei	5–30 min	25 bulk, 150 req/s
screenshots	1–10 min	10 concurrent browsers
Total: ~15–60 min for a medium-sized target.

# Optimization options:
·	Reduce port range: --ports 1-1000
·	Reduce nuclei severity: --severity critical,high
·	Use config/stealth.yaml for slower, quieter scans
·	Use config/web.yaml for HTTP-only surface

# Security Considerations
·	Non-root by default in Docker — USER recon in Dockerfile
·	No credentials stored — API keys should use env vars / secrets manager
·	Output sanitization — target names are sanitized in file paths
·	Rate limiting — nuclei rate limit prevents accidental DoS
·	Scope validation — utils/scope.py can enforce scan boundaries

# Working with Reports
Markdown Report
The .md report is a standalone document containing:
·	Executive summary with overall risk level
·	Severity breakdown table
·	Full port scan table
·	Subdomain listing (live/dead)
·	HTTP services with tech fingerprints
·	Per-vulnerability detail with CVE info and MITRE mapping
·	MITRE ATT&CK matrix
·	CVE enrichment from NVD
·	Screenshots
·	Remediation recommendations

# Open in GitHub, VS Code, Obsidian, or any Markdown renderer.
HTML Report
Self-contained dark-mode report with:
·	Interactive severity donut chart
·	Collapsible sections
·	Clickable CVE links
·	Technology fingerprint display
·	MITRE ATT&CK listing
# Generate HTML report
python main.py -t example.com --format html,markdown,json

# Serve it locally
python3 -m http.server 8080 --directory output/reports/
# Open: http://localhost:8080

# JSON Report
Machine-readable output for integration with other tools:
import json

🔍 Auto Recon Report
Target: demo.example.com

Scan ID: scan_20240115_143022_a3f9c1

Date: 2024-01-15 14:30 UTC

# 📊 Risk Summary
Severity	Count
🔴 Critical	2
🟠 High	5
🟡 Medium	8
🔵 Low	3
⚪ Info	11

Total: 14 ports · 27 subdomains · 29 findings · 12 screenshots

📋 Executive Summary
Overall Risk Level: 🔴 CRITICAL
The reconnaissance scan of demo.example.com revealed the following:
·	14 open network ports across the target
·	27 subdomains discovered (19 live)
·	29 security findings (2 critical, 5 high)
·	Technologies detected: Apache Struts, Apache Tomcat, jQuery 1.7.1, MySQL, OpenSSH 7.4, PHP 7.2.34, WordPress 5.8.1
⚠️ IMMEDIATE ACTION REQUIRED: Critical vulnerabilities were found.

# ⚙️ Scan Metadata
Parameter	Value
Target	demo.example.com
Scan ID	scan_20240115_143022_a3f9c1
Started	2024-01-15 14:30:22 UTC
Duration	47m 13s
Status	COMPLETED

# Module Status
Module	Status
Nmap Port Scan	✅ completed
Subfinder Subdomain Enum	✅ completed
HTTPX Probing	✅ completed
Nuclei Vulnerability Scan	✅ completed
Screenshot Capture	✅ completed

# 🔌 Port Scan (14 open ports)
Port	Protocol	Service	Version
21	TCP	ftp	vsftpd 3.0.3
22	TCP	ssh	OpenSSH 7.4 (protocol 2.0)
25	TCP	smtp	Postfix smtpd
80	TCP	http	Apache httpd 2.4.29
443	TCP	https	Apache httpd 2.4.29
3306	TCP	mysql	MySQL 5.7.39-log
6379	TCP	redis	Redis key-value store
8080	TCP	http	Apache Tomcat 9.0.46
8443	TCP	https	Apache Tomcat 9.0.46
8888	TCP	http	Jupyter Notebook
9200	TCP	http	Elasticsearch REST API
27017	TCP	mongodb	MongoDB 4.4.18
50000	TCP	ibm-db2	—
55555	TCP	unknown	—


# 🌐 Subdomain Enumeration (27 found)
Live Subdomains (19)
Status	Subdomain	IP
✅	www.demo.example.com	203.0.113.10
✅	api.demo.example.com	203.0.113.10
✅	admin.demo.example.com	203.0.113.11
✅	dev.demo.example.com	203.0.113.12
✅	staging.demo.example.com	203.0.113.13
✅	mail.demo.example.com	203.0.113.14
✅	vpn.demo.example.com	203.0.113.15
✅	jenkins.demo.example.com	203.0.113.16
✅	gitlab.demo.example.com	203.0.113.16
✅	jira.demo.example.com	203.0.113.17
✅	confluence.demo.example.com	203.0.113.17
✅	kibana.demo.example.com	203.0.113.10
✅	grafana.demo.example.com	203.0.113.10
✅	shop.demo.example.com	203.0.113.18
✅	blog.demo.example.com	203.0.113.10
✅	legacy.demo.example.com	203.0.113.19
✅	backup.demo.example.com	203.0.113.20
✅	ftp.demo.example.com	203.0.113.10
✅	test.demo.example.com	203.0.113.12

# Non-Responding Subdomains (8)
Status	Subdomain	IP
❌	old.demo.example.com	—
❌	portal.demo.example.com	—
❌	beta.demo.example.com	—
❌	app2.demo.example.com	—
❌	cdn.demo.example.com	—
❌	assets.demo.example.com	—
❌	support.demo.example.com	—
❌	status.demo.example.com	—


# 🕸️ HTTP Services (19 live)
URL	Status	Title	Size	Technologies
https://www.demo.example.com	200	Example Company	45231	WordPress, PHP, MySQL
https://api.demo.example.com	200	API Gateway	1204	Node.js, Express
http://admin.demo.example.com	200	Admin Panel	8432	PHP, Bootstrap
https://dev.demo.example.com	200	Dev Environment	3211	React, Node.js
http://jenkins.demo.example.com:8080	200	Jenkins	5033	Jenkins 2.319.3
https://gitlab.demo.example.com	200	GitLab	28441	GitLab CE 14.6
http://kibana.demo.example.com:5601	200	Kibana	4123	Kibana 7.15.2
http://grafana.demo.example.com:3000	200	Grafana	3987	Grafana 8.3.3
http://legacy.demo.example.com	200	Legacy App	12433	Apache Struts 2.5.27
http://backup.demo.example.com	200	Directory Index	823	Apache 2.4.29
http://test.demo.example.com:8888	200	Jupyter	4211	Jupyter Notebook


🐛 Vulnerability Findings (29 total)
🔴 Critical: 2 | 🟠 High: 5 | 🟡 Medium: 8 | 🔵 Low: 3

# 🔴 Apache Log4Shell RCE

Field	Value
Template	cves/2021/CVE-2021-44228
Host	http://legacy.demo.example.com
Matched At	http://legacy.demo.example.com/struts/login
CVE	CVE-2021-44228
CVSS	10.0
MITRE	T1190 Exploit Public-Facing Application

Description: Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints.
References:
·	https://nvd.nist.gov/vuln/detail/CVE-2021-44228
·	https://www.lunasec.io/docs/blog/log4j-zero-day/

# 🔴 Exposed Jupyter Notebook (Unauthenticated)
Field	Value
Template	exposures/apis/jupyter-notebook
Host	http://test.demo.example.com:8888
Matched At	http://test.demo.example.com:8888/api/kernels
CVE	—
CVSS	—
MITRE	T1083 File and Directory Discovery

# Description: An unauthenticated Jupyter Notebook instance is accessible. Jupyter Notebooks allow arbitrary code execution on the server.

# 🟠 Jenkins Anonymous Access Enabled
Field	Value
Template	exposures/misconfiguration/jenkins-anonymous-access
Host	http://jenkins.demo.example.com:8080
Matched At	http://jenkins.demo.example.com:8080/asynchPeople/
CVE	—
CVSS	—
MITRE	T1078 Valid Accounts

Description: Jenkins has anonymous read access enabled allowing unauthenticated users to enumerate jobs, builds, and user information.

# 🟠 WordPress Plugin Vulnerability (CVE-2022-4328)
Field	Value
Template	cves/2022/CVE-2022-4328
Host	https://www.demo.example.com
Matched At	https://www.demo.example.com/wp-content/plugins/woocommerce/...
CVE	CVE-2022-4328
CVSS	8.8
MITRE	T1190 Exploit Public-Facing Application

Description: WooCommerce plugin 7.1.0 and below has an unauthenticated arbitrary option update vulnerability.

# 🟡 Redis Unauthenticated Access
Field	Value
Template	network/redis-unauthorized-access
Host	demo.example.com:6379
Matched At	demo.example.com:6379
CVE	—
CVSS	—
MITRE	T1046 Network Service Discovery

Description: Redis is accessible without authentication. An attacker can read/write all cached data and potentially achieve code execution via config rewrite.

# 🟡 Apache Directory Listing Enabled
Field	Value
Template	exposures/configs/apache-directory-listing
Host	http://backup.demo.example.com
Matched At	http://backup.demo.example.com/
CVE	—
CVSS	—
MITRE	T1083 File and Directory Discovery
Description: Apache directory listing is enabled on the backup server, exposing filenames and directory structure. Backup files are visible.

🔖 CVE Details
🔴 CVE-2021-44228
Field	Value
CVSS Score	10.0 (Critical)
CVSS Vector	CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
Published	2021-12-10
CWE	CWE-917, CWE-20
Description: Apache Log4j2 versions 2.0-beta9 to 2.15.0 contain an JNDI injection vulnerability that can allow an attacker to execute arbitrary code on the target system via specially crafted log messages.

# 🛠️ Remediation Recommendations
1.	🔴 Patch critical vulnerabilities immediately — these represent direct compromise risk
2.	🟠 Remediate high-severity findings within 7 days — prioritize by CVSS score
3.	🟡 Address medium findings within 30 days — schedule in next sprint
·	Keep WordPress core, themes, and plugins up to date
·	Harden web server configuration; disable unnecessary modules
·	Update PHP to a supported version; review php.ini security settings
·	Immediately update Log4j to version 2.17.1 or later across all Java services
·	Restrict network access to Redis (port 6379), MongoDB (27017), Elasticsearch (9200) — never expose to internet
·	Add authentication to Jupyter Notebook, Jenkins, and Kibana
·	Disable Apache directory listing (Options -Indexes in httpd.conf)
·	Implement a Web Application Firewall (WAF)
·	Enable HTTPS everywhere and enforce HSTS
·	Set up regular automated scanning in your CI/CD pipeline
·	Review exposed subdomains and remove unused services

# MITRE ATT&CK Mapping Reference
This document explains how Auto Recon Framework maps findings to the MITRE ATT&CK Enterprise framework.

# Covered Tactics
Tactic ID	Tactic Name	Source Module
TA0043	Reconnaissance	subfinder, httpx, nuclei
TA0007	Discovery	nmap, nuclei
TA0001	Initial Access	nuclei (CVEs, exploits)
TA0002	Execution	nuclei (RCE findings)
TA0003	Persistence	nuclei (webshells, backdoors)
TA0005	Defense Evasion	nuclei (misconfigs)
TA0006	Credential Access	nuclei (default creds)

# Technique Mapping Table
Technique	Name	Trigger
T1046	Network Service Discovery	nmap open ports
T1190	Exploit Public-Facing Application	nuclei CVE templates
T1592	Gather Victim Host Information	httpx tech detection
T1592.002	Software	httpx technology fingerprinting
T1590	Gather Victim Network Information	subfinder
T1590.001	Domain Properties	subfinder subdomain enum
T1590.005	IP Addresses	httpx IP resolution
T1595	Active Scanning	all active modules
T1595.002	Vulnerability Scanning	nuclei scan
T1083	File and Directory Discovery	nuclei exposure templates
T1078	Valid Accounts	nuclei misconfiguration
T1078.001	Default Accounts	nuclei default-credentials
T1059.007	JavaScript	nuclei XSS templates
T1203	Exploitation for Client Execution	nuclei RCE templates
T1090	Proxy	nuclei SSRF templates
T1584	Compromise Infrastructure	nuclei takeover templates

# Report Structure
In the Markdown report, the MITRE section looks like:
## 🛡️ MITRE ATT&CK Mapping

### Reconnaissance
- **T1590.001: Domain Properties** — subfinder subdomain enumeration
- **T1595.002: Vulnerability Scanning** — nuclei scan

### Initial Access
- **T1190: Exploit Public-Facing Application** — CVE-2021-44228 (Log4Shell), CVE-2022-22965
- **T1078.001: Default Accounts** — default-credentials:admin-panel

# Navigator Export (Planned)
Future versions will export an ATT&CK Navigator layer JSON file that can be imported at:

https://mitre-attack.github.io/attack-navigator/
This will visually highlight which techniques were observed during the recon scan.

# References
·	MITRE ATT&CK Enterprise
·	Nuclei Template Tags
·	ATT&CK Navigator

