# 🔍 Auto Recon Framework

[![CI/CD](https://github.com/your-org/auto-recon/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/auto-recon/actions)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat&logo=docker&logoColor=white)](docker/Dockerfile)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat)](#license)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat)](https://attack.mitre.org)
[![Nuclei](https://img.shields.io/badge/Nuclei-templates-00acd7?style=flat)](https://nuclei.projectdiscovery.io)
[![nmap](https://img.shields.io/badge/nmap-integrated-4682B4?style=flat)](https://nmap.org)

> **Automated reconnaissance pipeline** combining port scanning, subdomain enumeration, HTTP probing, and vulnerability detection — with MITRE ATT\&CK mapping and structured Markdown + JSON reports.

---

## 📋 Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Docker](#docker)
- [Configuration](#configuration)
- [Usage](#usage)
- [Output & Reports](#output--reports)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [CI/CD Integration](#cicd-integration)
- [Module Reference](#module-reference)
- [Extending the Framework](#extending-the-framework)
- [FAQ](#faq)

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔌 **Port Scanning** | Full-range nmap scan with service + version detection |
| 🌐 **Subdomain Enumeration** | Passive enumeration via subfinder with 50+ sources |
| 🕸️ **HTTP Probing** | Live service detection, tech fingerprinting, title extraction |
| 🐛 **Vulnerability Scanning** | Nuclei template-based scanning with 9,000+ templates |
| 📸 **Screenshots** | Automatic web screenshots via gowitness/chromium |
| 🔖 **CVE Mapping** | Real-time CVE enrichment from NVD API with CVSS scores |
| 🛡️ **MITRE ATT&CK** | Automatic technique mapping for all findings |
| 📊 **Reports** | Markdown + JSON reports with executive summary |
| 🐳 **Docker** | Full Docker + Docker Compose support |
| ⚡ **CI/CD** | GitHub Actions with scheduled scanning |

---

## 🏗️ Architecture

### High-Level Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                     Auto Recon Framework                        │
│                                                                 │
│   Input: Target (domain / IP)                                   │
│         │                                                       │
│         ▼                                                       │
│   ┌─────────────┐                                               │
│   │  CLI / main │  ← config.yaml, CLI flags                    │
│   └──────┬──────┘                                               │
│          │                                                       │
│          ▼                                                       │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                    ReconEngine                          │   │
│   │                                                         │   │
│   │  Phase 1          Phase 2           Phase 3             │   │
│   │  ┌──────────┐    ┌───────────┐    ┌──────────┐          │   │
│   │  │   nmap   │ →  │ subfinder │ →  │   httpx  │          │   │
│   │  │  ports   │    │subdomains │    │  probing │          │   │
│   │  └──────────┘    └───────────┘    └──────────┘          │   │
│   │                                        │                │   │
│   │  Phase 4                    Phase 5    │                │   │
│   │  ┌──────────┐    ┌───────────────┐    │                │   │
│   │  │  nuclei  │ ←  │  screenshots  │ ←──┘                │   │
│   │  │  vulns   │    │   gowitness   │                     │   │
│   │  └──────────┘    └───────────────┘                     │   │
│   │       │                                                 │   │
│   └───────┼─────────────────────────────────────────────────┘   │
│           │                                                       │
│           ▼                                                       │
│   ┌───────────────────────────────────────┐                      │
│   │             Reporting Engine          │                      │
│   │                                       │                      │
│   │  CVE Mapper    MITRE ATT&CK Mapper    │                      │
│   │      │               │               │                      │
│   │      ▼               ▼               │                      │
│   │  MarkdownReporter  JsonReporter      │                      │
│   └───────────────────────────────────────┘                      │
│                                                                 │
│   Output: reports/  screenshots/  json/                         │
└─────────────────────────────────────────────────────────────────┘
```

### Module Dependency Graph

```
main.py
  └── core/engine.py (ReconEngine)
        ├── modules/nmap_scanner.py     → core/models.py (PortInfo)
        ├── modules/subfinder_scanner.py → core/models.py (SubdomainInfo)
        ├── modules/httpx_prober.py      → core/models.py (SubdomainInfo)
        ├── modules/nuclei_scanner.py    → core/models.py (VulnerabilityFinding)
        ├── modules/screenshot_capture.py → core/models.py (ScreenshotInfo)
        └── reporting/
              ├── markdown_reporter.py
              │     ├── reporting/cve_mapper.py   (NVD API)
              │     └── reporting/mitre_mapper.py
              └── json_reporter.py
```

### MITRE ATT&CK Coverage

```
Reconnaissance (TA0043)              Discovery (TA0007)
├── T1590 Network Info Gathering     └── T1046 Network Service Discovery
│   ├── T1590.001 Domain Properties
│   └── T1590.005 IP Addresses       Initial Access (TA0001)
├── T1592 Host Information           └── T1190 Exploit Public-Facing App
│   └── T1592.002 Software
└── T1595 Active Scanning            Execution (TA0002)
    └── T1595.002 Vulnerability Scan └── T1203 Exploitation for Client Exec
```

### Directory Structure

```
auto-recon/
├── core/
│   ├── engine.py          # Main orchestrator
│   ├── config.py          # Configuration management
│   └── models.py          # Data models (dataclasses)
│
├── modules/
│   ├── nmap_scanner.py    # Phase 1: Port scanning
│   ├── subfinder_scanner.py # Phase 2: Subdomain enum
│   ├── httpx_prober.py    # Phase 3: HTTP probing
│   ├── nuclei_scanner.py  # Phase 4: Vuln scanning
│   └── screenshot_capture.py # Phase 5: Screenshots
│
├── reporting/
│   ├── markdown_reporter.py # Markdown report generator
│   ├── json_reporter.py   # JSON report generator
│   └── cve_mapper.py      # CVE + MITRE ATT&CK mapping
│
├── utils/
│   ├── logger.py          # Colored structured logging
│   └── helpers.py         # Shared utilities
│
├── tests/
│   └── test_framework.py  # Unit tests (pytest)
│
├── docker/
│   ├── Dockerfile         # Multi-stage Docker build
│   └── docker-compose.yml # Compose configuration
│
├── .github/workflows/
│   └── ci.yml             # GitHub Actions CI/CD
│
├── output/                # Generated at runtime
│   ├── reports/           # Markdown + JSON reports
│   ├── screenshots/       # Web screenshots
│   └── json/              # Raw tool outputs
│
├── main.py                # CLI entry point
├── setup.sh               # Automated installer
├── config.yaml            # Default configuration
└── requirements.txt       # Python dependencies
```

---

## ⚡ Quick Start

```bash
# Clone the repository
git clone https://github.com/your-org/auto-recon
cd auto-recon

# Install dependencies
chmod +x setup.sh && ./setup.sh

# Run your first scan
python main.py -t example.com
```

---

## 🔧 Installation

### Prerequisites

| Tool | Purpose | Install |
|------|---------|---------|
| Python 3.10+ | Framework runtime | [python.org](https://python.org) |
| nmap | Port scanning | `sudo apt install nmap` |
| Go 1.20+ | Building Go tools | [go.dev/dl](https://go.dev/dl) |
| subfinder | Subdomain enumeration | `go install ...` |
| httpx | HTTP probing | `go install ...` |
| nuclei | Vulnerability scanning | `go install ...` |
| gowitness | Screenshots (optional) | `go install ...` |

### Automated Install

```bash
chmod +x setup.sh
./setup.sh
```

The setup script:
1. Detects your OS (Ubuntu/Debian/Kali/macOS)
2. Installs nmap via package manager
3. Installs Go tools: subfinder, httpx, nuclei, gowitness
4. Installs Python dependencies
5. Updates nuclei templates
6. Creates default `config.yaml`
7. Creates output directories

### Manual Install

```bash
# Python dependencies
pip install -r requirements.txt

# Go tools (requires Go)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/sensepost/gowitness@latest

# nmap (Ubuntu/Debian/Kali)
sudo apt install nmap

# nmap (macOS)
brew install nmap

# Update nuclei templates
nuclei -update-templates
```

---

## 🐳 Docker

### Build & Run

```bash
# Build the image
docker build -f docker/Dockerfile -t auto-recon .

# Run a scan
docker run --rm \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  -v $(pwd)/output:/app/output \
  auto-recon -t example.com

# With network mode host (for accurate nmap)
docker run --rm --network host \
  -v $(pwd)/output:/app/output \
  auto-recon -t example.com --verbose
```

### Docker Compose

```bash
# Run a scan
docker-compose -f docker/docker-compose.yml run --rm recon -t example.com

# Serve the reports on localhost:8080
docker-compose -f docker/docker-compose.yml --profile reports up report-server
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RECON_TARGET` | — | Override scan target |
| `RECON_OUTPUT_DIR` | `output/` | Output directory |
| `RECON_VERBOSE` | `false` | Enable verbose logging |

---

## ⚙️ Configuration

Generate a default config:

```bash
python main.py --init-config
# Creates config.yaml
```

### Full Configuration Reference (`config.yaml`)

```yaml
# Output settings
output:
  base_dir: output
  format:
    - markdown    # Markdown report
    - json        # Machine-readable JSON

# Nmap port scanning
nmap:
  ports: "1-65535"         # Port range
  timing: "-T4"            # Timing template (T1-T5)
  flags: "-sV -sC -O --open" # Nmap flags
  timeout: 300             # Seconds

# Subfinder subdomain enumeration
subfinder:
  threads: 100
  recursive: true
  all_sources: false       # Use all (slower but more thorough)
  resolvers:
    - 8.8.8.8
    - 1.1.1.1

# HTTPX probing
httpx:
  threads: 50
  timeout: 10
  follow_redirects: true
  probe_tech: true         # Technology detection
  title: true
  content_length: true

# Nuclei vulnerability scanning
nuclei:
  templates:
    - cves
    - vulnerabilities
    - exposures
    - misconfiguration
  severity:
    - critical
    - high
    - medium
  rate_limit: 150          # Requests per second
  bulk_size: 25
  update_templates: true   # Auto-update on each run

# Screenshot capture
screenshot:
  enabled: true
  timeout: 15
  threads: 10
```

---

## 🚀 Usage

### Basic Scan

```bash
# Full scan against a domain
python main.py -t example.com

# Full scan against an IP
python main.py -t 192.168.1.1
```

### Targeted Scans

```bash
# Port scan only
python main.py -t example.com --no-subfinder --no-httpx --no-nuclei --no-screenshots

# Skip slow phases for quick HTTP check
python main.py -t example.com --no-nmap --no-subfinder --no-nuclei

# Critical findings only
python main.py -t example.com --severity critical

# Custom port range
python main.py -t example.com --ports "80,443,8080,8443"
```

### Output Options

```bash
# Custom output directory
python main.py -t example.com --output /tmp/recon-$(date +%Y%m%d)

# JSON output only
python main.py -t example.com --format json

# Both formats (default)
python main.py -t example.com --format markdown,json

# Custom scan ID
python main.py -t example.com --scan-id pentest-client-2024
```

### With Config File

```bash
python main.py -t example.com -c config/aggressive.yaml
python main.py -t example.com -c config/stealth.yaml
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success, no critical/high findings |
| `1` | High-severity findings detected |
| `2` | Critical findings detected |
| `>0` | Can be used in CI/CD to gate deployments |

---

## 📊 Output & Reports

After a scan, outputs are organized under `output/`:

```
output/
├── reports/
│   ├── scan_20240115_143022_abc123_report.md   ← Main report
│   └── scan_20240115_143022_abc123_report.json ← JSON data
├── screenshots/
│   ├── https_example_com.png
│   └── https_sub_example_com.png
└── json/
    ├── scan_..._nmap.xml
    ├── scan_..._subdomains.txt
    ├── scan_..._httpx.jsonl
    └── scan_..._nuclei.jsonl
```

### Markdown Report Structure

```
# Auto Recon Report
## Risk Summary (severity table)
## Executive Summary
## Scan Metadata
## Port Scan
## Subdomain Enumeration
## HTTP Services
## Vulnerability Findings (per-finding detail)
## MITRE ATT&CK Mapping
## CVE Details (NVD enrichment)
## Screenshots
## Remediation Recommendations
```

---

## 🛡️ MITRE ATT&CK Mapping

Every finding is automatically mapped to MITRE ATT\&CK tactics and techniques:

| Finding Type | Tactic | Technique |
|-------------|--------|-----------|
| Port scanning | TA0007 Discovery | T1046 Network Service Discovery |
| Subdomain enum | TA0043 Reconnaissance | T1590.001 Domain Properties |
| HTTP fingerprint | TA0043 Reconnaissance | T1592.002 Software |
| CVE exploit | TA0001 Initial Access | T1190 Exploit Public-Facing App |
| Default creds | TA0001 Initial Access | T1078.001 Default Accounts |
| File exposure | TA0007 Discovery | T1083 File and Directory Discovery |
| Misconfiguration | TA0001 Initial Access | T1078 Valid Accounts |

The report includes a full ATT\&CK matrix section grouping findings by tactic → technique → vulnerability name.

---

## ⚙️ CI/CD Integration

### GitHub Actions

The included workflow (`.github/workflows/ci.yml`) provides:

1. **Lint + Type Check** — ruff, mypy
2. **Unit Tests** — pytest with coverage
3. **Security Scan** — Bandit SAST, pip-audit
4. **Docker Build** — multi-arch (amd64/arm64) push to GHCR
5. **Scheduled Recon** — weekly scan of your target
6. **Manual Trigger** — `workflow_dispatch` with target input

### Pipeline as Security Gate

```yaml
# In your deployment pipeline:
- name: Recon scan before deploy
  run: python main.py -t ${{ vars.PROD_TARGET }} --severity critical,high
  # Exits 1 or 2 if critical/high findings exist → blocks deploy
```

### Scheduled Scanning Setup

1. Set `RECON_DEFAULT_TARGET` in your repo's Variables
2. The workflow runs every Sunday at 02:00 UTC
3. Reports are uploaded as GitHub Actions artifacts (30-day retention)

---

## 📦 Module Reference

### `core/engine.py` — ReconEngine

```python
from core.config import load_config
from core.engine import ReconEngine

config = load_config("config.yaml")
engine = ReconEngine(config)
result = engine.run("example.com")

print(result.total_vulnerabilities)
print(result.severity_counts())
```

### `core/models.py` — Data Models

```python
ScanResult      # Top-level scan container
PortInfo        # nmap port finding
SubdomainInfo   # Subdomain + HTTP probe data
VulnerabilityFinding  # Nuclei finding with CVE + MITRE
ScreenshotInfo  # Screenshot path + metadata
```

### `reporting/cve_mapper.py` — CVE & MITRE

```python
from reporting.cve_mapper import fetch_cve_details, build_mitre_summary

# Fetch single CVE
detail = fetch_cve_details("CVE-2021-44228")
print(detail.cvss_score, detail.description)

# Build MITRE map from findings
summary = build_mitre_summary(result.vulnerabilities)
```

---

## 🔌 Extending the Framework

### Adding a New Module

1. Create `modules/my_tool.py`:

```python
from core.config import ReconConfig
from core.models import ScanResult, ScanStatus
from utils.helpers import run_command, tool_exists
from utils.logger import log

class MyToolScanner:
    MODULE = "mytool"

    def __init__(self, config: ReconConfig):
        self.config = config

    def scan(self, result: ScanResult) -> ScanResult:
        if not tool_exists("mytool"):
            result.my_status = ScanStatus.SKIPPED
            return result

        # Run the tool, parse output, populate result
        log.info(f"Running mytool on {result.target}", self.MODULE)
        # ... your logic ...
        return result
```

2. Register in `core/engine.py`:

```python
from modules.my_tool import MyToolScanner

# In ReconEngine.run():
if self.config.run_mytool:
    log.info("━━ Phase X/Y: MyTool ━━", "engine")
    scanner = MyToolScanner(self.config)
    result = scanner.scan(result)
```

3. Add config toggle in `core/config.py`:

```python
@dataclass
class ReconConfig:
    run_mytool: bool = True
```

---

## ❓ FAQ

**Q: Does this tool bypass firewalls or IDS?**
A: No. This framework uses standard open-source tools (nmap, nuclei) without evasion techniques. Add `--no-nuclei` for passive-only scanning.

**Q: Is it legal to use this?**
A: Only scan targets you own or have explicit written permission to test. Unauthorized scanning is illegal.

**Q: How long does a full scan take?**
A: Roughly: small site ~5-15 min, medium site ~30-60 min, large org ~2-4 hours. Use `--ports "1-1000"` to speed up nmap.

**Q: Can I run multiple targets?**
A: Use a loop in bash: `while IFS= read -r target; do python main.py -t "$target"; done < targets.txt`

**Q: The nuclei scan is very slow. How to speed it up?**
A: Increase `--rate-limit`, reduce template scope: `--templates cves --severity critical`

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

**⚠️ Responsible Use:** This tool is for authorized security testing only. Always obtain proper authorization before scanning.

---

_Built with ❤️ using nmap · subfinder · httpx · nuclei · ProjectDiscovery_
