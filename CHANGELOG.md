# Changelog

All notable changes to the Auto Recon Framework are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.0] - 2024-01-15

### Added

#### Core Framework
- `ReconEngine` — orchestrates all phases, aggregates `ScanResult`
- `ScanResult` dataclass — unified data model for all module outputs
- Config system — layered YAML + env vars + CLI overrides
- Structured logging with per-module color-coded output
- Exit codes: `0` (clean), `1` (high), `2` (critical)

#### Scanning Modules
- **NmapScanner** — full-range port scan with XML parsing, service/version detection
- **SubfinderScanner** — passive subdomain enumeration with 50+ sources
- **HttpxProber** — HTTP/HTTPS probing with tech fingerprinting, title, status
- **NucleiScanner** — template-based vuln scan (CVEs, misconfigs, exposures, creds)
- **ScreenshotCapture** — gowitness primary, chromium headless fallback

#### Reporting
- **MarkdownReporter** — structured `.md` report with full detail
- **JsonReporter** — machine-readable `.json` report
- **HtmlReporter** — self-contained dark-mode interactive HTML report
- **CVE Mapper** — real-time enrichment from NVD API v2
- **MITRE ATT&CK Mapper** — automatic technique mapping for all findings

#### Infrastructure
- Multi-stage `Dockerfile` (Go tools builder + Python slim runtime)
- `docker-compose.yml` with optional report server
- `setup.sh` — automated installer for Ubuntu/Debian/Kali/macOS
- `Makefile` — common dev/scan/CI tasks
- GitHub Actions CI/CD pipeline — lint, test, SAST, Docker build, scheduled scan

#### Configuration
- `config/default.yaml` — balanced defaults
- `config/aggressive.yaml` — maximum coverage preset
- `config/stealth.yaml` — low-noise, reduced rate limits
- `config/web.yaml` — HTTP attack surface focused

#### Utilities
- `utils/scope.py` — target validation, scope management, DNS resolution
- `utils/console_ui.py` — rich progress bars, tables, summary panels
- `utils/template_manager.py` — nuclei template management and stats
- `pyproject.toml` — ruff, mypy, pytest, bandit configuration

#### Documentation
- `README.md` — full badges, architecture diagrams, usage reference
- `docs/architecture.md` — system design, data flow, extension guide
- `docs/user-guide.md` — installation, configuration, troubleshooting
- `docs/mitre-mapping.md` — ATT&CK technique mapping reference
- `docs/example-report.md` — realistic sample output

#### Tests
- Unit tests for models, helpers, config, CVE mapper
- Mocked integration tests for scanner modules
- `pyproject.toml` pytest + coverage configuration

---

## [Unreleased]

### Planned

- ATT&CK Navigator JSON export
- Multi-target file input (`-l targets.txt`)
- Slack/Teams webhook notifications
- PDF report generation
- Vulnerability deduplication across scans
- Historical diff reporting (compare scan A vs scan B)
- Web UI for report browsing
- Shodan/Censys integration
- DNS brute-force module (dnsx)
- WAF detection module
