"""
Auto Recon Framework - Markdown Report Generator
Produces comprehensive, structured recon reports
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from core.config import ReconConfig
from core.models import ScanResult, Severity, ScanStatus
from reporting.cve_mapper import (
    enrich_findings_with_cve, build_mitre_summary,
    get_tactic_name, get_technique_name, cvss_to_label, CVEDetail
)
from utils.logger import log


SEVERITY_BADGE = {
    Severity.CRITICAL: "![Critical](https://img.shields.io/badge/Critical-FF0000?style=flat-square)",
    Severity.HIGH:     "![High](https://img.shields.io/badge/High-FF6600?style=flat-square)",
    Severity.MEDIUM:   "![Medium](https://img.shields.io/badge/Medium-FFAA00?style=flat-square)",
    Severity.LOW:      "![Low](https://img.shields.io/badge/Low-3399FF?style=flat-square)",
    Severity.INFO:     "![Info](https://img.shields.io/badge/Info-888888?style=flat-square)",
    Severity.UNKNOWN:  "![Unknown](https://img.shields.io/badge/Unknown-CCCCCC?style=flat-square)",
}

SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🔵",
    Severity.INFO:     "⚪",
    Severity.UNKNOWN:  "❔",
}


class MarkdownReporter:
    """Generates structured Markdown recon reports."""

    MODULE = "report"

    def __init__(self, config: ReconConfig):
        self.config = config
        self.reports_dir = config.output.reports_dir

    def generate(self, result: ScanResult) -> str:
        """Generate full report and write to file. Returns file path."""
        log.info("Generating Markdown report...", self.MODULE)

        Path(self.reports_dir).mkdir(parents=True, exist_ok=True)

        # Enrich with CVE data
        cve_details = {}
        if self.config.include_cve_details:
            cve_details = enrich_findings_with_cve(
                result.vulnerabilities,
                fetch_online=True
            )

        # Build MITRE summary
        mitre_summary = {}
        if self.config.include_mitre:
            mitre_summary = build_mitre_summary(result.vulnerabilities)

        result.update_summary()

        sections = [
            self._header(result),
            self._executive_summary(result),
            self._scan_metadata(result),
            self._port_scan_section(result),
            self._subdomain_section(result),
            self._http_probes_section(result),
            self._vulnerabilities_section(result, cve_details),
            self._mitre_section(mitre_summary),
            self._cve_details_section(cve_details),
            self._screenshots_section(result),
            self._remediation_section(result),
            self._footer(result),
        ]

        report = "\n\n".join(s for s in sections if s)

        # Write file
        report_file = str(
            Path(self.reports_dir) / f"{result.scan_id}_report.md"
        )
        with open(report_file, "w") as f:
            f.write(report)

        log.success(f"Report written to {report_file}", self.MODULE)
        return report_file

    # ── Sections ──────────────────────────────────────────────────────────────

    def _header(self, r: ScanResult) -> str:
        ts = r.started_at.strftime("%Y-%m-%d %H:%M UTC")
        counts = r.severity_counts()
        return f"""# 🔍 Auto Recon Report

**Target:** `{r.target}`
**Scan ID:** `{r.scan_id}`
**Date:** {ts}

---

## 📊 Risk Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | **{counts['critical']}** |
| 🟠 High | **{counts['high']}** |
| 🟡 Medium | **{counts['medium']}** |
| 🔵 Low | **{counts['low']}** |
| ⚪ Info | **{counts['info']}** |

> **Total:** {r.total_ports} ports · {r.total_subdomains} subdomains · {r.total_vulnerabilities} findings · {r.total_screenshots} screenshots"""

    def _executive_summary(self, r: ScanResult) -> str:
        counts = r.severity_counts()
        risk = "Low"
        if counts["critical"] > 0:
            risk = "🔴 CRITICAL"
        elif counts["high"] > 0:
            risk = "🟠 HIGH"
        elif counts["medium"] > 0:
            risk = "🟡 MEDIUM"
        else:
            risk = "🔵 LOW"

        alive_subs = sum(1 for s in r.subdomains if s.alive)
        tech_set = set()
        for p in r.http_probes:
            tech_set.update(p.technologies)

        techs = ", ".join(sorted(tech_set)[:10]) or "None detected"

        return f"""## 📋 Executive Summary

**Overall Risk Level:** {risk}

The reconnaissance scan of `{r.target}` revealed the following:

- **{r.total_ports}** open network ports across the target
- **{r.total_subdomains}** subdomains discovered ({alive_subs} live)
- **{r.total_vulnerabilities}** security findings ({counts['critical']} critical, {counts['high']} high)
- **Technologies detected:** {techs}

{"⚠️ **IMMEDIATE ACTION REQUIRED:** Critical vulnerabilities were found." if counts["critical"] > 0 else ""}
{"⚠️ **ACTION REQUIRED:** High-severity vulnerabilities require prompt remediation." if counts["high"] > 0 and counts["critical"] == 0 else ""}"""

    def _scan_metadata(self, r: ScanResult) -> str:
        duration = ""
        if r.finished_at:
            secs = (r.finished_at - r.started_at).total_seconds()
            mins = int(secs // 60)
            duration = f"{mins}m {int(secs % 60)}s"

        status_icon = lambda s: "✅" if s == ScanStatus.COMPLETED else ("⏭️" if s == ScanStatus.SKIPPED else ("❌" if s == ScanStatus.FAILED else "⚠️"))

        return f"""## ⚙️ Scan Metadata

| Parameter | Value |
|-----------|-------|
| Target | `{r.target}` |
| Scan ID | `{r.scan_id}` |
| Started | {r.started_at.strftime("%Y-%m-%d %H:%M:%S UTC")} |
| Duration | {duration or "N/A"} |
| Status | {r.status.value.upper()} |

### Module Status

| Module | Status |
|--------|--------|
| Nmap Port Scan | {status_icon(r.nmap_status)} {r.nmap_status.value} |
| Subfinder Subdomain Enum | {status_icon(r.subfinder_status)} {r.subfinder_status.value} |
| HTTPX Probing | {status_icon(r.httpx_status)} {r.httpx_status.value} |
| Nuclei Vulnerability Scan | {status_icon(r.nuclei_status)} {r.nuclei_status.value} |
| Screenshot Capture | {status_icon(r.screenshot_status)} {r.screenshot_status.value} |"""

    def _port_scan_section(self, r: ScanResult) -> str:
        if not r.ports:
            return "## 🔌 Port Scan\n\n_No open ports discovered or scan skipped._"

        rows = "\n".join(
            f"| {p.port} | {p.protocol.upper()} | {p.service} | {p.version[:60] if p.version else '—'} |"
            for p in r.ports
        )

        return f"""## 🔌 Port Scan ({r.total_ports} open ports)

| Port | Protocol | Service | Version |
|------|----------|---------|---------|
{rows}"""

    def _subdomain_section(self, r: ScanResult) -> str:
        if not r.subdomains:
            return "## 🌐 Subdomain Enumeration\n\n_No subdomains found or scan skipped._"

        alive = [s for s in r.subdomains if s.alive]
        dead  = [s for s in r.subdomains if not s.alive]

        alive_rows = "\n".join(
            f"| ✅ | `{s.subdomain}` | {s.ip or '—'} |"
            for s in alive
        )
        dead_rows = "\n".join(
            f"| ❌ | `{s.subdomain}` | — |"
            for s in dead[:20]
        )

        out = f"""## 🌐 Subdomain Enumeration ({r.total_subdomains} found)

### Live Subdomains ({len(alive)})

| Status | Subdomain | IP |
|--------|-----------|-----|
{alive_rows or "_None_"}"""

        if dead:
            out += f"""

### Non-Responding Subdomains ({len(dead)})

| Status | Subdomain | IP |
|--------|-----------|-----|
{dead_rows}
{"_...and more_" if len(dead) > 20 else ""}"""

        return out

    def _http_probes_section(self, r: ScanResult) -> str:
        if not r.http_probes:
            return "## 🕸️ HTTP Services\n\n_No HTTP services detected._"

        rows = "\n".join(
            f"| `{p.subdomain}` | {p.status} | {(p.title or '—')[:50]} | {p.content_length} | {', '.join(p.technologies[:3]) or '—'} |"
            for p in r.http_probes
        )

        return f"""## 🕸️ HTTP Services ({len(r.http_probes)} live)

| URL | Status | Title | Size | Technologies |
|-----|--------|-------|------|--------------|
{rows}"""

    def _vulnerabilities_section(self, r: ScanResult, cve_details: dict) -> str:
        if not r.vulnerabilities:
            return "## 🐛 Vulnerability Findings\n\n✅ No vulnerabilities detected."

        sections = [f"## 🐛 Vulnerability Findings ({r.total_vulnerabilities} total)\n"]
        counts = r.severity_counts()

        sections.append(
            f"> 🔴 Critical: **{counts['critical']}** | "
            f"🟠 High: **{counts['high']}** | "
            f"🟡 Medium: **{counts['medium']}** | "
            f"🔵 Low: **{counts['low']}**"
        )

        for vuln in r.vulnerabilities:
            emoji = SEVERITY_EMOJI.get(vuln.severity, "❔")
            badge = SEVERITY_BADGE.get(vuln.severity, "")
            cve_str = " · ".join(f"`{c}`" for c in vuln.cve_ids) or "—"
            cvss_str = f"**{vuln.cvss_score}**" if vuln.cvss_score else "—"
            refs = "\n".join(f"  - {r}" for r in vuln.reference[:3]) or "  —"
            mitre = " · ".join(
                f"`{t}` {get_technique_name(t)}"
                for t in vuln.mitre_techniques
            ) or "—"

            sections.append(f"""---

### {emoji} {vuln.name}

{badge}

| Field | Value |
|-------|-------|
| Template | `{vuln.template_id}` |
| Host | `{vuln.host}` |
| Matched At | `{vuln.matched_at}` |
| CVE | {cve_str} |
| CVSS | {cvss_str} |
| MITRE | {mitre} |

**Description:** {vuln.description or "_No description provided._"}

**References:**
{refs}""")

        return "\n".join(sections)

    def _mitre_section(self, mitre_summary: dict) -> str:
        if not mitre_summary:
            return ""

        lines = ["## 🛡️ MITRE ATT&CK Mapping\n"]
        lines.append("> Vulnerabilities mapped to MITRE ATT&CK Enterprise framework\n")

        for tactic, techniques in sorted(mitre_summary.items()):
            lines.append(f"### {tactic}\n")
            for technique_key, vuln_names in sorted(techniques.items()):
                vuln_list = ", ".join(set(vuln_names))
                lines.append(f"- **{technique_key}** — {vuln_list}")
            lines.append("")

        return "\n".join(lines)

    def _cve_details_section(self, cve_details: dict[str, CVEDetail]) -> str:
        if not cve_details:
            return ""

        lines = ["## 🔖 CVE Details\n"]

        for cve_id, detail in sorted(cve_details.items()):
            severity_label, emoji = cvss_to_label(detail.cvss_score)
            refs = "\n".join(f"  - {r}" for r in detail.references[:3]) or "  —"

            lines.append(f"""### {emoji} {detail.cve_id}

| Field | Value |
|-------|-------|
| CVSS Score | **{detail.cvss_score}** ({severity_label}) |
| CVSS Vector | `{detail.cvss_vector or "N/A"}` |
| Published | {detail.published[:10] if detail.published else "Unknown"} |
| CWE | {", ".join(detail.cwe) or "N/A"} |

**Description:** {detail.description[:500] or "_No description._"}

**References:**
{refs}

---""")

        return "\n".join(lines)

    def _screenshots_section(self, r: ScanResult) -> str:
        if not r.screenshots:
            return "## 📸 Screenshots\n\n_No screenshots captured._"

        lines = [f"## 📸 Screenshots ({r.total_screenshots} captured)\n"]

        for sc in r.screenshots:
            rel_path = Path(sc.path).name
            url_label = sc.url or rel_path
            lines.append(f"### {url_label}\n")
            lines.append(f"![{url_label}](../screenshots/{rel_path})\n")

        return "\n".join(lines)

    def _remediation_section(self, r: ScanResult) -> str:
        counts = r.severity_counts()
        if not r.vulnerabilities:
            return ""

        items = []
        if counts["critical"] > 0:
            items.append("1. 🔴 **Patch critical vulnerabilities immediately** — these represent direct compromise risk")
        if counts["high"] > 0:
            items.append("2. 🟠 **Remediate high-severity findings within 7 days** — prioritize by CVSS score")
        if counts["medium"] > 0:
            items.append("3. 🟡 **Address medium findings within 30 days** — schedule in next sprint")

        # Technology-specific recommendations
        tech_set = set()
        for p in r.http_probes:
            tech_set.update(t.lower() for t in p.technologies)

        if "wordpress" in tech_set:
            items.append("- Keep WordPress core, themes, and plugins up to date")
        if "nginx" in tech_set or "apache" in tech_set:
            items.append("- Harden web server configuration; disable unnecessary modules")
        if "php" in tech_set:
            items.append("- Update PHP to a supported version; review php.ini security settings")

        items.append("- Implement a Web Application Firewall (WAF)")
        items.append("- Enable HTTPS everywhere and enforce HSTS")
        items.append("- Set up regular automated scanning in your CI/CD pipeline")
        items.append("- Review exposed subdomains and remove unused services")

        return f"""## 🛠️ Remediation Recommendations

{chr(10).join(items)}"""

    def _footer(self, r: ScanResult) -> str:
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        return f"""---

_Generated by [Auto Recon Framework](https://github.com/your-org/auto-recon) · {ts}_
_Tools: nmap · subfinder · httpx · nuclei · MITRE ATT&CK_"""
