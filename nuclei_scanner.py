"""
Auto Recon Framework - Nuclei Vulnerability Scanning Module
MITRE ATT&CK: T1595.002 (Active Scanning: Vulnerability Scanning)
"""
import json
import re
from pathlib import Path

from core.config import ReconConfig
from core.models import VulnerabilityFinding, Severity, ScanResult, ScanStatus
from utils.helpers import run_command, tool_exists, ensure_dirs
from utils.logger import log


MITRE_TACTICS    = ["TA0043"]
MITRE_TECHNIQUES = ["T1595.002"]

# Template → MITRE technique mapping
TEMPLATE_MITRE_MAP = {
    "cves":                ["T1190"],          # Exploit Public-Facing Application
    "vulnerabilities":     ["T1190", "T1203"], # Exploitation for Client Execution
    "exposures":           ["T1083"],          # File and Directory Discovery
    "misconfiguration":    ["T1078"],          # Valid Accounts
    "default-credentials": ["T1078.001"],      # Default Credentials
    "takeovers":           ["T1584"],          # Compromise Infrastructure
    "technologies":        ["T1592.002"],      # Software
    "network":             ["T1046"],          # Network Service Scanning
    "file":                ["T1083"],          # File and Directory Discovery
    "xss":                 ["T1059.007"],      # JavaScript
    "sqli":                ["T1190"],          # Exploit Public-Facing Application
    "ssrf":                ["T1090"],          # Proxy
    "rce":                 ["T1203"],          # Exploitation for Client Execution
    "lfi":                 ["T1083"],          # File and Directory Discovery
    "xxe":                 ["T1190"],
}

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
    "info":     Severity.INFO,
}


class NucleiScanner:
    """Wraps nuclei for template-based vulnerability scanning."""

    MODULE = "nuclei"

    def __init__(self, config: ReconConfig):
        self.config = config
        self.nc_cfg = config.nuclei
        self.output_dir = config.output.json_dir

    def scan(self, result: ScanResult) -> ScanResult:
        if not tool_exists("nuclei"):
            log.warning("nuclei not found — skipping vuln scan", self.MODULE)
            result.nuclei_status = ScanStatus.SKIPPED
            return result

        targets = self._collect_targets(result)
        if not targets:
            log.info("No HTTP targets for nuclei — skipping", self.MODULE)
            result.nuclei_status = ScanStatus.SKIPPED
            return result

        targets_file = str(Path(self.output_dir) / f"{result.scan_id}_nuclei_targets.txt")
        output_file  = str(Path(self.output_dir) / f"{result.scan_id}_nuclei.jsonl")
        ensure_dirs(self.output_dir)

        with open(targets_file, "w") as f:
            f.write("\n".join(targets))

        # Update templates first
        if self.nc_cfg.update_templates:
            log.info("Updating nuclei templates...", self.MODULE)
            run_command(["nuclei", "-update-templates", "-silent"], timeout=60)

        log.info(f"Running nuclei on {len(targets)} targets", self.MODULE)
        result.nuclei_status = ScanStatus.RUNNING

        cmd = self._build_command(targets_file, output_file)
        log.debug(f"Running: {' '.join(cmd)}", self.MODULE)

        rc, stdout, stderr = run_command(
            cmd,
            timeout=self.config.timeout,
        )

        if rc == -2:
            log.error("nuclei binary not found", self.MODULE)
            result.nuclei_status = ScanStatus.FAILED
            return result

        findings = self._parse_output(output_file)
        result.vulnerabilities = findings
        result.total_vulnerabilities = len(findings)
        result.nuclei_status = ScanStatus.COMPLETED

        counts = result.severity_counts()
        log.success(
            f"nuclei complete — "
            f"CRIT:{counts['critical']} HIGH:{counts['high']} "
            f"MED:{counts['medium']} LOW:{counts['low']} INFO:{counts['info']}",
            self.MODULE
        )

        for vuln in findings:
            log.finding(vuln.severity.value, f"{vuln.name} @ {vuln.matched_at}", self.MODULE)

        return result

    def _collect_targets(self, result: ScanResult) -> list[str]:
        """Use live HTTP probes as nuclei targets."""
        targets = set()
        for probe in result.http_probes:
            if probe.alive and probe.subdomain:
                targets.add(probe.subdomain)
        # Fallback: add main target
        if not targets:
            targets.add(f"http://{result.target}")
            targets.add(f"https://{result.target}")
        return list(targets)

    def _build_command(self, targets_file: str, output_file: str) -> list[str]:
        cmd = [
            "nuclei",
            "-l", targets_file,
            "-o", output_file,
            "-json",
            "-silent",
            "-rate-limit", str(self.nc_cfg.rate_limit),
            "-bulk-size", str(self.nc_cfg.bulk_size),
            "-timeout", str(self.nc_cfg.timeout),
            "-retries", str(self.nc_cfg.retries),
        ]
        # Severity filter
        if self.nc_cfg.severity:
            cmd.extend(["-severity", ",".join(self.nc_cfg.severity)])
        # Templates
        if self.nc_cfg.templates:
            for tmpl in self.nc_cfg.templates:
                cmd.extend(["-t", tmpl])
        return cmd

    def _parse_output(self, output_file: str) -> list[VulnerabilityFinding]:
        """Parse nuclei JSONL output into VulnerabilityFinding list."""
        findings = []
        if not Path(output_file).exists():
            return findings

        with open(output_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    info = data.get("info", {})

                    severity_str = info.get("severity", "unknown").lower()
                    severity = SEVERITY_MAP.get(severity_str, Severity.UNKNOWN)

                    # Extract CVE IDs
                    cve_ids = []
                    tags = info.get("tags", [])
                    if isinstance(tags, str):
                        tags = tags.split(",")
                    for tag in tags:
                        if re.match(r'CVE-\d{4}-\d+', tag, re.I):
                            cve_ids.append(tag.upper())
                    # Also check classification block
                    classification = info.get("classification", {})
                    cve_ids += classification.get("cve-id", [])
                    cve_ids = list(set(cve_ids))

                    # MITRE mapping
                    template_id = data.get("template-id", "")
                    mitre_techniques = self._map_to_mitre(template_id, tags)

                    finding = VulnerabilityFinding(
                        template_id=template_id,
                        name=info.get("name", template_id),
                        severity=severity,
                        host=data.get("host", ""),
                        matched_at=data.get("matched-at", ""),
                        description=info.get("description", ""),
                        reference=info.get("reference", []),
                        cve_ids=cve_ids,
                        cvss_score=float(classification.get("cvss-score", 0.0) or 0.0),
                        tags=tags if isinstance(tags, list) else tags.split(","),
                        mitre_tactics=["TA0043"],
                        mitre_techniques=mitre_techniques,
                    )
                    findings.append(finding)
                except (json.JSONDecodeError, ValueError):
                    continue

        # Sort by severity
        order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
                 Severity.LOW: 3, Severity.INFO: 4, Severity.UNKNOWN: 5}
        return sorted(findings, key=lambda f: order.get(f.severity, 5))

    def _map_to_mitre(self, template_id: str, tags: list) -> list[str]:
        """Map nuclei template to MITRE technique IDs."""
        techniques = set()
        tid = template_id.lower()
        for keyword, mitre_ids in TEMPLATE_MITRE_MAP.items():
            if keyword in tid or keyword in tags:
                techniques.update(mitre_ids)
        return list(techniques) or ["T1595.002"]
