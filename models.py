"""
Auto Recon Framework - Data Models
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from enum import Enum


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


@dataclass
class PortInfo:
    port: int
    protocol: str
    state: str
    service: str
    version: str = ""
    banner: str = ""


@dataclass
class SubdomainInfo:
    subdomain: str
    ip: str = ""
    status: str = ""
    alive: bool = False
    technologies: list = field(default_factory=list)
    title: str = ""
    content_length: int = 0


@dataclass
class VulnerabilityFinding:
    template_id: str
    name: str
    severity: Severity
    host: str
    matched_at: str
    description: str = ""
    reference: list = field(default_factory=list)
    cve_ids: list = field(default_factory=list)
    cvss_score: float = 0.0
    tags: list = field(default_factory=list)
    mitre_tactics: list = field(default_factory=list)
    mitre_techniques: list = field(default_factory=list)


@dataclass
class ScreenshotInfo:
    url: str
    path: str
    title: str = ""
    status_code: int = 0
    timestamp: str = ""


@dataclass
class ScanResult:
    target: str
    scan_id: str
    started_at: datetime = field(default_factory=datetime.utcnow)
    finished_at: Optional[datetime] = None
    status: ScanStatus = ScanStatus.PENDING

    # Module results
    ports: list[PortInfo] = field(default_factory=list)
    subdomains: list[SubdomainInfo] = field(default_factory=list)
    vulnerabilities: list[VulnerabilityFinding] = field(default_factory=list)
    screenshots: list[ScreenshotInfo] = field(default_factory=list)
    http_probes: list[SubdomainInfo] = field(default_factory=list)

    # Summary
    total_ports: int = 0
    total_subdomains: int = 0
    total_vulnerabilities: int = 0
    total_screenshots: int = 0

    # Module statuses
    nmap_status: ScanStatus = ScanStatus.PENDING
    subfinder_status: ScanStatus = ScanStatus.PENDING
    httpx_status: ScanStatus = ScanStatus.PENDING
    nuclei_status: ScanStatus = ScanStatus.PENDING
    screenshot_status: ScanStatus = ScanStatus.PENDING

    def update_summary(self):
        self.total_ports = len(self.ports)
        self.total_subdomains = len(self.subdomains)
        self.total_vulnerabilities = len(self.vulnerabilities)
        self.total_screenshots = len(self.screenshots)

    def severity_counts(self) -> dict:
        counts = {s.value: 0 for s in Severity}
        for vuln in self.vulnerabilities:
            counts[vuln.severity.value] += 1
        return counts
