"""
Auto Recon Framework - JSON Reporter
Outputs structured machine-readable scan results
"""
import dataclasses
import json
from datetime import datetime
from pathlib import Path

from core.config import ReconConfig
from core.models import ScanResult
from utils.logger import log


class JsonReporter:
    """Serializes ScanResult to structured JSON."""

    MODULE = "report"

    def __init__(self, config: ReconConfig):
        self.config = config
        self.reports_dir = config.output.reports_dir

    def generate(self, result: ScanResult) -> str:
        """Write JSON report and return file path."""
        Path(self.reports_dir).mkdir(parents=True, exist_ok=True)

        result.update_summary()
        data = self._serialize(result)

        out_file = str(Path(self.reports_dir) / f"{result.scan_id}_report.json")
        with open(out_file, "w") as f:
            json.dump(data, f, indent=2, default=str)

        log.success(f"JSON report written to {out_file}", self.MODULE)
        return out_file

    def _serialize(self, result: ScanResult) -> dict:
        return {
            "meta": {
                "target": result.target,
                "scan_id": result.scan_id,
                "started_at": result.started_at.isoformat(),
                "finished_at": result.finished_at.isoformat() if result.finished_at else None,
                "status": result.status.value,
                "framework": "Auto Recon Framework v1.0.0",
            },
            "summary": {
                "total_ports": result.total_ports,
                "total_subdomains": result.total_subdomains,
                "total_vulnerabilities": result.total_vulnerabilities,
                "total_screenshots": result.total_screenshots,
                "severity_counts": result.severity_counts(),
                "module_statuses": {
                    "nmap": result.nmap_status.value,
                    "subfinder": result.subfinder_status.value,
                    "httpx": result.httpx_status.value,
                    "nuclei": result.nuclei_status.value,
                    "screenshot": result.screenshot_status.value,
                },
            },
            "ports": [dataclasses.asdict(p) for p in result.ports],
            "subdomains": [dataclasses.asdict(s) for s in result.subdomains],
            "http_probes": [dataclasses.asdict(h) for h in result.http_probes],
            "vulnerabilities": [
                {
                    **dataclasses.asdict(v),
                    "severity": v.severity.value,
                }
                for v in result.vulnerabilities
            ],
            "screenshots": [dataclasses.asdict(s) for s in result.screenshots],
        }
