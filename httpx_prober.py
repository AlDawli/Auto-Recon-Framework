"""
Auto Recon Framework - HTTPX HTTP Probing Module
MITRE ATT&CK: T1590.005 (Gather Victim Network Information: IP Addresses)
              T1592 (Gather Victim Host Information)
"""
import json
from pathlib import Path

from core.config import ReconConfig
from core.models import SubdomainInfo, ScanResult, ScanStatus
from utils.helpers import run_command, tool_exists, ensure_dirs, is_ip
from utils.logger import log


MITRE_TACTICS    = ["TA0043"]
MITRE_TECHNIQUES = ["T1590.005", "T1592"]


class HttpxProber:
    """Wraps httpx for HTTP service detection and fingerprinting."""

    MODULE = "httpx"

    def __init__(self, config: ReconConfig):
        self.config = config
        self.hx_cfg = config.httpx
        self.output_dir = config.output.json_dir

    def probe(self, result: ScanResult) -> ScanResult:
        if not tool_exists("httpx"):
            log.warning("httpx not found — skipping HTTP probing", self.MODULE)
            result.httpx_status = ScanStatus.SKIPPED
            return result

        targets = self._collect_targets(result)
        if not targets:
            log.info("No targets to probe", self.MODULE)
            result.httpx_status = ScanStatus.SKIPPED
            return result

        # Write targets to temp file
        targets_file = str(Path(self.output_dir) / f"{result.scan_id}_httpx_targets.txt")
        output_file  = str(Path(self.output_dir) / f"{result.scan_id}_httpx.jsonl")
        ensure_dirs(self.output_dir)

        with open(targets_file, "w") as f:
            f.write("\n".join(targets))

        log.info(f"Probing {len(targets)} targets via HTTP/HTTPS", self.MODULE)
        result.httpx_status = ScanStatus.RUNNING

        cmd = self._build_command(targets_file, output_file)
        log.debug(f"Running: {' '.join(cmd)}", self.MODULE)

        rc, stdout, stderr = run_command(
            cmd,
            timeout=self.hx_cfg.timeout * len(targets) + 30
        )

        if rc == -2:
            log.error("httpx binary not found", self.MODULE)
            result.httpx_status = ScanStatus.FAILED
            return result

        probes = self._parse_output(output_file)
        result.http_probes = probes

        # Mark alive subdomains
        alive_hosts = {p.subdomain for p in probes if p.alive}
        for sub in result.subdomains:
            if sub.subdomain in alive_hosts or f"http://{sub.subdomain}" in alive_hosts:
                sub.alive = True

        result.httpx_status = ScanStatus.COMPLETED
        log.success(f"HTTP probing complete: {len(probes)} live services", self.MODULE)

        for p in probes[:15]:
            code_color = "✓" if p.status == "200" else "→"
            log.info(
                f"  {code_color} [{p.status:>3}] {p.subdomain:<50} {p.title[:40]}",
                self.MODULE
            )

        return result

    def _collect_targets(self, result: ScanResult) -> list[str]:
        """Build target list from subdomains + main target."""
        targets = set()
        targets.add(result.target)

        for sub in result.subdomains:
            targets.add(sub.subdomain)

        # Also probe discovered HTTP ports from nmap
        for port in result.ports:
            if port.service in ("http", "https", "http-alt") or port.port in (80, 443, 8080, 8443, 8888):
                scheme = "https" if (port.port == 443 or "ssl" in port.service or "https" in port.service) else "http"
                targets.add(f"{scheme}://{result.target}:{port.port}")

        return list(targets)

    def _build_command(self, targets_file: str, output_file: str) -> list[str]:
        cmd = [
            "httpx",
            "-l", targets_file,
            "-o", output_file,
            "-json",
            "-threads", str(self.hx_cfg.threads),
            "-timeout", str(self.hx_cfg.timeout),
            "-silent",
        ]
        if self.hx_cfg.follow_redirects:
            cmd.append("-follow-redirects")
        if self.hx_cfg.probe_tech:
            cmd.append("-tech-detect")
        if self.hx_cfg.status_codes:
            cmd.append("-status-code")
        if self.hx_cfg.title:
            cmd.append("-title")
        if self.hx_cfg.content_length:
            cmd.append("-content-length")
        cmd.extend(["-web-server", "-ip", "-cname"])
        return cmd

    def _parse_output(self, output_file: str) -> list[SubdomainInfo]:
        """Parse httpx JSONL output."""
        probes = []
        if not Path(output_file).exists():
            return probes

        with open(output_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    probe = SubdomainInfo(
                        subdomain=data.get("url", data.get("input", "")),
                        ip=data.get("host", ""),
                        status=str(data.get("status-code", "")),
                        alive=True,
                        title=data.get("title", ""),
                        content_length=data.get("content-length", 0),
                        technologies=data.get("technologies", []),
                    )
                    probes.append(probe)
                except json.JSONDecodeError:
                    continue

        return probes
