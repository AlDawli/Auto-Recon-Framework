"""
Auto Recon Framework - Subfinder Subdomain Enumeration Module
MITRE ATT&CK: T1590.001 (Gather Victim Network Information: Domain Properties)
"""
import json
from pathlib import Path

from core.config import ReconConfig
from core.models import SubdomainInfo, ScanResult, ScanStatus
from utils.helpers import run_command, tool_exists, ensure_dirs, is_ip
from utils.logger import log


MITRE_TACTICS    = ["TA0043"]       # Reconnaissance
MITRE_TECHNIQUES = ["T1590.001"]    # Gather Victim Network Info: Domain Properties


class SubfinderScanner:
    """Wraps subfinder for passive subdomain enumeration."""

    MODULE = "subfinder"

    def __init__(self, config: ReconConfig):
        self.config = config
        self.sf_cfg = config.subfinder
        self.output_dir = config.output.json_dir

    def scan(self, result: ScanResult) -> ScanResult:
        target = result.target

        # Skip for IP targets
        if is_ip(target):
            log.info("Target is IP — skipping subdomain enumeration", self.MODULE)
            result.subfinder_status = ScanStatus.SKIPPED
            return result

        if not tool_exists("subfinder"):
            log.warning("subfinder not found — skipping", self.MODULE)
            result.subfinder_status = ScanStatus.SKIPPED
            return result

        out_file = str(Path(self.output_dir) / f"{result.scan_id}_subdomains.txt")
        ensure_dirs(self.output_dir)

        log.info(f"Enumerating subdomains for {target}", self.MODULE)
        result.subfinder_status = ScanStatus.RUNNING

        cmd = self._build_command(target, out_file)
        log.debug(f"Running: {' '.join(cmd)}", self.MODULE)

        rc, stdout, stderr = run_command(cmd, timeout=self.sf_cfg.timeout * 60)

        if rc == -2:
            log.error("subfinder binary not found", self.MODULE)
            result.subfinder_status = ScanStatus.FAILED
            return result

        if rc != 0:
            log.error(f"subfinder failed (exit {rc})", self.MODULE)
            result.subfinder_status = ScanStatus.FAILED
            return result

        subdomains = self._parse_output(out_file, stdout)
        result.subdomains = subdomains
        result.total_subdomains = len(subdomains)
        result.subfinder_status = ScanStatus.COMPLETED

        log.success(f"Found {len(subdomains)} subdomains for {target}", self.MODULE)
        for sub in subdomains[:10]:
            log.info(f"  {sub.subdomain}", self.MODULE)
        if len(subdomains) > 10:
            log.info(f"  ... and {len(subdomains) - 10} more", self.MODULE)

        return result

    def _build_command(self, target: str, out_file: str) -> list[str]:
        cmd = [
            "subfinder",
            "-d", target,
            "-o", out_file,
            "-t", str(self.sf_cfg.threads),
            "-timeout", str(self.sf_cfg.timeout),
        ]
        if self.sf_cfg.recursive:
            cmd.append("-recursive")
        if self.sf_cfg.all_sources:
            cmd.append("-all")
        if self.sf_cfg.resolvers:
            cmd.extend(["-rL", ",".join(self.sf_cfg.resolvers)])
        cmd.extend(["-silent"])
        return cmd

    def _parse_output(self, out_file: str, stdout: str) -> list[SubdomainInfo]:
        """Parse subfinder output file or stdout."""
        subdomains = []
        lines = []

        if Path(out_file).exists():
            with open(out_file) as f:
                lines = f.read().splitlines()
        elif stdout:
            lines = stdout.splitlines()

        seen = set()
        for line in lines:
            sub = line.strip()
            if sub and sub not in seen:
                seen.add(sub)
                subdomains.append(SubdomainInfo(
                    subdomain=sub,
                    alive=False,  # will be probed by httpx
                ))

        return subdomains
