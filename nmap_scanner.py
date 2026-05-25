"""
Auto Recon Framework - Nmap Port Scanner Module
MITRE ATT&CK: T1046 (Network Service Discovery)
"""
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from core.config import ReconConfig
from core.models import PortInfo, ScanResult, ScanStatus
from utils.helpers import run_command, tool_exists, ensure_dirs
from utils.logger import log


MITRE_TACTICS  = ["TA0007"]   # Discovery
MITRE_TECHNIQUES = ["T1046"]  # Network Service Scanning


class NmapScanner:
    """Wraps nmap to perform comprehensive port + service scanning."""

    MODULE = "nmap"

    def __init__(self, config: ReconConfig):
        self.config = config
        self.nmap_cfg = config.nmap
        self.output_dir = config.output.json_dir

    def scan(self, result: ScanResult) -> ScanResult:
        if not tool_exists("nmap"):
            log.warning("nmap not found — skipping port scan", self.MODULE)
            result.nmap_status = ScanStatus.SKIPPED
            return result

        target = result.target
        xml_out = str(Path(self.output_dir) / f"{result.scan_id}_nmap.xml")
        ensure_dirs(self.output_dir)

        log.info(f"Starting port scan on {target}", self.MODULE)
        result.nmap_status = ScanStatus.RUNNING

        cmd = self._build_command(target, xml_out)
        log.debug(f"Running: {' '.join(cmd)}", self.MODULE)

        rc, stdout, stderr = run_command(cmd, timeout=self.nmap_cfg.timeout)

        if rc == -2:
            log.error("nmap binary not found", self.MODULE)
            result.nmap_status = ScanStatus.FAILED
            return result

        if rc not in (0, 1):  # nmap exits 1 for "no hosts up"
            log.error(f"nmap failed (exit {rc}): {stderr[:200]}", self.MODULE)
            result.nmap_status = ScanStatus.FAILED
            return result

        # Parse XML output
        ports = self._parse_xml(xml_out)
        result.ports = ports
        result.total_ports = len(ports)
        result.nmap_status = ScanStatus.COMPLETED

        log.success(f"Found {len(ports)} open ports on {target}", self.MODULE)
        for p in ports[:10]:  # log first 10
            log.info(f"  {p.port}/{p.protocol}  {p.service:<20} {p.version}", self.MODULE)

        return result

    def _build_command(self, target: str, xml_out: str) -> list[str]:
        cmd = ["nmap"]
        # Flags
        for flag in self.nmap_cfg.flags.split():
            cmd.append(flag)
        # Timing
        cmd.append(self.nmap_cfg.timing)
        # Ports
        cmd.extend(["-p", self.nmap_cfg.ports])
        # XML output
        cmd.extend(["-oX", xml_out])
        # Extra args
        if self.nmap_cfg.extra_args:
            cmd.extend(self.nmap_cfg.extra_args.split())
        cmd.append(target)
        return cmd

    def _parse_xml(self, xml_path: str) -> list[PortInfo]:
        """Parse nmap XML output into PortInfo list."""
        ports = []
        if not Path(xml_path).exists():
            return ports

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            for host in root.findall("host"):
                # Check host is up
                status = host.find("status")
                if status is not None and status.get("state") != "up":
                    continue

                ports_elem = host.find("ports")
                if ports_elem is None:
                    continue

                for port_elem in ports_elem.findall("port"):
                    state_elem = port_elem.find("state")
                    if state_elem is None or state_elem.get("state") != "open":
                        continue

                    portid   = int(port_elem.get("portid", 0))
                    protocol = port_elem.get("protocol", "tcp")

                    service_elem = port_elem.find("service")
                    service = ""
                    version = ""
                    if service_elem is not None:
                        service = service_elem.get("name", "")
                        product = service_elem.get("product", "")
                        ver     = service_elem.get("version", "")
                        extra   = service_elem.get("extrainfo", "")
                        parts   = [product, ver, extra]
                        version = " ".join(p for p in parts if p)

                    # Banner from script output
                    banner = ""
                    for script in port_elem.findall("script"):
                        if script.get("id") == "banner":
                            banner = script.get("output", "")[:200]
                            break

                    ports.append(PortInfo(
                        port=portid,
                        protocol=protocol,
                        state="open",
                        service=service,
                        version=version,
                        banner=banner,
                    ))

        except ET.ParseError as e:
            log.error(f"Failed to parse nmap XML: {e}", self.MODULE)

        return sorted(ports, key=lambda p: p.port)
