"""
Auto Recon Framework - Scan Engine
Orchestrates all recon modules in sequence
"""
import time
from datetime import datetime, timezone
from pathlib import Path

from core.config import ReconConfig
from core.models import ScanResult, ScanStatus
from modules.nmap_scanner import NmapScanner
from modules.subfinder_scanner import SubfinderScanner
from modules.httpx_prober import HttpxProber
from modules.nuclei_scanner import NucleiScanner
from modules.screenshot_capture import ScreenshotCapture
from reporting.markdown_reporter import MarkdownReporter
from reporting.json_reporter import JsonReporter
from reporting.html_reporter import HtmlReporter
from utils.helpers import generate_scan_id, normalize_target, ensure_dirs, format_duration
from utils.logger import log, GREEN, RESET, BOLD


class ReconEngine:
    """
    Central orchestrator for the Auto Recon Framework.
    Runs modules sequentially, aggregates results, and generates reports.
    """

    def __init__(self, config: ReconConfig):
        self.config = config
        self._setup_output_dirs()

    def _setup_output_dirs(self):
        ensure_dirs(
            self.config.output.base_dir,
            self.config.output.reports_dir,
            self.config.output.screenshots_dir,
            self.config.output.json_dir,
        )

    def run(self, target: str) -> ScanResult:
        """Execute full recon pipeline against target."""
        log.banner()

        target = normalize_target(target)
        scan_id = self.config.scan_id or generate_scan_id(target)

        result = ScanResult(
            target=target,
            scan_id=scan_id,
            started_at=datetime.utcnow(),
            status=ScanStatus.RUNNING,
        )

        log.info(f"Starting recon scan: {scan_id}", "engine")
        log.info(f"Target: {target}", "engine")
        log.info(f"Output: {self.config.output.base_dir}", "engine")
        print()

        start = time.time()

        try:
            # ── Phase 1: Port Discovery ────────────────────────────────────
            if self.config.run_nmap:
                log.info("━━ Phase 1/5: Port Scanning ━━━━━━━━━━━━━━━━━━━━━", "engine")
                scanner = NmapScanner(self.config)
                result = scanner.scan(result)
                print()

            # ── Phase 2: Subdomain Enumeration ────────────────────────────
            if self.config.run_subfinder:
                log.info("━━ Phase 2/5: Subdomain Enumeration ━━━━━━━━━━━━━", "engine")
                subfinder = SubfinderScanner(self.config)
                result = subfinder.scan(result)
                print()

            # ── Phase 3: HTTP Probing ──────────────────────────────────────
            if self.config.run_httpx:
                log.info("━━ Phase 3/5: HTTP Probing ━━━━━━━━━━━━━━━━━━━━━━", "engine")
                prober = HttpxProber(self.config)
                result = prober.probe(result)
                print()

            # ── Phase 4: Vulnerability Scanning ───────────────────────────
            if self.config.run_nuclei:
                log.info("━━ Phase 4/5: Vulnerability Scanning ━━━━━━━━━━━━", "engine")
                nuclei = NucleiScanner(self.config)
                result = nuclei.scan(result)
                print()

            # ── Phase 5: Screenshots ───────────────────────────────────────
            if self.config.run_screenshots:
                log.info("━━ Phase 5/5: Screenshots ━━━━━━━━━━━━━━━━━━━━━━━", "engine")
                capture = ScreenshotCapture(self.config)
                result = capture.capture(result)
                print()

            result.status = ScanStatus.COMPLETED

        except KeyboardInterrupt:
            log.warning("Scan interrupted by user", "engine")
            result.status = ScanStatus.FAILED

        except Exception as e:
            log.error(f"Scan engine error: {e}", "engine")
            result.status = ScanStatus.FAILED
            import traceback
            if self.config.debug:
                traceback.print_exc()

        finally:
            result.finished_at = datetime.utcnow()

        # ── Reporting ──────────────────────────────────────────────────────
        log.info("━━ Generating Reports ━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "engine")
        report_paths = self._generate_reports(result)

        duration = format_duration(time.time() - start)
        counts = result.severity_counts()

        self._print_summary(result, report_paths, duration, counts)

        return result

    def _generate_reports(self, result: ScanResult) -> dict[str, str]:
        paths = {}
        formats = self.config.output.format

        if "markdown" in formats:
            reporter = MarkdownReporter(self.config)
            paths["markdown"] = reporter.generate(result)

        if "json" in formats:
            reporter = JsonReporter(self.config)
            paths["json"] = reporter.generate(result)

        if "html" in formats:
            reporter = HtmlReporter(self.config)
            paths["html"] = reporter.generate(result)

        return paths

    def _print_summary(self, result: ScanResult, report_paths: dict, duration: str, counts: dict):
        print(f"""
{BOLD}{'═' * 58}{RESET}
{GREEN}{BOLD}  SCAN COMPLETE{RESET}
{'═' * 58}
  Target     : {result.target}
  Scan ID    : {result.scan_id}
  Duration   : {duration}
  Status     : {result.status.value.upper()}

  Ports      : {result.total_ports}
  Subdomains : {result.total_subdomains}
  Vulns      : {result.total_vulnerabilities} (Critical:{counts['critical']} High:{counts['high']} Med:{counts['medium']})
  Screenshots: {result.total_screenshots}
{'─' * 58}""")

        for fmt, path in report_paths.items():
            print(f"  📄 {fmt.upper():<10}: {path}")

        print(f"{'═' * 58}\n")
