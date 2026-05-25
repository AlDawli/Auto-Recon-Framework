"""
Auto Recon Framework - Screenshot Capture Module
Uses gowitness or chromium headless as fallback
"""
import os
from pathlib import Path

from core.config import ReconConfig
from core.models import ScreenshotInfo, ScanResult, ScanStatus
from utils.helpers import run_command, tool_exists, ensure_dirs
from utils.logger import log
from datetime import datetime


class ScreenshotCapture:
    """Captures screenshots of live web services."""

    MODULE = "screenshot"

    def __init__(self, config: ReconConfig):
        self.config = config
        self.sc_cfg = config.screenshot
        self.screenshots_dir = config.output.screenshots_dir
        self.output_dir = config.output.json_dir

    def capture(self, result: ScanResult) -> ScanResult:
        if not self.sc_cfg.enabled:
            log.info("Screenshots disabled in config", self.MODULE)
            result.screenshot_status = ScanStatus.SKIPPED
            return result

        targets = self._collect_targets(result)
        if not targets:
            log.info("No HTTP targets for screenshots", self.MODULE)
            result.screenshot_status = ScanStatus.SKIPPED
            return result

        ensure_dirs(self.screenshots_dir)
        result.screenshot_status = ScanStatus.RUNNING

        # Prefer gowitness, fallback to chromium
        if tool_exists("gowitness"):
            screenshots = self._capture_gowitness(targets, result.scan_id)
        elif tool_exists("chromium") or tool_exists("chromium-browser") or tool_exists("google-chrome"):
            screenshots = self._capture_chromium(targets, result.scan_id)
        else:
            log.warning("No screenshot tool found (gowitness/chromium) — skipping", self.MODULE)
            result.screenshot_status = ScanStatus.SKIPPED
            return result

        result.screenshots = screenshots
        result.total_screenshots = len(screenshots)
        result.screenshot_status = ScanStatus.COMPLETED

        log.success(f"Captured {len(screenshots)} screenshots", self.MODULE)
        return result

    def _collect_targets(self, result: ScanResult) -> list[str]:
        targets = set()
        for probe in result.http_probes:
            if probe.alive and probe.subdomain:
                targets.add(probe.subdomain)
        if not targets:
            targets.add(f"http://{result.target}")
            targets.add(f"https://{result.target}")
        return list(targets)

    def _capture_gowitness(self, targets: list[str], scan_id: str) -> list[ScreenshotInfo]:
        """Use gowitness to capture screenshots."""
        targets_file = str(Path(self.output_dir) / f"{scan_id}_screenshot_targets.txt")
        db_file      = str(Path(self.screenshots_dir) / f"{scan_id}_gowitness.db")

        with open(targets_file, "w") as f:
            f.write("\n".join(targets))

        log.info(f"Capturing {len(targets)} screenshots with gowitness", self.MODULE)

        cmd = [
            "gowitness",
            "file",
            "-f", targets_file,
            "--destination", self.screenshots_dir,
            "--db-path", db_file,
            "--timeout", str(self.sc_cfg.timeout),
            "--threads", str(self.sc_cfg.threads),
            "--delay", "2",
        ]

        rc, stdout, stderr = run_command(cmd, timeout=self.sc_cfg.timeout * len(targets) + 60)

        return self._collect_screenshots(targets)

    def _capture_chromium(self, targets: list[str], scan_id: str) -> list[ScreenshotInfo]:
        """Fallback: chromium headless screenshots."""
        chrome_bin = None
        for binary in ["chromium", "chromium-browser", "google-chrome"]:
            if tool_exists(binary):
                chrome_bin = binary
                break

        if not chrome_bin:
            return []

        screenshots = []
        for url in targets[:20]:  # limit to 20 for performance
            safe_name = url.replace("://", "_").replace("/", "_").replace(":", "_")
            out_path = str(Path(self.screenshots_dir) / f"{safe_name}.png")

            cmd = [
                chrome_bin,
                "--headless",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                f"--screenshot={out_path}",
                "--window-size=1280,800",
                url,
            ]

            rc, _, _ = run_command(cmd, timeout=self.sc_cfg.timeout)

            if rc == 0 and Path(out_path).exists():
                screenshots.append(ScreenshotInfo(
                    url=url,
                    path=out_path,
                    timestamp=datetime.utcnow().isoformat(),
                ))
                log.info(f"  ✓ {url}", self.MODULE)
            else:
                log.debug(f"  ✗ {url}", self.MODULE)

        return screenshots

    def _collect_screenshots(self, targets: list[str]) -> list[ScreenshotInfo]:
        """Collect screenshot files from the output directory."""
        screenshots = []
        sc_dir = Path(self.screenshots_dir)

        for img_file in sc_dir.glob("*.png"):
            screenshots.append(ScreenshotInfo(
                url="",
                path=str(img_file),
                timestamp=datetime.utcnow().isoformat(),
            ))

        return screenshots
