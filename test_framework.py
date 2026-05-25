"""
Auto Recon Framework - Unit Tests
"""
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime

from core.models import (
    ScanResult, PortInfo, SubdomainInfo, VulnerabilityFinding,
    Severity, ScanStatus
)
from core.config import load_config, ReconConfig
from utils.helpers import (
    is_ip, is_domain, normalize_target, generate_scan_id,
    format_duration, sanitize_filename
)
from reporting.cve_mapper import cvss_to_label, get_tactic_name, get_technique_name


# ── Model Tests ───────────────────────────────────────────────────────────────

class TestScanResult:
    def test_update_summary(self):
        r = ScanResult(target="example.com", scan_id="test_001")
        r.ports = [PortInfo(80, "tcp", "open", "http")]
        r.subdomains = [
            SubdomainInfo("sub1.example.com"),
            SubdomainInfo("sub2.example.com"),
        ]
        r.vulnerabilities = [
            VulnerabilityFinding("tmpl-1", "Test Vuln", Severity.HIGH, "example.com", "http://example.com/test"),
        ]
        r.update_summary()

        assert r.total_ports == 1
        assert r.total_subdomains == 2
        assert r.total_vulnerabilities == 1

    def test_severity_counts(self):
        r = ScanResult(target="example.com", scan_id="test_002")
        r.vulnerabilities = [
            VulnerabilityFinding("t1", "V1", Severity.CRITICAL, "h", "url"),
            VulnerabilityFinding("t2", "V2", Severity.CRITICAL, "h", "url"),
            VulnerabilityFinding("t3", "V3", Severity.HIGH, "h", "url"),
            VulnerabilityFinding("t4", "V4", Severity.INFO, "h", "url"),
        ]
        counts = r.severity_counts()

        assert counts["critical"] == 2
        assert counts["high"] == 1
        assert counts["medium"] == 0
        assert counts["info"] == 1


# ── Helper Tests ──────────────────────────────────────────────────────────────

class TestHelpers:
    def test_is_ip_valid(self):
        assert is_ip("192.168.1.1") is True
        assert is_ip("10.0.0.1") is True
        assert is_ip("127.0.0.1") is True

    def test_is_ip_invalid(self):
        assert is_ip("example.com") is False
        assert is_ip("not-an-ip") is False
        assert is_ip("") is False

    def test_is_domain(self):
        assert is_domain("example.com") is True
        assert is_domain("sub.example.co.uk") is True
        assert is_domain("192.168.1.1") is False
        assert is_domain("not a domain") is False

    def test_normalize_target(self):
        assert normalize_target("https://example.com/") == "example.com"
        assert normalize_target("http://example.com") == "example.com"
        assert normalize_target("example.com") == "example.com"
        assert normalize_target("  example.com  ") == "example.com"

    def test_generate_scan_id(self):
        sid = generate_scan_id("example.com")
        assert sid.startswith("scan_")
        assert len(sid) > 10

    def test_format_duration(self):
        assert "s" in format_duration(45)
        assert "m" in format_duration(90)
        assert "h" in format_duration(4000)

    def test_sanitize_filename(self):
        assert sanitize_filename("http://example.com/path?q=1") == "http___example.com_path_q_1"
        assert sanitize_filename("normal.txt") == "normal.txt"


# ── Config Tests ──────────────────────────────────────────────────────────────

class TestConfig:
    def test_default_config(self):
        config = load_config()
        assert config.run_nmap is True
        assert config.run_subfinder is True
        assert config.run_httpx is True
        assert config.run_nuclei is True
        assert config.nmap.timing == "-T4"
        assert config.nuclei.rate_limit == 150

    def test_config_overrides(self):
        config = load_config(run_nmap=False, verbose=True)
        assert config.run_nmap is False
        assert config.verbose is True

    def test_nuclei_severity_default(self):
        config = load_config()
        assert "critical" in config.nuclei.severity
        assert "high" in config.nuclei.severity


# ── CVE Mapper Tests ──────────────────────────────────────────────────────────

class TestCVEMapper:
    def test_cvss_to_label(self):
        label, emoji = cvss_to_label(9.5)
        assert label == "Critical"
        assert "🔴" in emoji

        label, emoji = cvss_to_label(7.5)
        assert label == "High"

        label, emoji = cvss_to_label(5.0)
        assert label == "Medium"

        label, emoji = cvss_to_label(2.0)
        assert label == "Low"

    def test_tactic_name(self):
        assert get_tactic_name("TA0043") == "Reconnaissance"
        assert get_tactic_name("TA0007") == "Discovery"
        assert get_tactic_name("UNKNOWN") == "UNKNOWN"

    def test_technique_name(self):
        assert get_technique_name("T1046") == "Network Service Discovery"
        assert get_technique_name("T1190") == "Exploit Public-Facing Application"


# ── Module Integration Tests (mocked) ────────────────────────────────────────

class TestNmapScanner:
    @patch("modules.nmap_scanner.tool_exists", return_value=False)
    def test_skips_when_not_installed(self, mock_exists):
        from modules.nmap_scanner import NmapScanner
        from core.config import load_config

        config = load_config()
        scanner = NmapScanner(config)
        result = ScanResult(target="example.com", scan_id="test_nmap")
        result = scanner.scan(result)

        assert result.nmap_status == ScanStatus.SKIPPED

    @patch("modules.nmap_scanner.tool_exists", return_value=True)
    @patch("modules.nmap_scanner.run_command", return_value=(0, "", ""))
    def test_runs_when_installed(self, mock_cmd, mock_exists):
        from modules.nmap_scanner import NmapScanner
        from core.config import load_config

        config = load_config()
        scanner = NmapScanner(config)
        result = ScanResult(target="example.com", scan_id="test_nmap_2")

        # Should attempt to run and then parse (empty) XML
        result = scanner.scan(result)
        assert result.nmap_status in (ScanStatus.COMPLETED, ScanStatus.FAILED)


class TestSubfinderScanner:
    @patch("modules.subfinder_scanner.tool_exists", return_value=False)
    def test_skips_ip_target(self, mock_exists):
        from modules.subfinder_scanner import SubfinderScanner
        from core.config import load_config

        config = load_config()
        scanner = SubfinderScanner(config)
        result = ScanResult(target="192.168.1.1", scan_id="test_sf")
        result = scanner.scan(result)

        assert result.subfinder_status == ScanStatus.SKIPPED


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
