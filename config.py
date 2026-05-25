"""
Auto Recon Framework - Configuration Management
"""
import os
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class NmapConfig:
    ports: str = "1-65535"
    timing: str = "-T4"
    flags: str = "-sV -sC -O --open"
    timeout: int = 300
    extra_args: str = ""


@dataclass
class SubfinderConfig:
    timeout: int = 30
    threads: int = 100
    recursive: bool = True
    all_sources: bool = False
    resolvers: list = field(default_factory=lambda: ["8.8.8.8", "1.1.1.1"])


@dataclass
class HttpxConfig:
    timeout: int = 10
    threads: int = 50
    follow_redirects: bool = True
    probe_tech: bool = True
    status_codes: bool = True
    title: bool = True
    content_length: bool = True


@dataclass
class NucleiConfig:
    templates: list = field(default_factory=lambda: ["cves", "vulnerabilities", "exposures", "misconfiguration"])
    severity: list = field(default_factory=lambda: ["critical", "high", "medium"])
    rate_limit: int = 150
    bulk_size: int = 25
    timeout: int = 10
    retries: int = 1
    update_templates: bool = True


@dataclass
class ScreenshotConfig:
    enabled: bool = True
    timeout: int = 15
    threads: int = 10
    full_page: bool = False


@dataclass
class OutputConfig:
    base_dir: str = "output"
    reports_dir: str = "output/reports"
    screenshots_dir: str = "output/screenshots"
    json_dir: str = "output/json"
    format: list = field(default_factory=lambda: ["markdown", "json"])


@dataclass
class ReconConfig:
    # General
    target: str = ""
    scan_id: str = ""
    output: OutputConfig = field(default_factory=OutputConfig)
    threads: int = 10
    timeout: int = 600
    verbose: bool = False
    debug: bool = False

    # Module toggles
    run_nmap: bool = True
    run_subfinder: bool = True
    run_httpx: bool = True
    run_nuclei: bool = True
    run_screenshots: bool = True

    # Module configs
    nmap: NmapConfig = field(default_factory=NmapConfig)
    subfinder: SubfinderConfig = field(default_factory=SubfinderConfig)
    httpx: HttpxConfig = field(default_factory=HttpxConfig)
    nuclei: NucleiConfig = field(default_factory=NucleiConfig)
    screenshot: ScreenshotConfig = field(default_factory=ScreenshotConfig)

    # Reporting
    report_title: str = "Auto Recon Report"
    include_mitre: bool = True
    include_cve_details: bool = True


def load_config(config_path: Optional[str] = None, **overrides) -> ReconConfig:
    """Load configuration from file and apply CLI overrides."""
    config = ReconConfig()

    # Load from file if provided
    if config_path and Path(config_path).exists():
        with open(config_path) as f:
            data = yaml.safe_load(f)
        _apply_dict(config, data)

    # Apply environment variables
    _apply_env(config)

    # Apply CLI overrides
    for key, val in overrides.items():
        if val is not None and hasattr(config, key):
            setattr(config, key, val)

    return config


def _apply_dict(config: ReconConfig, data: dict):
    """Apply dict values to config object recursively."""
    for key, val in data.items():
        if hasattr(config, key):
            attr = getattr(config, key)
            if hasattr(attr, '__dataclass_fields__') and isinstance(val, dict):
                _apply_dict(attr, val)
            else:
                setattr(config, key, val)


def _apply_env(config: ReconConfig):
    """Apply relevant environment variables."""
    env_map = {
        "RECON_TARGET": "target",
        "RECON_THREADS": "threads",
        "RECON_VERBOSE": "verbose",
        "RECON_OUTPUT_DIR": ("output", "base_dir"),
    }
    for env_key, cfg_key in env_map.items():
        val = os.getenv(env_key)
        if val:
            if isinstance(cfg_key, tuple):
                obj = getattr(config, cfg_key[0])
                setattr(obj, cfg_key[1], val)
            else:
                setattr(config, cfg_key, val)


DEFAULT_CONFIG_YAML = """
# Auto Recon Framework Configuration
# See docs/configuration.md for full reference

output:
  base_dir: output
  format:
    - markdown
    - json

nmap:
  ports: "1-65535"
  timing: "-T4"
  flags: "-sV -sC -O --open"
  timeout: 300

subfinder:
  threads: 100
  recursive: true
  resolvers:
    - 8.8.8.8
    - 1.1.1.1

httpx:
  threads: 50
  timeout: 10
  follow_redirects: true
  probe_tech: true

nuclei:
  templates:
    - cves
    - vulnerabilities
    - exposures
    - misconfiguration
  severity:
    - critical
    - high
    - medium
  rate_limit: 150
  update_templates: true

screenshot:
  enabled: true
  timeout: 15
  threads: 10
"""
