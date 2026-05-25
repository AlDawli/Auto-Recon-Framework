#!/usr/bin/env python3
"""
Auto Recon Framework - CLI Entry Point

Usage:
  python main.py -t example.com
  python main.py -t 192.168.1.1 --no-subfinder --output /tmp/scan
  python main.py -t example.com -c config/custom.yaml --verbose
"""
import argparse
import sys
from pathlib import Path

from core.config import load_config, DEFAULT_CONFIG_YAML
from core.engine import ReconEngine
from utils.logger import log


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="auto-recon",
        description="🔍 Auto Recon Framework — nmap · subfinder · httpx · nuclei",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t example.com
  %(prog)s -t 10.0.0.1 --no-subfinder --no-screenshots
  %(prog)s -t example.com -c config.yaml --output /tmp/recon --verbose
  %(prog)s --init-config          # Generate default config.yaml
        """,
    )

    # Target
    parser.add_argument("-t", "--target", help="Target domain or IP address")

    # Config
    parser.add_argument("-c", "--config", help="Path to YAML config file")

    # Output
    parser.add_argument("-o", "--output", help="Output directory (default: output/)")

    # Module toggles
    parser.add_argument("--no-nmap",        action="store_true", help="Skip nmap port scan")
    parser.add_argument("--no-subfinder",   action="store_true", help="Skip subfinder subdomain enum")
    parser.add_argument("--no-httpx",       action="store_true", help="Skip httpx probing")
    parser.add_argument("--no-nuclei",      action="store_true", help="Skip nuclei vulnerability scan")
    parser.add_argument("--no-screenshots", action="store_true", help="Skip screenshot capture")

    # Nmap options
    parser.add_argument("--ports",          default=None, help="Port range (e.g. '1-1000')")
    parser.add_argument("--nmap-flags",     default=None, help="Extra nmap flags")

    # Nuclei options
    parser.add_argument("--severity",       default=None, help="Nuclei severity filter (e.g. 'critical,high')")
    parser.add_argument("--templates",      default=None, help="Nuclei template tags (comma-separated)")

    # Output options
    parser.add_argument("--format",         default="markdown,json", help="Report format(s): markdown,json")
    parser.add_argument("--scan-id",        default=None, help="Custom scan ID")

    # Verbosity
    parser.add_argument("-v", "--verbose",  action="store_true", help="Verbose output")
    parser.add_argument("--debug",          action="store_true", help="Debug output")

    # Init
    parser.add_argument("--init-config",    action="store_true", help="Write default config.yaml and exit")

    return parser.parse_args()


def main():
    args = parse_args()

    # Init config helper
    if args.init_config:
        config_path = "config.yaml"
        with open(config_path, "w") as f:
            f.write(DEFAULT_CONFIG_YAML)
        print(f"✅ Config written to {config_path}")
        sys.exit(0)

    # Require target
    if not args.target:
        print("❌ Error: --target / -t is required\n")
        print("Run with --help for usage.")
        sys.exit(1)

    # Build config
    overrides = {
        "verbose":          args.verbose,
        "debug":            args.debug,
        "run_nmap":         not args.no_nmap,
        "run_subfinder":    not args.no_subfinder,
        "run_httpx":        not args.no_httpx,
        "run_nuclei":       not args.no_nuclei,
        "run_screenshots":  not args.no_screenshots,
    }

    if args.scan_id:
        overrides["scan_id"] = args.scan_id

    config = load_config(args.config, **overrides)

    # Output dir
    if args.output:
        config.output.base_dir       = args.output
        config.output.reports_dir    = str(Path(args.output) / "reports")
        config.output.screenshots_dir = str(Path(args.output) / "screenshots")
        config.output.json_dir       = str(Path(args.output) / "json")

    # Report format
    config.output.format = [f.strip() for f in args.format.split(",")]

    # Nmap overrides
    if args.ports:
        config.nmap.ports = args.ports
    if args.nmap_flags:
        config.nmap.flags = args.nmap_flags

    # Nuclei overrides
    if args.severity:
        config.nuclei.severity = [s.strip() for s in args.severity.split(",")]
    if args.templates:
        config.nuclei.templates = [t.strip() for t in args.templates.split(",")]

    # Run scan
    engine = ReconEngine(config)
    result = engine.run(args.target)

    # Exit code based on findings
    counts = result.severity_counts()
    if counts["critical"] > 0:
        sys.exit(2)
    elif counts["high"] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
