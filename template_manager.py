"""
Auto Recon Framework - Nuclei Template Manager
Handles template updates, custom templates, and template validation
"""
import json
import os
from pathlib import Path
from typing import Optional

from utils.helpers import run_command, tool_exists
from utils.logger import log

MODULE = "nuclei"

NUCLEI_TEMPLATES_DIR = Path.home() / "nuclei-templates"

# Template category descriptions for reporting
TEMPLATE_CATEGORIES = {
    "cves":                "Known CVE exploits and vulnerability checks",
    "vulnerabilities":     "Generic vulnerability detection templates",
    "exposures":           "Sensitive file and data exposure checks",
    "misconfiguration":    "Security misconfiguration detection",
    "default-credentials": "Default username/password checks",
    "takeovers":           "Subdomain takeover vulnerability checks",
    "network":             "Network service vulnerability checks",
    "dns":                 "DNS misconfiguration and vulnerability checks",
    "technologies":        "Technology fingerprinting templates",
    "fuzzing":             "Input fuzzing templates (use with caution)",
    "helpers":             "Helper and utility templates",
    "workflows":           "Multi-step workflow templates",
}


def update_templates(silent: bool = True) -> bool:
    """Update nuclei templates to latest version."""
    if not tool_exists("nuclei"):
        log.warning("nuclei not found, cannot update templates", MODULE)
        return False

    log.info("Updating nuclei templates...", MODULE)
    cmd = ["nuclei", "-update-templates"]
    if silent:
        cmd.append("-silent")

    rc, stdout, stderr = run_command(cmd, timeout=120)
    if rc == 0:
        log.success("Templates updated successfully", MODULE)
        return True
    else:
        log.warning(f"Template update failed: {stderr[:100]}", MODULE)
        return False


def get_templates_version() -> Optional[str]:
    """Get current nuclei templates version."""
    version_file = NUCLEI_TEMPLATES_DIR / ".version"
    if version_file.exists():
        return version_file.read_text().strip()
    return None


def list_installed_templates(category: Optional[str] = None) -> dict[str, int]:
    """
    Count templates per category.
    Returns {category: count}
    """
    counts = {}
    if not NUCLEI_TEMPLATES_DIR.exists():
        return counts

    search_root = NUCLEI_TEMPLATES_DIR / category if category else NUCLEI_TEMPLATES_DIR

    for cat_dir in search_root.iterdir() if not category else [search_root]:
        if cat_dir.is_dir() and not cat_dir.name.startswith("."):
            yaml_count = len(list(cat_dir.rglob("*.yaml")))
            if yaml_count > 0:
                counts[cat_dir.name] = yaml_count

    return counts


def validate_custom_template(template_path: str) -> tuple[bool, str]:
    """Validate a custom nuclei template file."""
    path = Path(template_path)
    if not path.exists():
        return False, f"File not found: {template_path}"
    if path.suffix not in (".yaml", ".yml"):
        return False, f"Not a YAML file: {template_path}"

    rc, stdout, stderr = run_command(
        ["nuclei", "-t", template_path, "-validate"],
        timeout=30,
    )
    if rc == 0:
        return True, "Template is valid"
    return False, stderr.strip()


def get_nuclei_stats() -> dict:
    """Get nuclei installation stats."""
    stats = {
        "installed": tool_exists("nuclei"),
        "templates_dir": str(NUCLEI_TEMPLATES_DIR),
        "templates_exist": NUCLEI_TEMPLATES_DIR.exists(),
        "version": None,
        "templates_version": get_templates_version(),
        "template_counts": {},
    }

    if stats["installed"]:
        rc, stdout, _ = run_command(["nuclei", "-version"], timeout=5)
        if rc == 0:
            for line in stdout.splitlines():
                if "nuclei" in line.lower() and "version" in line.lower():
                    stats["version"] = line.strip()
                    break

    if stats["templates_exist"]:
        stats["template_counts"] = list_installed_templates()

    return stats


def build_template_flags(templates: list[str], custom_paths: list[str] = None) -> list[str]:
    """
    Build nuclei -t flags for a list of template categories and custom paths.
    Returns list of ["-t", "category", ...] arguments.
    """
    flags = []
    for tmpl in templates:
        flags.extend(["-t", tmpl])
    for path in (custom_paths or []):
        if Path(path).exists():
            flags.extend(["-t", path])
        else:
            log.warning(f"Custom template path not found: {path}", MODULE)
    return flags


def print_template_summary():
    """Print a summary of installed templates."""
    stats = get_nuclei_stats()

    if not stats["installed"]:
        log.warning("nuclei is not installed", MODULE)
        return

    log.info(f"nuclei version: {stats['version'] or 'unknown'}", MODULE)
    log.info(f"Templates dir: {stats['templates_dir']}", MODULE)
    log.info(f"Templates version: {stats['templates_version'] or 'unknown'}", MODULE)

    if stats["template_counts"]:
        total = sum(stats["template_counts"].values())
        log.info(f"Total templates: {total}", MODULE)
        for cat, count in sorted(stats["template_counts"].items(), key=lambda x: -x[1])[:10]:
            desc = TEMPLATE_CATEGORIES.get(cat, "")
            log.info(f"  {cat:<25} {count:>5} templates  {desc}", MODULE)
