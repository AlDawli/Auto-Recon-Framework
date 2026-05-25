"""
Auto Recon Framework - Helper Utilities
"""
import hashlib
import json
import re
import socket
import subprocess
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse


def generate_scan_id(target: str) -> str:
    """Generate a unique scan ID from target + timestamp."""
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    short_hash = hashlib.md5(target.encode()).hexdigest()[:6]
    return f"scan_{ts}_{short_hash}"


def is_ip(target: str) -> bool:
    """Check if target is an IP address."""
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        return False


def is_domain(target: str) -> bool:
    """Check if target looks like a domain."""
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    return bool(domain_pattern.match(target))


def normalize_target(target: str) -> str:
    """Strip protocol and trailing slashes from target."""
    target = target.strip()
    if "://" in target:
        target = urlparse(target).netloc or urlparse(target).path
    return target.rstrip("/")


def ensure_dirs(*paths: str):
    """Create directories if they don't exist."""
    for path in paths:
        Path(path).mkdir(parents=True, exist_ok=True)


def run_command(
    cmd: list[str],
    timeout: int = 300,
    capture: bool = True,
    cwd: Optional[str] = None,
) -> tuple[int, str, str]:
    """Run a subprocess command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        return result.returncode, result.stdout or "", result.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s"
    except FileNotFoundError:
        return -2, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return -3, "", str(e)


def tool_exists(tool: str) -> bool:
    """Check if a CLI tool exists on PATH."""
    rc, _, _ = run_command(["which", tool], timeout=5)
    return rc == 0


def check_required_tools(tools: list[str]) -> dict[str, bool]:
    """Return availability map of required tools."""
    return {t: tool_exists(t) for t in tools}


def save_json(data: dict | list, path: str):
    """Save data as pretty-printed JSON."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def load_json(path: str) -> dict | list | None:
    """Load JSON file, returning None on error."""
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def sanitize_filename(name: str) -> str:
    """Make a string safe for use as a filename."""
    return re.sub(r'[^\w\-_.]', '_', name)


def parse_url_list(text: str) -> list[str]:
    """Extract URLs or hosts from newline-separated text."""
    lines = [l.strip() for l in text.splitlines()]
    return [l for l in lines if l and not l.startswith("#")]


def format_duration(seconds: float) -> str:
    """Format duration in human-readable form."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds / 60:.1f}m"
    else:
        return f"{seconds / 3600:.1f}h"


def unique_id() -> str:
    return str(uuid.uuid4())[:8]
