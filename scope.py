"""
Auto Recon Framework - Scope & Target Validation
Validates targets, manages scope exclusions, resolves DNS
"""
import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from utils.logger import log

MODULE = "scope"


@dataclass
class ScopeConfig:
    """Defines what is in and out of scope for a scan."""
    targets: list[str] = field(default_factory=list)
    exclude_hosts: list[str] = field(default_factory=list)
    exclude_cidrs: list[str] = field(default_factory=list)
    exclude_domains: list[str] = field(default_factory=list)
    allowed_ports: list[int] = field(default_factory=list)   # empty = all ports


@dataclass
class ResolvedTarget:
    raw: str
    normalized: str
    is_ip: bool
    is_domain: bool
    ip_address: Optional[str] = None
    is_private: bool = False
    is_valid: bool = True
    error: str = ""


PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def validate_target(target: str) -> ResolvedTarget:
    """
    Parse, validate, and resolve a target string.
    Returns a ResolvedTarget with metadata about the target.
    """
    raw = target.strip()
    # Strip protocol if present
    if "://" in raw:
        parsed = urlparse(raw)
        normalized = parsed.netloc or parsed.path
    else:
        normalized = raw.rstrip("/")

    result = ResolvedTarget(raw=raw, normalized=normalized, is_ip=False, is_domain=False)

    # Check IP
    try:
        ip = ipaddress.ip_address(normalized)
        result.is_ip = True
        result.ip_address = str(ip)
        result.is_private = any(ip in net for net in PRIVATE_RANGES)
        return result
    except ValueError:
        pass

    # Check domain
    domain_re = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    if domain_re.match(normalized):
        result.is_domain = True
        # Attempt DNS resolution
        try:
            ip_str = socket.gethostbyname(normalized)
            result.ip_address = ip_str
            ip_obj = ipaddress.ip_address(ip_str)
            result.is_private = any(ip_obj in net for net in PRIVATE_RANGES)
        except socket.gaierror:
            log.warning(f"DNS resolution failed for {normalized}", MODULE)
        return result

    # CIDR range
    try:
        network = ipaddress.ip_network(normalized, strict=False)
        result.is_ip = True  # treat CIDR as IP-type
        result.is_private = network.is_private
        return result
    except ValueError:
        pass

    result.is_valid = False
    result.error = f"Cannot parse '{normalized}' as IP, domain, or CIDR"
    return result


def check_scope(target: str, scope: ScopeConfig) -> tuple[bool, str]:
    """
    Check if a target falls within defined scope.
    Returns (in_scope: bool, reason: str)
    """
    normalized = target.strip()

    # Check explicit exclusions
    for excl in scope.exclude_hosts:
        if normalized == excl.strip():
            return False, f"Excluded host: {excl}"

    # Check CIDR exclusions
    try:
        ip_obj = ipaddress.ip_address(normalized)
        for cidr in scope.exclude_cidrs:
            if ip_obj in ipaddress.ip_network(cidr, strict=False):
                return False, f"Excluded CIDR: {cidr}"
    except ValueError:
        pass

    # Check domain exclusions
    for excl_domain in scope.exclude_domains:
        if normalized.endswith(f".{excl_domain}") or normalized == excl_domain:
            return False, f"Excluded domain: {excl_domain}"

    return True, "in scope"


def load_targets_from_file(path: str) -> list[str]:
    """Read targets from a file (one per line, # comments ignored)."""
    targets = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
    except FileNotFoundError:
        log.error(f"Targets file not found: {path}", MODULE)
    return targets


def resolve_subdomain_ips(subdomains: list[str], timeout: float = 2.0) -> dict[str, str]:
    """
    Bulk DNS resolve a list of subdomains.
    Returns {subdomain: ip_address} for successful resolutions.
    """
    import concurrent.futures
    results = {}

    def _resolve(sub: str) -> tuple[str, Optional[str]]:
        try:
            socket.setdefaulttimeout(timeout)
            ip = socket.gethostbyname(sub)
            return sub, ip
        except Exception:
            return sub, None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(_resolve, s): s for s in subdomains}
        for future in concurrent.futures.as_completed(futures):
            sub, ip = future.result()
            if ip:
                results[sub] = ip

    return results
