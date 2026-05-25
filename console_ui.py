"""
Auto Recon Framework - Rich Progress & Console UI
Provides live progress bars and a status dashboard
"""
from contextlib import contextmanager
from datetime import datetime
from typing import Optional

try:
    from rich.console import Console
    from rich.progress import (
        Progress, SpinnerColumn, BarColumn, TextColumn,
        TimeElapsedColumn, TaskProgressColumn, MofNCompleteColumn,
    )
    from rich.table import Table
    from rich.panel import Panel
    from rich.columns import Columns
    from rich.text import Text
    from rich.live import Live
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from core.models import ScanResult, ScanStatus, Severity


# Fall back to plain print if rich isn't installed
console = Console() if RICH_AVAILABLE else None


SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "red",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "blue",
    Severity.INFO:     "dim white",
    Severity.UNKNOWN:  "dim",
}

STATUS_STYLES = {
    ScanStatus.COMPLETED: ("✅", "green"),
    ScanStatus.RUNNING:   ("⏳", "yellow"),
    ScanStatus.FAILED:    ("❌", "red"),
    ScanStatus.SKIPPED:   ("⏭️",  "dim"),
    ScanStatus.PENDING:   ("⬜", "dim"),
}


def print_scan_header(target: str, scan_id: str):
    """Print a styled scan header panel."""
    if not RICH_AVAILABLE or not console:
        print(f"\n[AUTO RECON] Target: {target}  ID: {scan_id}\n")
        return

    content = (
        f"[bold cyan]Target:[/bold cyan] [white]{target}[/white]\n"
        f"[bold cyan]Scan ID:[/bold cyan] [white]{scan_id}[/white]\n"
        f"[bold cyan]Started:[/bold cyan] [white]{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}[/white]"
    )
    console.print(Panel(content, title="[bold magenta]🔍 Auto Recon Framework[/bold magenta]",
                        border_style="cyan", expand=False))
    console.print()


def print_findings_table(result: ScanResult):
    """Print a formatted vulnerabilities table."""
    if not RICH_AVAILABLE or not console:
        for v in result.vulnerabilities:
            print(f"  [{v.severity.value.upper()}] {v.name} @ {v.matched_at}")
        return

    if not result.vulnerabilities:
        console.print("[green]✓ No vulnerabilities found[/green]")
        return

    table = Table(
        title=f"[bold red]Vulnerability Findings ({len(result.vulnerabilities)})[/bold red]",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold magenta",
    )
    table.add_column("Severity",    style="bold",   width=10)
    table.add_column("Name",                        width=40)
    table.add_column("Host",        style="cyan",   width=35)
    table.add_column("CVE",         style="yellow", width=20)
    table.add_column("CVSS",        style="bold",   width=6)

    for v in result.vulnerabilities:
        sev_style = SEVERITY_STYLES.get(v.severity, "white")
        sev_text  = Text(v.severity.value.upper(), style=sev_style)
        cve       = ", ".join(v.cve_ids[:2]) if v.cve_ids else "—"
        cvss      = str(v.cvss_score) if v.cvss_score else "—"

        table.add_row(sev_text, v.name[:40], v.host[:35], cve, cvss)

    console.print(table)


def print_port_table(result: ScanResult):
    """Print a formatted port scan results table."""
    if not RICH_AVAILABLE or not console or not result.ports:
        return

    table = Table(
        title=f"[bold blue]Open Ports ({len(result.ports)})[/bold blue]",
        box=box.SIMPLE_HEAD,
        header_style="bold blue",
    )
    table.add_column("Port",     style="cyan bold",  width=8)
    table.add_column("Protocol", style="dim",        width=10)
    table.add_column("Service",  style="green",      width=18)
    table.add_column("Version",  style="white",      width=50)

    for p in result.ports:
        table.add_row(str(p.port), p.protocol.upper(), p.service, p.version[:50])

    console.print(table)


def print_subdomain_table(result: ScanResult):
    """Print subdomain enumeration results."""
    if not RICH_AVAILABLE or not console or not result.subdomains:
        return

    alive = [s for s in result.subdomains if s.alive]
    dead  = [s for s in result.subdomains if not s.alive]

    table = Table(
        title=f"[bold magenta]Subdomains ({len(result.subdomains)} found, {len(alive)} alive)[/bold magenta]",
        box=box.SIMPLE_HEAD,
        header_style="bold magenta",
    )
    table.add_column("Status",    width=8)
    table.add_column("Subdomain", style="cyan",  width=50)
    table.add_column("IP",        style="dim",   width=18)
    table.add_column("Title",     style="white", width=40)

    for s in alive[:30]:
        table.add_row("✅", s.subdomain, s.ip or "—", s.title[:40] if s.title else "—")
    for s in dead[:10]:
        table.add_row("❌", s.subdomain, "—", "—")
    if len(dead) > 10:
        table.add_row("…", f"[dim]and {len(dead) - 10} more[/dim]", "", "")

    console.print(table)


def print_summary_panel(result: ScanResult, duration: str, report_paths: dict):
    """Print final summary panel."""
    if not RICH_AVAILABLE or not console:
        return

    counts = result.severity_counts()
    status_emoji, _ = STATUS_STYLES.get(result.status, ("?", "white"))

    # Severity grid
    severity_cols = [
        Panel(f"[bold red]{counts['critical']}[/bold red]",   title="🔴 Critical"),
        Panel(f"[bold red]{counts['high']}[/bold red]",       title="🟠 High"),
        Panel(f"[bold yellow]{counts['medium']}[/bold yellow]",title="🟡 Medium"),
        Panel(f"[bold blue]{counts['low']}[/bold blue]",      title="🔵 Low"),
        Panel(f"[dim]{counts['info']}[/dim]",                  title="⚪ Info"),
    ]

    console.print()
    console.print(Columns(severity_cols, equal=True))
    console.print()

    # Stats table
    stats = Table(box=box.MINIMAL, show_header=False, padding=(0, 2))
    stats.add_column(style="bold cyan", width=18)
    stats.add_column(style="white")
    stats.add_row("Target",       result.target)
    stats.add_row("Scan ID",      result.scan_id)
    stats.add_row("Duration",     duration)
    stats.add_row("Status",       f"{status_emoji} {result.status.value.upper()}")
    stats.add_row("Ports",        str(result.total_ports))
    stats.add_row("Subdomains",   str(result.total_subdomains))
    stats.add_row("Findings",     str(result.total_vulnerabilities))
    stats.add_row("Screenshots",  str(result.total_screenshots))

    for fmt, path in report_paths.items():
        stats.add_row(f"📄 {fmt.capitalize()}", path)

    console.print(Panel(
        stats,
        title="[bold green]✅ Scan Complete[/bold green]",
        border_style="green",
        expand=False,
    ))


@contextmanager
def phase_progress(description: str, total: Optional[int] = None):
    """Context manager providing a progress spinner for a scan phase."""
    if not RICH_AVAILABLE or not console:
        print(f"  → {description}...")
        yield None
        return

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn() if total else TextColumn(""),
        TaskProgressColumn() if total else TextColumn(""),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(f"[cyan]{description}[/cyan]", total=total)
        yield (progress, task)
