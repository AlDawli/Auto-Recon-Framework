"""
Auto Recon Framework - Structured Logger
"""
import logging
import sys
from datetime import datetime
from typing import Optional
from pathlib import Path

# ANSI color codes
RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"
GRAY    = "\033[90m"

SEVERITY_COLORS = {
    "critical": RED + BOLD,
    "high":     RED,
    "medium":   YELLOW,
    "low":      BLUE,
    "info":     CYAN,
    "unknown":  GRAY,
}

MODULE_COLORS = {
    "nmap":       BLUE,
    "subfinder":  MAGENTA,
    "httpx":      CYAN,
    "nuclei":     RED,
    "screenshot": GREEN,
    "report":     YELLOW,
    "engine":     WHITE,
}


class ReconFormatter(logging.Formatter):
    """Custom formatter with colors and module tags."""

    LEVEL_COLORS = {
        logging.DEBUG:    GRAY,
        logging.INFO:     GREEN,
        logging.WARNING:  YELLOW,
        logging.ERROR:    RED,
        logging.CRITICAL: RED + BOLD,
    }

    def format(self, record: logging.LogRecord) -> str:
        level_color = self.LEVEL_COLORS.get(record.levelno, RESET)
        module_tag  = getattr(record, "module_tag", "core")
        mod_color   = MODULE_COLORS.get(module_tag, WHITE)

        ts        = datetime.utcnow().strftime("%H:%M:%S")
        level_str = f"{level_color}{record.levelname:<8}{RESET}"
        tag_str   = f"{mod_color}[{module_tag.upper():^10}]{RESET}"
        msg       = record.getMessage()

        return f"{GRAY}{ts}{RESET} {level_str} {tag_str}  {msg}"


class ReconLogger:
    """Framework logger with module context support."""

    def __init__(self, name: str = "auto-recon", log_file: Optional[str] = None):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        self.logger.handlers.clear()

        # Console handler
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(ReconFormatter())
        self.logger.addHandler(ch)

        # File handler
        if log_file:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(log_file)
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(logging.Formatter(
                "%(asctime)s %(levelname)-8s [%(module_tag)s] %(message)s"
            ))
            self.logger.addHandler(fh)

    def _log(self, level: int, msg: str, module: str = "engine", **kwargs):
        extra = {"module_tag": module}
        self.logger.log(level, msg, extra=extra, **kwargs)

    def info(self, msg: str, module: str = "engine"):
        self._log(logging.INFO, msg, module)

    def debug(self, msg: str, module: str = "engine"):
        self._log(logging.DEBUG, msg, module)

    def warning(self, msg: str, module: str = "engine"):
        self._log(logging.WARNING, msg, module)

    def error(self, msg: str, module: str = "engine"):
        self._log(logging.ERROR, msg, module)

    def critical(self, msg: str, module: str = "engine"):
        self._log(logging.CRITICAL, msg, module)

    def success(self, msg: str, module: str = "engine"):
        self._log(logging.INFO, f"{GREEN}✓{RESET} {msg}", module)

    def finding(self, severity: str, msg: str, module: str = "nuclei"):
        color = SEVERITY_COLORS.get(severity.lower(), GRAY)
        self._log(logging.INFO, f"{color}[{severity.upper()}]{RESET} {msg}", module)

    def banner(self):
        print(f"""
{CYAN}{BOLD}
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{RESET}
  {GRAY}Auto Recon Framework v1.0.0{RESET}
  {GRAY}nmap · subfinder · httpx · nuclei · MITRE ATT&CK{RESET}
  {GRAY}──────────────────────────────────────────────────{RESET}
""")


# Global logger instance
log = ReconLogger()
