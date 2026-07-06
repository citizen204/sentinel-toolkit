from __future__ import annotations

from pathlib import Path

from sentinel.core.finding import Finding
from sentinel.core.scanner import BaseScanner
from .checks.auth import check_bruteforce, check_root_login


class LogwatchScanner(BaseScanner):
    """Analyzes auth logs (from config.log_paths) for suspicious login activity."""

    name = "logwatch"

    def run(self, config) -> list[Finding]:
        lines: list[str] = []
        for path in config.log_paths:
            p = Path(path)
            if p.exists():
                lines.extend(
                    p.read_text(encoding="utf-8", errors="ignore").splitlines()
                )
        findings: list[Finding] = []
        findings.extend(check_bruteforce(lines))
        findings.extend(check_root_login(lines))
        return findings
