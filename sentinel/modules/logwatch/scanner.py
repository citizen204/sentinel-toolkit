from __future__ import annotations

from pathlib import Path

from sentinel.core.finding import Finding, Severity
from sentinel.core.scanner import BaseScanner, ScannerSkipped

from .checks.auth import (
    DEFAULT_BRUTEFORCE_THRESHOLD,
    check_bruteforce,
    check_root_login,
)


class LogwatchScanner(BaseScanner):
    """Analyzes auth logs (from config.log_paths) for suspicious login activity."""

    name = "logwatch"

    def run(self, config) -> list[Finding]:
        if not config.log_paths:
            raise ScannerSkipped(
                "No log_paths are configured, so no logs were analyzed.",
                "Set log_paths in your config, or exclude logwatch from the run.",
            )

        lines: list[str] = []
        missing: list[str] = []
        for path in config.log_paths:
            p = Path(path)
            if p.exists():
                lines.extend(
                    p.read_text(encoding="utf-8", errors="ignore").splitlines()
                )
            else:
                missing.append(str(path))

        if len(missing) == len(config.log_paths):
            raise ScannerSkipped(
                f"None of the configured log_paths exist: {', '.join(missing)}.",
                "Correct the log_paths so the logs can be read.",
            )

        findings: list[Finding] = []
        # Partial coverage still produces findings, so the gap has to travel with them.
        for path in missing:
            findings.append(
                Finding(
                    id="LOG-SOURCE-ERROR",
                    module="logwatch",
                    severity=Severity.INFO,
                    title="Configured log file could not be read",
                    description=f"Log path '{path}' does not exist and was not analyzed.",
                    remediation="Correct the path, or remove it from log_paths.",
                    rationale=(
                        "Other logs were analyzed, so this run is partial: activity "
                        "recorded only in this file was not assessed."
                    ),
                    evidence={"path": path},
                    resource=path,
                )
            )
        findings.extend(
            check_bruteforce(
                lines,
                threshold=config.threshold_for(
                    "LOG-BRUTEFORCE", DEFAULT_BRUTEFORCE_THRESHOLD
                ),
            )
        )
        findings.extend(check_root_login(lines))
        return findings
