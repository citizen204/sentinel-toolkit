from __future__ import annotations

from sentinel.core.finding import Finding
from sentinel.core.scanner import BaseScanner, ScannerSkipped

from .checks.headers import check_security_headers


class WebScanner(BaseScanner):
    """Checks a target web application (config.target_url) for common issues."""

    name = "webscan"

    def run(self, config) -> list[Finding]:
        if not config.target_url:
            raise ScannerSkipped(
                "No target_url is configured, so no web application was scanned.",
                "Set target_url in your config, or exclude webscan from the run.",
            )
        return check_security_headers(config.target_url)
