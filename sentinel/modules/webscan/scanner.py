from __future__ import annotations

from sentinel.core.finding import Finding
from sentinel.core.scanner import BaseScanner
from .checks.headers import check_security_headers


class WebScanner(BaseScanner):
    """Checks a target web application (config.target_url) for common issues."""

    name = "webscan"

    def run(self, config) -> list[Finding]:
        if not config.target_url:
            return []
        return check_security_headers(config.target_url)
