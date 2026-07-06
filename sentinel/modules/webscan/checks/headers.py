from __future__ import annotations

import requests

from sentinel.core.finding import Finding, Severity

# Header -> (severity, remediation) for headers every site should set.
_REQUIRED_HEADERS = {
    "Strict-Transport-Security": (
        Severity.MEDIUM, "Enforce HTTPS by adding a Strict-Transport-Security (HSTS) header."
    ),
    "Content-Security-Policy": (
        Severity.MEDIUM, "Add a Content-Security-Policy header to mitigate XSS."
    ),
    "X-Content-Type-Options": (
        Severity.LOW, "Add 'X-Content-Type-Options: nosniff' to stop MIME sniffing."
    ),
    "X-Frame-Options": (
        Severity.LOW, "Add 'X-Frame-Options: DENY' to prevent clickjacking."
    ),
}


def check_security_headers(url: str, session=None, timeout: int = 10) -> list[Finding]:
    """Flag missing HTTP security response headers for the given URL."""
    http = session or requests
    resp = http.get(url, timeout=timeout)
    present = {name.lower() for name in resp.headers.keys()}

    findings: list[Finding] = []
    for header, (severity, remediation) in _REQUIRED_HEADERS.items():
        if header.lower() not in present:
            findings.append(
                Finding(
                    id="WEB-MISSING-HEADER",
                    module="webscan",
                    severity=severity,
                    title=f"Missing security header: {header}",
                    description=f"The response from {url} does not set the {header} header.",
                    remediation=remediation,
                    evidence={"url": url, "header": header},
                    resource=url,
                )
            )
    return findings
