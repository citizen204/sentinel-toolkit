from __future__ import annotations

import re
from collections import defaultdict

from sentinel.core.finding import Finding, Severity

_IP = r"(\d{1,3}(?:\.\d{1,3}){3})"
_FAILED = re.compile(r"Failed password for (?:invalid user )?\S+ from " + _IP)
_ACCEPTED_PRIV = re.compile(r"Accepted password for (root|admin) from " + _IP)


def check_bruteforce(lines, threshold: int = 5) -> list[Finding]:
    """Flag source IPs with many failed SSH logins (possible brute force)."""
    counts: dict[str, int] = defaultdict(int)
    for line in lines:
        match = _FAILED.search(line)
        if match:
            counts[match.group(1)] += 1

    findings: list[Finding] = []
    for ip, attempts in counts.items():
        if attempts >= threshold:
            findings.append(
                Finding(
                    id="LOG-BRUTEFORCE",
                    module="logwatch",
                    severity=Severity.HIGH,
                    title="Possible SSH brute-force attempt",
                    description=f"{attempts} failed login attempts from {ip}.",
                    remediation=(
                        "Block the source IP, enforce key-based auth, and deploy "
                        "fail2ban or an equivalent rate limiter."
                    ),
                    evidence={"ip": ip, "failed_attempts": attempts},
                    resource=ip,
                )
            )
    return findings


def check_root_login(lines) -> list[Finding]:
    """Flag successful direct privileged (root/admin) SSH logins."""
    findings: list[Finding] = []
    for line in lines:
        match = _ACCEPTED_PRIV.search(line)
        if match:
            account, ip = match.group(1), match.group(2)
            findings.append(
                Finding(
                    id="LOG-ROOT-LOGIN",
                    module="logwatch",
                    severity=Severity.MEDIUM,
                    title="Direct privileged login",
                    description=f"Successful '{account}' login from {ip}.",
                    remediation=(
                        "Disable direct root/admin SSH login; require sudo from "
                        "named user accounts."
                    ),
                    evidence={"account": account, "ip": ip},
                    resource=ip,
                )
            )
    return findings
