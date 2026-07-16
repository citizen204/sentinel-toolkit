from __future__ import annotations

import re
from collections import defaultdict

from sentinel.core.asset import Asset
from sentinel.core.finding import Finding
from sentinel.core.rule import build_finding

from .. import rules  # noqa: F401 - registers logwatch rules

DEFAULT_BRUTEFORCE_THRESHOLD = 5

_IP = r"(\d{1,3}(?:\.\d{1,3}){3})"
_FAILED = re.compile(r"Failed password for (?:invalid user )?\S+ from " + _IP)
_ACCEPTED_PRIV = re.compile(r"Accepted password for (root|admin) from " + _IP)


def check_bruteforce(lines, threshold: int = DEFAULT_BRUTEFORCE_THRESHOLD) -> list[Finding]:
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
                build_finding(
                    "LOG-BRUTEFORCE",
                    description=f"{attempts} failed login attempts from {ip}.",
                    remediation=(
                        "Block the source IP, enforce key-based auth, and deploy "
                        "fail2ban or an equivalent rate limiter."
                    ),
                    asset=Asset(provider="host", type="ip", id=ip),
                    evidence={
                        "ip": ip, "failed_attempts": attempts, "threshold": threshold,
                    },
                    api="sshd auth log",
                    rationale=(
                        f"{attempts} 'Failed password' lines originate from {ip}, at or above "
                        f"the configured threshold of {threshold} — a volume characteristic of "
                        f"credential guessing rather than user error."
                    ),
                    verify=f"grep 'Failed password' <auth log> | grep {ip} | wc -l",
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
                build_finding(
                    "LOG-ROOT-LOGIN",
                    description=f"Successful '{account}' login from {ip}.",
                    remediation=(
                        "Disable direct root/admin SSH login; require sudo from "
                        "named user accounts."
                    ),
                    asset=Asset(provider="host", type="ip", id=ip),
                    evidence={"account": account, "ip": ip, "line_type": "Accepted password"},
                    api="sshd auth log",
                    rationale=(
                        f"An 'Accepted password' line for the privileged account '{account}' "
                        f"shows a direct privileged login, which bypasses per-user "
                        f"accountability that sudo from a named account provides."
                    ),
                    verify=f"grep 'Accepted password for {account}' <auth log>",
                    resource=ip,
                )
            )
    return findings
