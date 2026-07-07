from __future__ import annotations

import boto3

from sentinel.core.finding import Finding, Severity
from sentinel.core.scanner import BaseScanner

from .checks.iam import check_users_without_mfa
from .checks.s3 import check_public_buckets
from .checks.security_groups import check_open_security_groups


def _run_check(name: str, fn) -> list[Finding]:
    """Run one cloudscan check, isolating its failure as an INFO finding.

    Keeps the findings other checks already produced instead of letting a single
    failing API call (e.g. a missing IAM permission) wipe out the whole module.
    """
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - isolate any single check failure
        return [
            Finding(
                id="CLOUD-CHECK-ERROR",
                module="cloudscan",
                severity=Severity.INFO,
                title=f"cloudscan check '{name}' failed",
                description=f"{type(exc).__name__}: {exc}",
                remediation="Check the AWS permissions/credentials for this check.",
                category="Operational",
                evidence={"check": name, "error": str(exc)},
                resource=name,
            )
        ]


class CloudScanner(BaseScanner):
    """Scans an AWS account for common misconfigurations (read-only)."""

    name = "cloudscan"

    def run(self, config) -> list[Finding]:
        if config.aws_profile:
            session = boto3.Session(profile_name=config.aws_profile)
        else:
            session = boto3.Session()

        findings: list[Finding] = []
        findings += _run_check("s3_public_buckets", lambda: check_public_buckets(session))
        findings += _run_check(
            "open_security_groups",
            lambda: check_open_security_groups(session, config.aws_regions),
        )
        findings += _run_check(
            "iam_users_without_mfa", lambda: check_users_without_mfa(session)
        )
        return findings
