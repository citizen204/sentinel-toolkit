from __future__ import annotations

import boto3

from sentinel.core.finding import Finding
from sentinel.core.scanner import BaseScanner
from .checks.s3 import check_public_buckets
from .checks.security_groups import check_open_security_groups
from .checks.iam import check_users_without_mfa


class CloudScanner(BaseScanner):
    """Scans an AWS account for common misconfigurations (read-only)."""

    name = "cloudscan"

    def run(self, config) -> list[Finding]:
        if config.aws_profile:
            session = boto3.Session(profile_name=config.aws_profile)
        else:
            session = boto3.Session()
        findings: list[Finding] = []
        findings.extend(check_public_buckets(session))
        findings.extend(check_open_security_groups(session, config.aws_regions))
        findings.extend(check_users_without_mfa(session))
        return findings
