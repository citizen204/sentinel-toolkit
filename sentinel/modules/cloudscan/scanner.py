from __future__ import annotations

import boto3

from sentinel.core.context import aws_scan_context
from sentinel.core.finding import Finding
from sentinel.core.rule import build_finding
from sentinel.core.scanner import BaseScanner

from .checks.ebs import check_unencrypted_volumes
from .checks.iam import check_admin_users, check_password_policy, check_users_without_mfa
from .checks.rds import check_unencrypted_databases
from .checks.s3 import (
    check_bucket_encryption,
    check_bucket_public_access_block,
    check_bucket_versioning,
    check_public_buckets,
)
from .checks.security_groups import check_open_security_groups


def _check_error(name: str, exc: Exception) -> list[Finding]:
    return [
        build_finding(
            "CLOUD-CHECK-ERROR",
            title=f"cloudscan check '{name}' failed",
            description=f"{type(exc).__name__}: {exc}",
            remediation="Check the AWS permissions/credentials for this check.",
            evidence={"check": name, "error": str(exc)},
            resource=name,
        )
    ]


def _run_check(name: str, fn) -> list[Finding]:
    """Run one cloudscan check, isolating its failure as an INFO finding.

    Keeps the findings other checks already produced instead of letting a single
    failing API call (e.g. a missing IAM permission) wipe out the whole module.
    """
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - isolate any single check failure
        return _check_error(name, exc)


class CloudScanner(BaseScanner):
    """Scans an AWS account for common misconfigurations (read-only)."""

    name = "cloudscan"

    def run(self, config) -> list[Finding]:
        if config.aws_profile:
            session = boto3.Session(profile_name=config.aws_profile)
        else:
            session = boto3.Session()

        findings: list[Finding] = []

        # Establish identity first: it attributes every asset to an account and
        # keeps dedupe keys stable across accounts. If it fails, say so rather
        # than silently scanning without an account id.
        context = None
        try:
            context = aws_scan_context(session, config.aws_regions)
        except Exception as exc:  # noqa: BLE001
            findings += _check_error("scan_context", exc)
        account = context.account_id if context else None

        findings += _run_check(
            "s3_public_buckets", lambda: check_public_buckets(session, account)
        )
        findings += _run_check(
            "s3_encryption", lambda: check_bucket_encryption(session, account)
        )
        findings += _run_check(
            "s3_versioning", lambda: check_bucket_versioning(session, account)
        )
        findings += _run_check(
            "s3_block_public_access",
            lambda: check_bucket_public_access_block(session, account),
        )
        findings += _run_check(
            "open_security_groups",
            lambda: check_open_security_groups(session, config.aws_regions, account),
        )
        findings += _run_check(
            "iam_users_without_mfa", lambda: check_users_without_mfa(session, account)
        )
        findings += _run_check(
            "iam_password_policy", lambda: check_password_policy(session, account)
        )
        findings += _run_check(
            "iam_admin_users", lambda: check_admin_users(session, account)
        )
        findings += _run_check(
            "ebs_encryption",
            lambda: check_unencrypted_volumes(session, config.aws_regions, account),
        )
        findings += _run_check(
            "rds_encryption",
            lambda: check_unencrypted_databases(session, config.aws_regions, account),
        )
        return findings
