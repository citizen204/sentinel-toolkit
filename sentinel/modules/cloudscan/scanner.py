from __future__ import annotations

import boto3

from sentinel.core.context import aws_scan_context, discover_regions
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
from .session import assume_role_session


def _check_error(name: str, exc: Exception) -> list[Finding]:
    return [
        build_finding(
            "CLOUD-CHECK-ERROR",
            title=f"cloudscan check '{name}' failed",
            description=f"{type(exc).__name__}: {exc}",
            remediation="Check the AWS permissions/credentials for this check.",
            evidence={"check": name, "error": str(exc), "error_type": type(exc).__name__},
            api=f"cloudscan:{name}",
            rationale=(
                "The check could not complete, so its result is unknown. Treat this as "
                "unassessed — not as a pass."
            ),
            verify="Re-run the scan once the underlying permission/credential issue is fixed.",
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


def _scan_session(session, regions: list[str]) -> list[Finding]:
    """Run every cloudscan check against one account's session."""
    findings: list[Finding] = []

    # Resolve the scan scope. An explicit list wins; otherwise discover the
    # account's enabled regions so an unconfigured scan really does cover
    # every region rather than just the session default.
    if not regions:
        try:
            regions = discover_regions(session)
        except Exception as exc:  # noqa: BLE001
            findings += _check_error("region_discovery", exc)
            regions = [session.region_name] if session.region_name else []

    # Establish identity next: it attributes every asset to an account and
    # keeps dedupe keys stable across accounts. If it fails, say so rather
    # than silently scanning without an account id.
    context = None
    try:
        context = aws_scan_context(session, regions)
    except Exception as exc:  # noqa: BLE001
        findings += _check_error("scan_context", exc)
    account = context.account_id if context else None
    # s3control is regional; give it a concrete region instead of relying on
    # the session having a default configured.
    primary_region = regions[0] if regions else None

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
        lambda: check_bucket_public_access_block(session, account, primary_region),
    )
    findings += _run_check(
        "open_security_groups",
        lambda: check_open_security_groups(session, regions, account),
    )
    findings += _run_check(
        "iam_users_without_mfa", lambda: check_users_without_mfa(session, account)
    )
    findings += _run_check(
        "iam_password_policy", lambda: check_password_policy(session, account)
    )
    findings += _run_check("iam_admin_users", lambda: check_admin_users(session, account))
    findings += _run_check(
        "ebs_encryption", lambda: check_unencrypted_volumes(session, regions, account)
    )
    findings += _run_check(
        "rds_encryption", lambda: check_unencrypted_databases(session, regions, account)
    )
    return findings


class CloudScanner(BaseScanner):
    """Scans one or many AWS accounts for common misconfigurations (read-only).

    With no `aws_accounts` configured it audits the current credentials. Given
    `aws_accounts`, it assumes each role in turn — a failure on one account is
    reported and the remaining accounts still get scanned.
    """

    name = "cloudscan"

    def run(self, config) -> list[Finding]:
        base = (
            boto3.Session(profile_name=config.aws_profile)
            if config.aws_profile
            else boto3.Session()
        )

        if not config.aws_accounts:
            return _scan_session(base, config.aws_regions)

        findings: list[Finding] = []
        for account in config.aws_accounts:
            try:
                session = assume_role_session(base, account.role_arn)
            except Exception as exc:  # noqa: BLE001 - isolate one bad account
                findings += _check_error(f"assume_role[{account.role_arn}]", exc)
                continue
            findings += _scan_session(session, account.regions or config.aws_regions)
        return findings
