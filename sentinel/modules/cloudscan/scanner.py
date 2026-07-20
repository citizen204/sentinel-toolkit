from __future__ import annotations

import boto3

from sentinel.core.context import aws_scan_context, discover_regions
from sentinel.core.envelope import CoverageStatus, CoverageUnit
from sentinel.core.finding import Finding
from sentinel.core.rule import build_finding
from sentinel.core.scanner import BaseScanner

from .checks.ebs import check_unencrypted_volumes
from .checks.iam import check_password_policy, check_users_without_mfa
from .checks.iam_privilege import check_customer_managed_admin, check_effective_admin
from .checks.rds import check_unencrypted_databases
from .checks.s3 import (
    S3Inventory,
    check_bucket_encryption,
    check_bucket_public_access_block,
    check_bucket_public_access_block_strict,
    check_bucket_versioning,
    check_public_buckets,
)
from .checks.security_groups import check_open_security_groups
from .session import account_id_from_arn, assume_role_session


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


def _run_check(name: str, fn) -> tuple[list[Finding], bool]:
    """Run one cloudscan check, isolating its failure as an INFO finding.

    Keeps the findings other checks already produced instead of letting a single
    failing API call (e.g. a missing IAM permission) wipe out the whole module.
    Returns the findings and whether the check completed.
    """
    try:
        return fn(), True
    except Exception as exc:  # noqa: BLE001 - isolate any single check failure
        return _check_error(name, exc), False


# Checks whose scope is the whole account; their findings carry no region.
_GLOBAL_CHECKS = "global"


def _scan_session(session, regions: list[str]) -> tuple[list[Finding], list[CoverageUnit]]:
    """Run every cloudscan check against one account's session.

    Returns the findings plus a coverage unit per (check, account, region) that
    was genuinely attempted -- recorded here, where the scope is known, rather
    than reconstructed later from whatever findings happened to appear.
    """
    findings: list[Finding] = []
    units: list[CoverageUnit] = []

    # Resolve the scan scope. An explicit list wins; otherwise discover the
    # account's enabled regions so an unconfigured scan really does cover
    # every region rather than just the session default.
    discovery_failed = False
    if not regions:
        try:
            regions = discover_regions(session)
        except Exception as exc:  # noqa: BLE001
            findings += _check_error("region_discovery", exc)
            regions = [session.region_name] if session.region_name else []
            discovery_failed = True

    # Establish identity next: it attributes every asset to an account and
    # keeps dedupe keys stable across accounts. If it fails, say so rather
    # than silently scanning without an account id.
    context = None
    identity_failed = False
    try:
        context = aws_scan_context(session, regions)
    except Exception as exc:  # noqa: BLE001
        findings += _check_error("scan_context", exc)
        identity_failed = True
    account = context.account_id if context else None
    # s3control is regional; give it a concrete region instead of relying on
    # the session having a default configured.
    primary_region = regions[0] if regions else None

    def record(name: str, fn, scope: str | list[str]) -> None:
        """Run a check and record coverage for every scope it was meant to reach.

        `scope` is either _GLOBAL_CHECKS (account-wide, no region) or the list of
        regions the check iterates. A check that raised marks its scopes ERROR,
        so a permission gap in one region cannot make another region's old
        findings look resolved.
        """
        produced, ok = _run_check(name, fn)
        findings.extend(produced)
        status = CoverageStatus.OK if ok else CoverageStatus.ERROR
        # Without an account id, findings cannot be attributed and their dedupe
        # keys are not comparable with a run that did resolve identity. Nothing
        # from this session may be treated as authoritative.
        if identity_failed:
            status = CoverageStatus.ERROR
        # Region discovery failing means we do not know the real region list, so
        # regional checks cannot claim to have covered it.
        if scope != _GLOBAL_CHECKS and discovery_failed:
            status = CoverageStatus.ERROR
        scopes = [None] if scope == _GLOBAL_CHECKS else list(scope) or [None]
        for region in scopes:
            units.append(
                CoverageUnit(
                    scanner="cloudscan", account_id=account,
                    region=region, check=name, status=status,
                )
            )

    # One bucket enumeration and one account-BPA lookup, shared by all five S3
    # checks. Each of them used to re-list every bucket in the account.
    s3_inventory = S3Inventory(session, primary_region)

    record("s3_public_buckets",
           lambda: check_public_buckets(session, account, s3_inventory),
           _GLOBAL_CHECKS)
    record("s3_encryption",
           lambda: check_bucket_encryption(session, account, s3_inventory),
           _GLOBAL_CHECKS)
    record("s3_versioning",
           lambda: check_bucket_versioning(session, account, s3_inventory),
           _GLOBAL_CHECKS)
    record("s3_block_public_access",
           lambda: check_bucket_public_access_block(
               session, account, primary_region, s3_inventory),
           _GLOBAL_CHECKS)
    record("s3_block_public_access_strict",
           lambda: check_bucket_public_access_block_strict(
               session, account, primary_region, s3_inventory),
           _GLOBAL_CHECKS)
    record("iam_users_without_mfa",
           lambda: check_users_without_mfa(session, account), _GLOBAL_CHECKS)
    record("iam_password_policy",
           lambda: check_password_policy(session, account), _GLOBAL_CHECKS)
    record("iam_effective_admin",
           lambda: check_effective_admin(session, account), _GLOBAL_CHECKS)
    record("iam_customer_managed_admin",
           lambda: check_customer_managed_admin(session, account), _GLOBAL_CHECKS)
    record("open_security_groups",
           lambda: check_open_security_groups(session, regions, account), regions)
    record("ebs_encryption",
           lambda: check_unencrypted_volumes(session, regions, account), regions)
    record("rds_encryption",
           lambda: check_unencrypted_databases(session, regions, account), regions)
    return findings, units


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
            findings, self.coverage_units = _scan_session(base, config.aws_regions)
            return findings

        findings: list[Finding] = []
        units: list[CoverageUnit] = []
        for account in config.aws_accounts:
            try:
                session = assume_role_session(base, account.role_arn)
            except Exception as exc:  # noqa: BLE001 - isolate one bad account
                # An explicit ERROR unit, not just a finding. Omitting the account
                # entirely leaves no trace that it was meant to be in scope, so the
                # run still looks complete and --fail-on-incomplete passes on an
                # estate that was only partly reachable. Other accounts still scan.
                findings += _check_error(f"assume_role[{account.role_arn}]", exc)
                units.append(
                    CoverageUnit(
                        scanner="cloudscan",
                        account_id=account.account_id or account_id_from_arn(
                            account.role_arn
                        ),
                        check="assume_role",
                        status=CoverageStatus.ERROR,
                    )
                )
                continue
            produced, produced_units = _scan_session(
                session, account.regions or config.aws_regions
            )
            findings += produced
            units += produced_units
        self.coverage_units = units
        return findings
