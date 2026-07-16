from __future__ import annotations

from botocore.exceptions import ClientError

from sentinel.core.asset import Asset
from sentinel.core.finding import Finding
from sentinel.core.rule import build_finding

from .. import rules  # noqa: F401 - registers cloudscan rules

_PUBLIC_URIS = (
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
)

_BPA_KEYS = (
    "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets",
)


def _bucket_asset(name: str, account_id: str | None = None) -> Asset:
    return Asset(
        provider="aws", type="s3_bucket", id=name, name=name, account_id=account_id
    )


def _bucket_names(s3) -> list[str]:
    return [b["Name"] for b in s3.list_buckets().get("Buckets", [])]


def _is_public(grants: list[dict]) -> bool:
    for grant in grants:
        uri = grant.get("Grantee", {}).get("URI", "")
        if uri in _PUBLIC_URIS:
            return True
    return False


def check_public_buckets(session, account_id: str | None = None) -> list[Finding]:
    """Flag S3 buckets whose ACL grants access to a public group."""
    s3 = session.client("s3")
    findings: list[Finding] = []
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        grants = s3.get_bucket_acl(Bucket=name).get("Grants", [])
        if _is_public(grants):
            findings.append(
                build_finding(
                    "CLOUD-S3-PUBLIC",
                    description=(
                        f"S3 bucket '{name}' grants access to a public group "
                        f"(AllUsers/AuthenticatedUsers)."
                    ),
                    remediation="Remove public ACL grants and enable S3 Block Public Access.",
                    asset=_bucket_asset(name, account_id),
                    evidence={"bucket": name, "grants": grants},
                    resource=name,
                )
            )
    return findings


def check_bucket_encryption(session, account_id: str | None = None) -> list[Finding]:
    """Flag S3 buckets without default server-side encryption."""
    s3 = session.client("s3")
    findings: list[Finding] = []
    for name in _bucket_names(s3):
        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError as exc:
            # Only "no encryption configured" is a finding. Anything else
            # (AccessDenied, endpoint/region errors, ...) must surface as an
            # error rather than silently becoming a clean result.
            if exc.response["Error"]["Code"] != "ServerSideEncryptionConfigurationNotFoundError":
                raise
            findings.append(
                build_finding(
                    "CLOUD-S3-NO-ENCRYPTION",
                    description=f"S3 bucket '{name}' has no default encryption configured.",
                    remediation="Enable default SSE-S3 or SSE-KMS encryption on the bucket.",
                    asset=_bucket_asset(name, account_id),
                    evidence={"bucket": name},
                    resource=name,
                )
            )
    return findings


def check_bucket_versioning(session, account_id: str | None = None) -> list[Finding]:
    """Flag S3 buckets that do not have versioning enabled."""
    s3 = session.client("s3")
    findings: list[Finding] = []
    for name in _bucket_names(s3):
        status = s3.get_bucket_versioning(Bucket=name).get("Status")
        if status != "Enabled":
            findings.append(
                build_finding(
                    "CLOUD-S3-NO-VERSIONING",
                    description=f"S3 bucket '{name}' does not have versioning enabled.",
                    remediation="Enable versioning to protect against overwrite and deletion.",
                    asset=_bucket_asset(name, account_id),
                    evidence={"bucket": name, "versioning": status or "Disabled"},
                    resource=name,
                )
            )
    return findings


def _account_bpa_fully_blocked(session) -> bool:
    """Whether account-level S3 Block Public Access blocks all four vectors."""
    account_id = session.client("sts").get_caller_identity()["Account"]
    try:
        cfg = session.client("s3control").get_public_access_block(AccountId=account_id)[
            "PublicAccessBlockConfiguration"
        ]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
            raise
        return False
    return all(cfg.get(k) for k in _BPA_KEYS)


def _bucket_bpa_fully_blocked(s3, name: str) -> bool:
    try:
        cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
            raise
        return False
    return all(cfg.get(k) for k in _BPA_KEYS)


def check_bucket_public_access_block(
    session, account_id: str | None = None
) -> list[Finding]:
    """Flag buckets not covered by Block Public Access at bucket *or* account level.

    Account-level BPA protects every bucket, so checking only the bucket-level
    setting would report false positives on accounts that block centrally.
    """
    s3 = session.client("s3")
    account_blocked = _account_bpa_fully_blocked(session)
    findings: list[Finding] = []
    for name in _bucket_names(s3):
        bucket_blocked = _bucket_bpa_fully_blocked(s3, name)
        effective = bucket_blocked or account_blocked
        if effective:
            continue
        findings.append(
            build_finding(
                "CLOUD-S3-NO-BPA",
                description=(
                    f"S3 bucket '{name}' is not covered by Block Public Access at "
                    f"bucket or account level."
                ),
                remediation=(
                    "Enable all four S3 Block Public Access settings on the bucket, "
                    "or account-wide via S3 Control."
                ),
                asset=_bucket_asset(name, account_id),
                evidence={
                    "bucket": name,
                    "bucket_bpa": bucket_blocked,
                    "account_bpa": account_blocked,
                    "effective_bpa": effective,
                },
                resource=name,
            )
        )
    return findings
