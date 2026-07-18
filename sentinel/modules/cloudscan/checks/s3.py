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


def _public_grant_uris(grants: list[dict]) -> list[str]:
    """The public grantee URIs present on a bucket ACL."""
    return [
        grant["Grantee"]["URI"]
        for grant in grants
        if grant.get("Grantee", {}).get("URI") in _PUBLIC_URIS
    ]


def check_public_buckets(session, account_id: str | None = None) -> list[Finding]:
    """Flag S3 buckets whose ACL grants access to a public group."""
    s3 = session.client("s3")
    findings: list[Finding] = []
    for name in _bucket_names(s3):
        grants = s3.get_bucket_acl(Bucket=name).get("Grants", [])
        public_uris = _public_grant_uris(grants)
        if public_uris:
            findings.append(
                build_finding(
                    "CLOUD-S3-PUBLIC",
                    description=(
                        f"S3 bucket '{name}' grants access to a public group "
                        f"(AllUsers/AuthenticatedUsers)."
                    ),
                    remediation="Remove public ACL grants and enable S3 Block Public Access.",
                    asset=_bucket_asset(name, account_id),
                    evidence={
                        "bucket": name,
                        "grants": grants,
                        "public_grantees": public_uris,
                    },
                    api="s3:GetBucketAcl",
                    rationale=(
                        f"The bucket ACL grants to {', '.join(public_uris)}; those groups "
                        f"resolve to anyone on the internet, so the bucket is public."
                    ),
                    verify=f"aws s3api get-bucket-acl --bucket {name}",
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
                    evidence={
                        "bucket": name,
                        "error_code": "ServerSideEncryptionConfigurationNotFoundError",
                    },
                    api="s3:GetBucketEncryption",
                    rationale=(
                        "GetBucketEncryption returned "
                        "ServerSideEncryptionConfigurationNotFoundError, meaning no default "
                        "encryption rule exists, so new objects can be stored unencrypted."
                    ),
                    verify=f"aws s3api get-bucket-encryption --bucket {name}",
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
                    api="s3:GetBucketVersioning",
                    rationale=(
                        f"Versioning Status is '{status or 'unset'}' rather than 'Enabled', "
                        f"so an overwrite or delete is unrecoverable."
                    ),
                    verify=f"aws s3api get-bucket-versioning --bucket {name}",
                    resource=name,
                )
            )
    return findings


def _account_bpa_fully_blocked(session, region: str | None = None) -> tuple[bool, str]:
    """Whether account-level S3 BPA blocks all four vectors, and the region used.

    s3control is a regional endpoint: without an explicit region a session that
    has no default configured raises NoRegionError, so the region is resolved
    here rather than left to chance.
    """
    account_id = session.client("sts").get_caller_identity()["Account"]
    client_region = region or session.region_name or "us-east-1"
    try:
        cfg = session.client(
            "s3control", region_name=client_region
        ).get_public_access_block(AccountId=account_id)["PublicAccessBlockConfiguration"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
            raise
        return False, client_region
    return all(cfg.get(k) for k in _BPA_KEYS), client_region


def _bucket_bpa_fully_blocked(s3, name: str) -> bool:
    try:
        cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
            raise
        return False
    return all(cfg.get(k) for k in _BPA_KEYS)


def check_bucket_public_access_block(
    session, account_id: str | None = None, region: str | None = None
) -> list[Finding]:
    """Flag buckets not covered by Block Public Access at bucket *or* account level.

    Account-level BPA protects every bucket, so checking only the bucket-level
    setting would report false positives on accounts that block centrally.
    """
    s3 = session.client("s3")
    account_blocked, bpa_region = _account_bpa_fully_blocked(session, region)
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
                    "required_settings": list(_BPA_KEYS),
                    "account_bpa_region": bpa_region,
                },
                api="s3:GetPublicAccessBlock + s3:GetAccountPublicAccessBlock",
                rationale=(
                    f"All four Block Public Access settings must be on at the bucket or the "
                    f"account level; bucket-level fully blocked = {bucket_blocked}, "
                    f"account-level = {account_blocked}, so nothing prevents a public "
                    f"ACL or policy being applied."
                ),
                verify=f"aws s3api get-public-access-block --bucket {name}",
                resource=name,
            )
        )
    return findings


def check_bucket_public_access_block_strict(
    session, account_id: str | None = None, region: str | None = None
) -> list[Finding]:
    """Flag buckets where BPA is set at only one of the two levels.

    CIS 2.1.4 maps to two Security Hub controls - S3.1 (account) and S3.8 (bucket) -
    and both must pass. `check_bucket_public_access_block` answers the risk question
    (is this bucket protected *at all*); this answers the compliance question, and
    conflating the two would let Sentinel claim CIS coverage it hasn't established.
    """
    s3 = session.client("s3")
    account_blocked, bpa_region = _account_bpa_fully_blocked(session, region)
    findings: list[Finding] = []
    for name in _bucket_names(s3):
        bucket_blocked = _bucket_bpa_fully_blocked(s3, name)
        if bucket_blocked and account_blocked:
            continue
        # Fully unprotected buckets are already reported by CLOUD-S3-NO-BPA.
        if not bucket_blocked and not account_blocked:
            continue
        missing = "bucket" if account_blocked else "account"
        findings.append(
            build_finding(
                "CLOUD-S3-BPA-NOT-STRICT",
                description=(
                    f"S3 bucket '{name}' has Block Public Access at the "
                    f"{'account' if account_blocked else 'bucket'} level only; "
                    f"CIS 2.1.4 requires both levels."
                ),
                remediation=(
                    f"Enable all four Block Public Access settings at the {missing} "
                    f"level as well."
                ),
                asset=_bucket_asset(name, account_id),
                evidence={
                    "bucket": name,
                    "bucket_bpa": bucket_blocked,
                    "account_bpa": account_blocked,
                    "missing_level": missing,
                    "required_settings": list(_BPA_KEYS),
                    "account_bpa_region": bpa_region,
                },
                api="s3:GetPublicAccessBlock + s3:GetAccountPublicAccessBlock",
                rationale=(
                    f"Bucket-level fully blocked = {bucket_blocked}, account-level = "
                    f"{account_blocked}. The bucket is not publicly exposed right now, "
                    f"but CIS 2.1.4 is satisfied only when both S3.1 (account) and S3.8 "
                    f"(bucket) pass, so a single change to the {'account' if account_blocked else 'bucket'} "
                    f"setting would expose it."
                ),
                verify=f"aws s3api get-public-access-block --bucket {name}",
                resource=name,
            )
        )
    return findings
