from __future__ import annotations

from sentinel.core.asset import Asset
from sentinel.core.finding import Finding
from sentinel.core.rule import build_finding

from .. import rules  # noqa: F401 - registers cloudscan rules

_PUBLIC_URIS = (
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
)


def _is_public(grants: list[dict]) -> bool:
    for grant in grants:
        uri = grant.get("Grantee", {}).get("URI", "")
        if uri in _PUBLIC_URIS:
            return True
    return False


def check_public_buckets(session) -> list[Finding]:
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
                    asset=Asset(provider="aws", type="s3_bucket", id=name, name=name),
                    evidence={"bucket": name, "grants": grants},
                    resource=name,
                )
            )
    return findings
