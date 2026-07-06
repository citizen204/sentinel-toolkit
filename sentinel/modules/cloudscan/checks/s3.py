from __future__ import annotations

from sentinel.core.finding import Finding, Severity

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
                Finding(
                    id="CLOUD-S3-PUBLIC",
                    module="cloudscan",
                    severity=Severity.HIGH,
                    title="Publicly accessible S3 bucket",
                    description=(
                        f"S3 bucket '{name}' grants access to a public group "
                        f"(AllUsers/AuthenticatedUsers)."
                    ),
                    remediation=(
                        "Remove public ACL grants and enable S3 Block Public Access."
                    ),
                    evidence={"bucket": name, "grants": grants},
                    resource=name,
                )
            )
    return findings
