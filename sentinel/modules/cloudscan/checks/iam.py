from __future__ import annotations

from sentinel.core.finding import Finding, Severity


def check_users_without_mfa(session) -> list[Finding]:
    """Flag IAM users that have no MFA device enabled."""
    iam = session.client("iam")
    findings: list[Finding] = []
    for user in iam.list_users().get("Users", []):
        username = user["UserName"]
        devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
        if not devices:
            findings.append(
                Finding(
                    id="CLOUD-IAM-NO-MFA",
                    module="cloudscan",
                    severity=Severity.MEDIUM,
                    title="IAM user without MFA",
                    description=f"IAM user '{username}' has no MFA device enabled.",
                    remediation="Enable an MFA device for this IAM user.",
                    evidence={"user": username},
                    resource=username,
                )
            )
    return findings
