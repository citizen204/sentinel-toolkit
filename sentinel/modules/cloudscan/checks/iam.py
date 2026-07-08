from __future__ import annotations

from sentinel.core.asset import Asset
from sentinel.core.finding import Finding
from sentinel.core.rule import build_finding

from .. import rules  # noqa: F401 - registers cloudscan rules


def _iter_users(iam):
    """Yield every IAM user, paginating so large accounts are fully covered."""
    for page in iam.get_paginator("list_users").paginate():
        yield from page.get("Users", [])


def check_users_without_mfa(session) -> list[Finding]:
    """Flag IAM users that have no MFA device enabled."""
    iam = session.client("iam")
    findings: list[Finding] = []
    for user in _iter_users(iam):
        username = user["UserName"]
        devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
        if not devices:
            findings.append(
                build_finding(
                    "CLOUD-IAM-NO-MFA",
                    description=f"IAM user '{username}' has no MFA device enabled.",
                    remediation="Enable an MFA device for this IAM user.",
                    asset=Asset(provider="aws", type="iam_user", id=username, name=username),
                    evidence={"user": username},
                    resource=username,
                )
            )
    return findings
