from __future__ import annotations

from botocore.exceptions import ClientError

from sentinel.core.asset import Asset
from sentinel.core.finding import Finding
from sentinel.core.rule import build_finding

from .. import rules  # noqa: F401 - registers cloudscan rules

_ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


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


def check_password_policy(session) -> list[Finding]:
    """Flag an account that has no IAM password policy configured."""
    iam = session.client("iam")
    try:
        iam.get_account_password_policy()
        return []
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
        return [
            build_finding(
                "CLOUD-IAM-NO-PASSWORD-POLICY",
                description="The AWS account has no IAM password policy configured.",
                remediation=(
                    "Set an IAM account password policy (length, complexity, rotation)."
                ),
                asset=Asset(provider="aws", type="account", id="password-policy"),
                evidence={},
                resource="account-password-policy",
            )
        ]


def check_admin_users(session) -> list[Finding]:
    """Flag IAM users with AdministratorAccess attached *directly* to the user.

    Deliberately narrow: group/role/inline and wildcard customer-managed policies
    are not evaluated here — that requires effective-privilege analysis.
    """
    iam = session.client("iam")
    findings: list[Finding] = []
    for user in _iter_users(iam):
        username = user["UserName"]
        attached = iam.list_attached_user_policies(UserName=username).get(
            "AttachedPolicies", []
        )
        is_admin = any(
            p.get("PolicyArn") == _ADMIN_ARN or p.get("PolicyName") == "AdministratorAccess"
            for p in attached
        )
        if is_admin:
            findings.append(
                build_finding(
                    "CLOUD-IAM-ADMIN-POLICY",
                    description=(
                        f"IAM user '{username}' has AdministratorAccess attached directly."
                    ),
                    remediation=(
                        "Remove direct AdministratorAccess; grant least-privilege via groups/roles."
                    ),
                    asset=Asset(provider="aws", type="iam_user", id=username, name=username),
                    evidence={"user": username, "policy": _ADMIN_ARN},
                    resource=username,
                )
            )
    return findings
