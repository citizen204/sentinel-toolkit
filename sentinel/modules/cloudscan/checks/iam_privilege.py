"""Effective-privilege analysis for IAM users.

Real admin risk rarely looks like "AdministratorAccess attached to the user". It
arrives through groups, inline policies, and customer-managed policies that quietly
grant ``Action: "*"`` on ``Resource: "*"``. This module resolves every path that
reaches a user and reports the ones that are admin-equivalent, naming the path.

Out of scope (documented, not silently missing): privilege-escalation chains such
as iam:PassRole + compute, and permission boundaries / SCPs that could constrain
an otherwise-admin policy.
"""
from __future__ import annotations

import json
from urllib.parse import unquote

from sentinel.core.asset import Asset
from sentinel.core.finding import Finding
from sentinel.core.rule import build_finding

from .. import rules  # noqa: F401 - registers cloudscan rules

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
_WILDCARD_ACTIONS = {"*", "*:*"}


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _as_document(value) -> dict:
    """IAM policy documents arrive as dicts (botocore decodes) or encoded strings."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            return json.loads(unquote(value))
        except (ValueError, TypeError):
            return {}
    return {}


def is_admin_document(document) -> bool:
    """True if the policy allows every action on every resource."""
    doc = _as_document(document)
    statements = _as_list(doc.get("Statement"))
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        actions = {str(a) for a in _as_list(statement.get("Action"))}
        resources = {str(r) for r in _as_list(statement.get("Resource"))}
        if actions & _WILDCARD_ACTIONS and "*" in resources:
            return True
    return False


def _managed_policy_is_admin(iam, policy_arn: str, policy_name: str) -> bool:
    # The AWS-managed AdministratorAccess is admin by definition; short-circuit so
    # we neither pay for the lookup nor depend on it being readable.
    if policy_arn == ADMIN_POLICY_ARN or policy_name == "AdministratorAccess":
        return True
    policy = iam.get_policy(PolicyArn=policy_arn)["Policy"]
    version = iam.get_policy_version(
        PolicyArn=policy_arn, VersionId=policy["DefaultVersionId"]
    )
    return is_admin_document(version["PolicyVersion"]["Document"])


def admin_paths(iam, username: str) -> list[str]:
    """Every path granting `username` admin-equivalent privileges."""
    paths: list[str] = []

    for policy in iam.list_attached_user_policies(UserName=username).get(
        "AttachedPolicies", []
    ):
        if _managed_policy_is_admin(iam, policy["PolicyArn"], policy["PolicyName"]):
            paths.append(f"managed policy '{policy['PolicyName']}' attached to the user")

    for name in iam.list_user_policies(UserName=username).get("PolicyNames", []):
        document = iam.get_user_policy(UserName=username, PolicyName=name)[
            "PolicyDocument"
        ]
        if is_admin_document(document):
            paths.append(f"inline policy '{name}' on the user")

    for group in iam.list_groups_for_user(UserName=username).get("Groups", []):
        group_name = group["GroupName"]
        for policy in iam.list_attached_group_policies(GroupName=group_name).get(
            "AttachedPolicies", []
        ):
            if _managed_policy_is_admin(iam, policy["PolicyArn"], policy["PolicyName"]):
                paths.append(
                    f"managed policy '{policy['PolicyName']}' via group '{group_name}'"
                )
        for name in iam.list_group_policies(GroupName=group_name).get("PolicyNames", []):
            document = iam.get_group_policy(GroupName=group_name, PolicyName=name)[
                "PolicyDocument"
            ]
            if is_admin_document(document):
                paths.append(f"inline policy '{name}' via group '{group_name}'")

    return paths


def _iter_users(iam):
    for page in iam.get_paginator("list_users").paginate():
        yield from page.get("Users", [])


def check_effective_admin(session, account_id: str | None = None) -> list[Finding]:
    """Flag IAM users who are admin-equivalent through any policy path."""
    iam = session.client("iam")
    findings: list[Finding] = []
    for user in _iter_users(iam):
        username = user["UserName"]
        paths = admin_paths(iam, username)
        if not paths:
            continue
        findings.append(
            build_finding(
                "CLOUD-IAM-EFFECTIVE-ADMIN",
                description=(
                    f"IAM user '{username}' has admin-equivalent privileges via "
                    f"{len(paths)} path(s)."
                ),
                remediation=(
                    "Remove the wildcard grant and replace it with least-privilege "
                    "policies scoped to the actions and resources actually needed."
                ),
                asset=Asset(
                    provider="aws", type="iam_user", id=username,
                    name=username, account_id=account_id,
                ),
                evidence={"user": username, "admin_paths": paths},
                api=(
                    "iam:ListAttachedUserPolicies, iam:ListUserPolicies, "
                    "iam:ListGroupsForUser, iam:GetPolicyVersion"
                ),
                rationale=(
                    f"'{username}' is granted Action '*' on Resource '*' through: "
                    f"{'; '.join(paths)}. That is unrestricted control of the account, "
                    f"regardless of how indirectly it is attached."
                ),
                verify=(
                    f"aws iam list-attached-user-policies --user-name {username}; "
                    f"aws iam list-groups-for-user --user-name {username}"
                ),
                resource=username,
            )
        )
    return findings
