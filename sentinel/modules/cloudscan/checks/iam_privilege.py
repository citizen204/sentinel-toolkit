"""Admin-privilege analysis for IAM.

Two questions live here, and conflating them is how a scanner ends up asserting
compliance it has not actually established:

``check_effective_admin`` asks *what can a user reach* - through groups, inline
policies, and managed policies that quietly grant ``Action: "*"`` on
``Resource: "*"``. That is the real-world risk question.

``check_customer_managed_admin`` asks *what does AWS IAM.1 / CIS 1.16 evaluate* -
customer managed policies only, attached or not. That is the compliance question,
and it is a different set of policies.

Out of scope for both (documented, not silently missing): privilege-escalation
chains such as iam:PassRole + compute, and policy Conditions / permission
boundaries / SCPs that could constrain an otherwise-admin policy.
"""
from __future__ import annotations

import json
import re
from urllib.parse import unquote

from sentinel.core.asset import Asset
from sentinel.core.finding import Finding
from sentinel.core.rule import build_finding

from .. import rules  # noqa: F401 - registers cloudscan rules

# Only the AWS-managed policy may be trusted by identity alone. The "::aws:" account
# field is what makes it AWS-managed; a customer policy in account 123456789012 can
# be called AdministratorAccess and grant nothing, so matching on the name alone
# invents admin users that do not exist.
_AWS_ADMIN_ARN = re.compile(r"^arn:aws[a-z0-9-]*:iam::aws:policy/AdministratorAccess$")
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


def _paginate(iam, operation: str, key: str, **kwargs):
    """Yield every item from a paginated IAM list call.

    Large accounts routinely exceed one page; taking only the first silently drops
    groups and policies, which reads as "no admin path found".
    """
    for page in iam.get_paginator(operation).paginate(**kwargs):
        yield from page.get(key, [])


def _managed_policy_is_admin(iam, policy_arn: str, cache: dict[str, bool]) -> bool:
    if policy_arn in cache:
        return cache[policy_arn]
    if _AWS_ADMIN_ARN.match(policy_arn):
        cache[policy_arn] = True
        return True
    policy = iam.get_policy(PolicyArn=policy_arn)["Policy"]
    version = iam.get_policy_version(
        PolicyArn=policy_arn, VersionId=policy["DefaultVersionId"]
    )
    result = is_admin_document(version["PolicyVersion"]["Document"])
    cache[policy_arn] = result
    return result


def admin_paths(iam, username: str, cache: dict[str, bool] | None = None) -> list[str]:
    """Every path granting `username` admin-equivalent privileges.

    `cache` memoises managed-policy verdicts across users; a policy shared by a
    whole team is otherwise re-fetched once per member.
    """
    cache = {} if cache is None else cache
    paths: list[str] = []

    for policy in _paginate(
        iam, "list_attached_user_policies", "AttachedPolicies", UserName=username
    ):
        if _managed_policy_is_admin(iam, policy["PolicyArn"], cache):
            paths.append(f"managed policy '{policy['PolicyName']}' attached to the user")

    for name in _paginate(iam, "list_user_policies", "PolicyNames", UserName=username):
        document = iam.get_user_policy(UserName=username, PolicyName=name)[
            "PolicyDocument"
        ]
        if is_admin_document(document):
            paths.append(f"inline policy '{name}' on the user")

    for group in _paginate(iam, "list_groups_for_user", "Groups", UserName=username):
        group_name = group["GroupName"]
        for policy in _paginate(
            iam, "list_attached_group_policies", "AttachedPolicies", GroupName=group_name
        ):
            if _managed_policy_is_admin(iam, policy["PolicyArn"], cache):
                paths.append(
                    f"managed policy '{policy['PolicyName']}' via group '{group_name}'"
                )
        for name in _paginate(
            iam, "list_group_policies", "PolicyNames", GroupName=group_name
        ):
            document = iam.get_group_policy(GroupName=group_name, PolicyName=name)[
                "PolicyDocument"
            ]
            if is_admin_document(document):
                paths.append(f"inline policy '{name}' via group '{group_name}'")

    return paths


def _iter_users(iam):
    for page in iam.get_paginator("list_users").paginate():
        yield from page.get("Users", [])


def check_customer_managed_admin(session, account_id: str | None = None) -> list[Finding]:
    """Flag customer managed policies whose default version grants full admin.

    This mirrors AWS IAM.1 / CIS 1.16 exactly: customer managed policies only
    (``Scope=Local``), evaluated whether or not anything is attached to them.
    ``check_effective_admin`` answers a different question - what a user can
    actually reach - and the two are deliberately not the same rule.

    Known deviation: IAM.1 sets ``excludePermissionBoundaryPolicy: true``, and this
    check does not yet detect which policies are in use as permission boundaries.
    """
    iam = session.client("iam")
    findings: list[Finding] = []
    for policy in _paginate(iam, "list_policies", "Policies", Scope="Local"):
        arn = policy["Arn"]
        version = iam.get_policy_version(
            PolicyArn=arn, VersionId=policy["DefaultVersionId"]
        )
        document = version["PolicyVersion"]["Document"]
        if not is_admin_document(document):
            continue
        name = policy["PolicyName"]
        findings.append(
            build_finding(
                "CLOUD-IAM-CUSTOM-POLICY-ADMIN",
                description=(
                    f"Customer managed policy '{name}' allows Action '*' on "
                    f"Resource '*' in its default version."
                ),
                remediation=(
                    "Scope the policy to the actions and resources it actually needs, "
                    "and publish that as a new default version."
                ),
                asset=Asset(
                    provider="aws", type="iam_policy", id=arn,
                    name=name, account_id=account_id,
                ),
                evidence={
                    "policy_name": name,
                    "policy_arn": arn,
                    "default_version": policy["DefaultVersionId"],
                    "attachment_count": policy.get("AttachmentCount"),
                },
                api="iam:ListPolicies(Scope=Local), iam:GetPolicyVersion",
                rationale=(
                    f"The default version of '{name}' contains an Allow statement with "
                    f"Action '*' over Resource '*'. Anything this policy is attached to "
                    f"gains full control of the account, so it fails AWS IAM.1 whether "
                    f"or not it is currently attached."
                ),
                verify=(
                    f"aws iam get-policy-version --policy-arn {arn} "
                    f"--version-id {policy['DefaultVersionId']}"
                ),
                resource=name,
            )
        )
    return findings


def check_effective_admin(session, account_id: str | None = None) -> list[Finding]:
    """Flag IAM users who are admin-equivalent through any policy path."""
    iam = session.client("iam")
    findings: list[Finding] = []
    cache: dict[str, bool] = {}
    for user in _iter_users(iam):
        username = user["UserName"]
        paths = admin_paths(iam, username, cache)
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
                    f"{'; '.join(paths)}. Treat this as unrestricted control of the "
                    f"account unless a policy Condition, permission boundary, or SCP "
                    f"constrains it - none of which this check evaluates."
                ),
                verify=(
                    f"aws iam list-attached-user-policies --user-name {username}; "
                    f"aws iam list-groups-for-user --user-name {username}"
                ),
                resource=username,
            )
        )
    return findings
