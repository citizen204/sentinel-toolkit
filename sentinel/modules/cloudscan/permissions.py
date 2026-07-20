"""The IAM permissions each cloudscan check needs, as a machine-readable contract.

This exists because the documented least-privilege policy silently fell behind the
code: the IAM.1 check started calling ``ListEntitiesForPolicy`` to exclude
permissions boundaries, and ``docs/aws-iam-policy.json`` was never updated. Anyone
who deployed the policy from the README got AccessDenied on a real account, and
nothing in CI noticed, because no test knew what the code actually calls.

So the mapping lives here, next to the checks, and a test asserts the shipped
policy grants everything listed. Adding an API call without updating this table
fails the build rather than a customer's scan.

Keys match the check names recorded in coverage units, so a reader tracing a
``CLOUD-CHECK-ERROR`` back to a missing permission has a direct path.
"""
from __future__ import annotations

# check name -> IAM actions that check invokes, directly or through a paginator.
REQUIRED_ACTIONS: dict[str, tuple[str, ...]] = {
    "region_discovery": ("ec2:DescribeRegions",),
    "scan_context": ("sts:GetCallerIdentity",),
    "assume_role": ("sts:AssumeRole",),

    "s3_public_buckets": ("s3:ListAllMyBuckets", "s3:GetBucketAcl"),
    "s3_encryption": ("s3:ListAllMyBuckets", "s3:GetEncryptionConfiguration"),
    "s3_versioning": ("s3:ListAllMyBuckets", "s3:GetBucketVersioning"),
    "s3_block_public_access": (
        "s3:ListAllMyBuckets",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetAccountPublicAccessBlock",
    ),
    "s3_block_public_access_strict": (
        "s3:ListAllMyBuckets",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetAccountPublicAccessBlock",
    ),

    "iam_users_without_mfa": ("iam:ListUsers", "iam:ListMFADevices"),
    "iam_password_policy": ("iam:GetAccountPasswordPolicy",),
    "iam_effective_admin": (
        "iam:ListUsers",
        "iam:ListAttachedUserPolicies",
        "iam:ListUserPolicies",
        "iam:GetUserPolicy",
        "iam:ListGroupsForUser",
        "iam:ListAttachedGroupPolicies",
        "iam:ListGroupPolicies",
        "iam:GetGroupPolicy",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
    ),
    "iam_customer_managed_admin": (
        "iam:ListPolicies",
        "iam:GetPolicyVersion",
        # Excludes permissions boundary policies, as AWS IAM.1 does.
        "iam:ListEntitiesForPolicy",
    ),

    "open_security_groups": ("ec2:DescribeSecurityGroups",),
    "ebs_encryption": ("ec2:DescribeVolumes",),
    "rds_encryption": ("rds:DescribeDBInstances",),
}


def required_actions() -> set[str]:
    """Every IAM action cloudscan can call, across all checks."""
    return {action for actions in REQUIRED_ACTIONS.values() for action in actions}


def actions_for(check: str) -> tuple[str, ...]:
    """The actions one check needs, for explaining an AccessDenied failure."""
    return REQUIRED_ACTIONS.get(check, ())
