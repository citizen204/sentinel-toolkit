from __future__ import annotations

import boto3


def account_id_from_arn(arn: str) -> str | None:
    """The account id embedded in a role ARN, or None if it isn't parseable.

    Needed when AssumeRole fails: STS never answers, so the account id has to come
    from the ARN we were about to use. Without it the failure cannot be attributed
    to a scope, and an unreachable account leaves no trace in coverage.
    """
    parts = arn.split(":") if arn else []
    # arn:partition:service:region:account-id:resource
    if len(parts) >= 5 and parts[4].isdigit():
        return parts[4]
    return None


def assume_role_session(
    base_session, role_arn: str, session_name: str = "sentinel-audit"
) -> boto3.Session:
    """Return a session for `role_arn`, assumed from `base_session`.

    This is how one set of credentials audits many accounts: the caller needs
    ``sts:AssumeRole`` on each target role, and each target role carries the
    read-only audit policy (see docs/aws-iam-policy.json).
    """
    creds = base_session.client("sts").assume_role(
        RoleArn=role_arn, RoleSessionName=session_name
    )["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=base_session.region_name,
    )
