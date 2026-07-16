from __future__ import annotations

import boto3


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
