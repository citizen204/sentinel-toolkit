import boto3
from moto import mock_aws

from sentinel.modules.cloudscan.checks.iam_privilege import (
    check_effective_admin,
    is_admin_document,
)

_ADMIN_DOC = (
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
)
_READONLY_DOC = (
    '{"Version":"2012-10-17","Statement":'
    '[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}'
)


# --- wildcard detection ------------------------------------------------------

def test_is_admin_document_detects_wildcards():
    assert is_admin_document({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    assert is_admin_document(
        {"Statement": [{"Effect": "Allow", "Action": ["*:*"], "Resource": ["*"]}]}
    )


def test_is_admin_document_ignores_scoped_and_deny():
    assert not is_admin_document(
        {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
    )
    assert not is_admin_document(
        {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::b"}]}
    )
    assert not is_admin_document(
        {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
    )


# --- the paths that actually reach a user ------------------------------------

@mock_aws
def test_admin_via_customer_managed_policy_on_user(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    arn = iam.create_policy(PolicyName="HomeGrownAdmin", PolicyDocument=_ADMIN_DOC)[
        "Policy"
    ]["Arn"]
    iam.create_user(UserName="wildcard-user")
    iam.attach_user_policy(UserName="wildcard-user", PolicyArn=arn)

    findings = check_effective_admin(session)

    assert [f.resource for f in findings] == ["wildcard-user"]
    assert "HomeGrownAdmin" in findings[0].evidence["admin_paths"][0]


@mock_aws
def test_admin_via_inline_user_policy(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    iam.create_user(UserName="inline-user")
    iam.put_user_policy(
        UserName="inline-user", PolicyName="inline-admin", PolicyDocument=_ADMIN_DOC
    )

    findings = check_effective_admin(session)

    assert [f.resource for f in findings] == ["inline-user"]
    assert "inline policy" in findings[0].evidence["admin_paths"][0]


@mock_aws
def test_admin_inherited_through_group(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    arn = iam.create_policy(PolicyName="GroupAdmin", PolicyDocument=_ADMIN_DOC)["Policy"][
        "Arn"
    ]
    iam.create_group(GroupName="admins")
    iam.attach_group_policy(GroupName="admins", PolicyArn=arn)
    iam.create_user(UserName="group-member")
    iam.add_user_to_group(GroupName="admins", UserName="group-member")

    findings = check_effective_admin(session)

    # the whole point: nothing is attached to the user directly
    assert [f.resource for f in findings] == ["group-member"]
    assert "via group 'admins'" in findings[0].evidence["admin_paths"][0]


@mock_aws
def test_admin_via_inline_group_policy(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    iam.create_group(GroupName="ops")
    iam.put_group_policy(
        GroupName="ops", PolicyName="ops-admin", PolicyDocument=_ADMIN_DOC
    )
    iam.create_user(UserName="ops-user")
    iam.add_user_to_group(GroupName="ops", UserName="ops-user")

    findings = check_effective_admin(session)

    assert [f.resource for f in findings] == ["ops-user"]


@mock_aws
def test_least_privilege_user_is_not_flagged(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    arn = iam.create_policy(PolicyName="ReadOnlyish", PolicyDocument=_READONLY_DOC)[
        "Policy"
    ]["Arn"]
    iam.create_user(UserName="scoped-user")
    iam.attach_user_policy(UserName="scoped-user", PolicyArn=arn)

    assert check_effective_admin(session) == []
