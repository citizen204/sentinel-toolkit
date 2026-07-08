import boto3
from moto import mock_aws

from sentinel.modules.cloudscan.checks.iam import check_admin_users, check_password_policy

_ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


@mock_aws
def test_password_policy_flagged_when_absent(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    findings = check_password_policy(session)
    assert len(findings) == 1
    assert findings[0].id == "CLOUD-IAM-NO-PASSWORD-POLICY"


@mock_aws
def test_password_policy_ok_when_set(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    session.client("iam").update_account_password_policy(MinimumPasswordLength=14)
    assert check_password_policy(session) == []


@mock_aws
def test_admin_user_flagged(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    # moto doesn't preload AWS-managed policies, so attach a same-named managed policy.
    admin_doc = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
    arn = iam.create_policy(PolicyName="AdministratorAccess", PolicyDocument=admin_doc)[
        "Policy"
    ]["Arn"]
    iam.create_user(UserName="admin-ish")
    iam.attach_user_policy(UserName="admin-ish", PolicyArn=arn)
    iam.create_user(UserName="normal")

    flagged = {f.resource for f in check_admin_users(session)}
    assert "admin-ish" in flagged
    assert "normal" not in flagged
