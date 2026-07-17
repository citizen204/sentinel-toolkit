import boto3
from moto import mock_aws

from sentinel.modules.cloudscan.checks.iam import check_password_policy


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
