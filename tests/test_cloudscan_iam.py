import boto3
from moto import mock_aws
from sentinel.modules.cloudscan.checks.iam import check_users_without_mfa
from sentinel.core.finding import Severity


@mock_aws
def test_user_without_mfa_is_flagged(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    iam.create_user(UserName="no-mfa-user")

    findings = check_users_without_mfa(session)

    assert len(findings) == 1
    assert findings[0].id == "CLOUD-IAM-NO-MFA"
    assert findings[0].resource == "no-mfa-user"
    assert findings[0].severity is Severity.MEDIUM


@mock_aws
def test_user_with_mfa_is_not_flagged(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    iam.create_user(UserName="mfa-user")
    dev = iam.create_virtual_mfa_device(VirtualMFADeviceName="dev1")
    iam.enable_mfa_device(
        UserName="mfa-user",
        SerialNumber=dev["VirtualMFADevice"]["SerialNumber"],
        AuthenticationCode1="123456",
        AuthenticationCode2="234567",
    )

    findings = check_users_without_mfa(session)

    assert all(f.resource != "mfa-user" for f in findings)


@mock_aws
def test_no_users_yields_no_findings(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    assert check_users_without_mfa(session) == []


@mock_aws
def test_pagination_covers_all_users(aws_credentials):
    # moto paginates list_users at 100; a single API call would miss users 101-120.
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    for i in range(120):
        iam.create_user(UserName=f"user-{i:03d}")

    findings = check_users_without_mfa(session)

    assert len(findings) == 120
