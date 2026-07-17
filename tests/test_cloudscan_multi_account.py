import boto3
from moto import mock_aws

from sentinel.core.config import AwsAccount, Config


def _public_bucket(session):
    s3 = session.client("s3")
    s3.create_bucket(Bucket="public-bucket")
    s3.put_bucket_acl(Bucket="public-bucket", ACL="public-read")


@mock_aws
def test_assume_role_scans_target_account(aws_credentials):
    from sentinel.modules.cloudscan.scanner import CloudScanner

    _public_bucket(boto3.Session(region_name="us-east-1"))

    cfg = Config(
        aws_accounts=[AwsAccount(role_arn="arn:aws:iam::123456789012:role/audit", regions=["us-east-1"])]
    )
    findings = CloudScanner().run(cfg)

    ids = {f.id for f in findings}
    assert "CLOUD-S3-PUBLIC" in ids


@mock_aws
def test_failed_assume_role_is_isolated(aws_credentials, monkeypatch):
    from sentinel.modules.cloudscan import scanner as scanner_mod

    _public_bucket(boto3.Session(region_name="us-east-1"))

    real = scanner_mod.assume_role_session

    def fake(base, role_arn, **kwargs):
        if "bad" in role_arn:
            raise RuntimeError("AccessDenied assuming role")
        return real(base, role_arn, **kwargs)

    monkeypatch.setattr(scanner_mod, "assume_role_session", fake)

    cfg = Config(
        aws_accounts=[
            AwsAccount(role_arn="arn:aws:iam::111111111111:role/bad"),
            AwsAccount(role_arn="arn:aws:iam::123456789012:role/audit", regions=["us-east-1"]),
        ]
    )
    findings = scanner_mod.CloudScanner().run(cfg)

    ids = {f.id for f in findings}
    assert "CLOUD-CHECK-ERROR" in ids  # the unreachable account is reported
    assert "CLOUD-S3-PUBLIC" in ids    # ...and the reachable one still got scanned
