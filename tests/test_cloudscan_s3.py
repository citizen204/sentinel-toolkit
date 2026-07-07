import boto3
from moto import mock_aws

from sentinel.core.finding import Severity
from sentinel.modules.cloudscan.checks.s3 import check_public_buckets


@mock_aws
def test_public_bucket_is_flagged(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="private-bucket")
    s3.create_bucket(Bucket="public-bucket")
    s3.put_bucket_acl(Bucket="public-bucket", ACL="public-read")

    findings = check_public_buckets(session)

    flagged = {(f.id, f.resource) for f in findings}
    assert ("CLOUD-S3-PUBLIC", "public-bucket") in flagged
    assert all(f.resource != "private-bucket" for f in findings)
    public = next(f for f in findings if f.resource == "public-bucket")
    assert public.severity is Severity.HIGH
    assert public.module == "cloudscan"


@mock_aws
def test_no_buckets_yields_no_findings(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    assert check_public_buckets(session) == []
