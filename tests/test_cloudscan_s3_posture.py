import boto3
from moto import mock_aws

from sentinel.modules.cloudscan.checks.s3 import (
    check_bucket_encryption,
    check_bucket_public_access_block,
    check_bucket_versioning,
)


@mock_aws
def test_versioning_flagged_when_disabled(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="novers")
    s3.create_bucket(Bucket="hasvers")
    s3.put_bucket_versioning(
        Bucket="hasvers", VersioningConfiguration={"Status": "Enabled"}
    )

    flagged = {f.resource for f in check_bucket_versioning(session)}
    assert "novers" in flagged
    assert "hasvers" not in flagged


@mock_aws
def test_block_public_access_flagged_when_absent(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="nobpa")
    s3.create_bucket(Bucket="hasbpa")
    s3.put_public_access_block(
        Bucket="hasbpa",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        },
    )

    flagged = {f.resource for f in check_bucket_public_access_block(session)}
    assert "nobpa" in flagged
    assert "hasbpa" not in flagged


@mock_aws
def test_encryption_flagged_when_absent(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="noenc")
    s3.create_bucket(Bucket="hasenc")
    s3.put_bucket_encryption(
        Bucket="hasenc",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )

    flagged = {f.resource for f in check_bucket_encryption(session)}
    assert "noenc" in flagged
    assert "hasenc" not in flagged
