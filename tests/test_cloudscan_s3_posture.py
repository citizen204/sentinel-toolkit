import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from sentinel.modules.cloudscan.checks.s3 import (
    check_bucket_encryption,
    check_bucket_public_access_block,
    check_bucket_versioning,
)


class _DeniedS3:
    """A client whose encryption lookup fails with an unexpected error."""

    def list_buckets(self):
        return {"Buckets": [{"Name": "b"}]}

    def get_bucket_encryption(self, Bucket):  # noqa: N803 - boto3 kwarg name
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "GetBucketEncryption",
        )


class _FakeSession:
    def client(self, *args, **kwargs):
        return _DeniedS3()


def test_encryption_reraises_unexpected_client_error():
    # AccessDenied must NOT be swallowed into "no findings" — that would be a
    # dangerous false negative. It surfaces so _run_check reports CLOUD-CHECK-ERROR.
    with pytest.raises(ClientError):
        check_bucket_encryption(_FakeSession())


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
def test_account_level_bpa_prevents_false_positive(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    session.client("s3").create_bucket(Bucket="no-bucket-bpa")
    account_id = session.client("sts").get_caller_identity()["Account"]
    session.client("s3control").put_public_access_block(
        AccountId=account_id,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        },
    )

    # account-level BPA covers every bucket → no finding despite no bucket-level BPA
    assert check_bucket_public_access_block(session) == []


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
