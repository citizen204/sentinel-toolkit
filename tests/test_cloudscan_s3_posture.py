import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from sentinel.modules.cloudscan.checks.s3 import (
    check_bucket_encryption,
    check_bucket_public_access_block,
    check_bucket_versioning,
)


class _FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return iter(self._pages)


class _DeniedS3:
    """A client whose encryption lookup fails with an unexpected error."""

    def get_paginator(self, operation):
        assert operation == "list_buckets"
        return _FakePaginator([{"Buckets": [{"Name": "b"}]}])

    def list_buckets(self):
        # Enumerating buckets without a paginator breaks on accounts above the
        # 10,000-bucket quota, so the bare call must never be used.
        raise AssertionError("list_buckets must be called through a paginator")

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
def test_account_bpa_uses_the_region_it_is_given(aws_credentials):
    # s3control is regional: the region must be explicit, not left to the
    # session default (which may not exist -> NoRegionError on a real account).
    session = boto3.Session(region_name="us-east-1")
    session.client("s3").create_bucket(Bucket="region-test-bucket")

    findings = check_bucket_public_access_block(session, region="ap-southeast-2")

    finding = next(f for f in findings if f.resource == "region-test-bucket")
    assert finding.evidence["account_bpa_region"] == "ap-southeast-2"


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


# --- one enumeration, shared ---------------------------------------------------

class _CountingS3:
    """Counts how many times the account's buckets get enumerated."""

    def __init__(self):
        self.list_calls = 0
        self.bpa_calls = 0

    def get_paginator(self, operation):
        assert operation == "list_buckets"
        self.list_calls += 1
        return _FakePaginator([
            {"Buckets": [{"Name": "a"}]},
            {"Buckets": [{"Name": "b"}]},   # deliberately a second page
        ])

    def get_bucket_acl(self, Bucket):  # noqa: N803
        return {"Grants": []}

    def get_bucket_versioning(self, Bucket):  # noqa: N803
        return {"Status": "Enabled"}

    def get_public_access_block(self, Bucket):  # noqa: N803
        raise ClientError(
            {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration", "Message": "x"}},
            "GetPublicAccessBlock",
        )


class _CountingSession:
    def __init__(self):
        self.s3 = _CountingS3()

    def client(self, service, **kwargs):
        if service == "sts":
            return _FakeSts()
        if service == "s3control":
            return _FakeS3Control(self.s3)
        return self.s3

    @property
    def region_name(self):
        return "us-east-1"


class _FakeSts:
    def get_caller_identity(self):
        return {"Account": "123456789012"}


class _FakeS3Control:
    def __init__(self, counter):
        self._counter = counter

    def get_public_access_block(self, AccountId):  # noqa: N803
        self._counter.bpa_calls += 1
        raise ClientError(
            {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration", "Message": "x"}},
            "GetPublicAccessBlock",
        )


def test_bucket_pagination_covers_every_page():
    from sentinel.modules.cloudscan.checks.s3 import S3Inventory

    session = _CountingSession()
    assert S3Inventory(session).names == ["a", "b"]


def test_shared_inventory_enumerates_buckets_once():
    """Five checks used to mean five full ListBuckets sweeps of the account."""
    from sentinel.modules.cloudscan.checks.s3 import (
        S3Inventory,
        check_bucket_public_access_block,
        check_bucket_public_access_block_strict,
        check_bucket_versioning,
        check_public_buckets,
    )

    session = _CountingSession()
    inv = S3Inventory(session, "us-east-1")

    check_public_buckets(session, "123456789012", inv)
    check_bucket_versioning(session, "123456789012", inv)
    check_bucket_public_access_block(session, "123456789012", "us-east-1", inv)
    check_bucket_public_access_block_strict(session, "123456789012", "us-east-1", inv)

    assert session.s3.list_calls == 1
    # ... and the account-level BPA config is fetched once, not once per check.
    assert session.s3.bpa_calls == 1
