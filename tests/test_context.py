import boto3
from moto import mock_aws

from sentinel.core.context import ScanContext, aws_scan_context


@mock_aws
def test_scan_context_from_sts(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    ctx = aws_scan_context(session, ["us-east-1", "us-west-2"])

    assert isinstance(ctx, ScanContext)
    assert ctx.account_id  # resolved via STS GetCallerIdentity
    assert ctx.partition == "aws"
    assert ctx.regions == ["us-east-1", "us-west-2"]
    assert ctx.tool_version
    assert ctx.started_at is not None
