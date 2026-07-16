"""Every finding must be auditable.

A finding has to answer: which API produced it, what was observed, why that is a
failure, and how to verify the fix. These guards fail the build if a rule ever
ships without that trail.
"""
import boto3
import responses
from moto import mock_aws

from sentinel.core.config import Config


def _assert_auditable(findings):
    assert findings, "expected findings to check"
    for f in findings:
        assert f.api, f"{f.id}: no api"
        assert f.rationale, f"{f.id}: no rationale"
        assert f.verify, f"{f.id}: no verify"
        assert f.evidence, f"{f.id}: no evidence"


@mock_aws
def test_cloudscan_findings_are_auditable(aws_credentials):
    from sentinel.modules.cloudscan.scanner import CloudScanner

    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="public-bucket")
    s3.put_bucket_acl(Bucket="public-bucket", ACL="public-read")

    ec2 = session.client("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(GroupName="s", Description="d", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg,
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )
    ec2.create_volume(AvailabilityZone="us-east-1a", Size=1, Encrypted=False)
    session.client("iam").create_user(UserName="no-mfa")

    _assert_auditable(CloudScanner().run(Config()))


def test_logwatch_findings_are_auditable(tmp_path):
    from sentinel.modules.logwatch.scanner import LogwatchScanner

    log = tmp_path / "auth.log"
    lines = ["Failed password for invalid user admin from 10.0.0.5 port 22 ssh2"] * 6
    lines.append("Accepted password for root from 203.0.113.7 port 22 ssh2")
    log.write_text("\n".join(lines), encoding="utf-8")

    _assert_auditable(LogwatchScanner().run(Config(log_paths=[str(log)])))


@responses.activate
def test_webscan_findings_are_auditable():
    from sentinel.modules.webscan.scanner import WebScanner

    responses.add(responses.GET, "https://example.test/", status=200, headers={})
    _assert_auditable(WebScanner().run(Config(target_url="https://example.test/")))


def test_netmon_findings_are_auditable(tmp_path):
    from sentinel.modules.netmon.scanner import NetmonScanner

    flows = tmp_path / "flows.txt"
    lines = [f"10.0.0.5 10.0.0.1 {p}" for p in range(1, 13)]
    lines += [f"10.0.0.9 10.0.0.{i} 445" for i in range(1, 13)]
    flows.write_text("\n".join(lines), encoding="utf-8")

    _assert_auditable(NetmonScanner().run(Config(capture_file=str(flows))))
