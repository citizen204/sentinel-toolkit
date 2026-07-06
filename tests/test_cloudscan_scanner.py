import boto3
from moto import mock_aws
from sentinel.core.scanner import all_scanners
from sentinel.core.config import Config


def test_cloudscan_is_registered():
    import sentinel.modules  # noqa: F401  triggers registration
    assert "cloudscan" in all_scanners()


@mock_aws
def test_run_aggregates_all_checks(aws_credentials):
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
            "IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )

    iam = session.client("iam")
    iam.create_user(UserName="no-mfa-user")

    findings = CloudScanner().run(Config())

    ids = {f.id for f in findings}
    assert ids == {"CLOUD-S3-PUBLIC", "CLOUD-SG-OPEN-INGRESS", "CLOUD-IAM-NO-MFA"}
