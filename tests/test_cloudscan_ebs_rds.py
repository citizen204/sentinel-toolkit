import boto3
from moto import mock_aws

from sentinel.modules.cloudscan.checks.ebs import check_unencrypted_volumes
from sentinel.modules.cloudscan.checks.rds import check_unencrypted_databases


@mock_aws
def test_unencrypted_ebs_volume_flagged(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")
    unenc = ec2.create_volume(AvailabilityZone="us-east-1a", Size=8, Encrypted=False)["VolumeId"]
    enc = ec2.create_volume(AvailabilityZone="us-east-1a", Size=8, Encrypted=True)["VolumeId"]

    flagged = {f.resource for f in check_unencrypted_volumes(session)}
    assert unenc in flagged
    assert enc not in flagged


@mock_aws
def test_unencrypted_rds_instance_flagged(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    rds = session.client("rds")
    common = dict(
        DBInstanceClass="db.t3.micro", Engine="postgres",
        AllocatedStorage=20, MasterUsername="admin", MasterUserPassword="password123",
    )
    rds.create_db_instance(DBInstanceIdentifier="unenc-db", StorageEncrypted=False, **common)
    rds.create_db_instance(DBInstanceIdentifier="enc-db", StorageEncrypted=True, **common)

    flagged = {f.resource for f in check_unencrypted_databases(session)}
    assert "unenc-db" in flagged
    assert "enc-db" not in flagged
