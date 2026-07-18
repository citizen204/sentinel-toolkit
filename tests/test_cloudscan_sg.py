import boto3
from moto import mock_aws

from sentinel.modules.cloudscan.checks.security_groups import (
    check_open_security_groups,
)


def _make_sg(ec2, from_port, to_port, cidr):
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(
        GroupName=f"sg-{from_port}", Description="test", VpcId=vpc
    )["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg,
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": from_port, "ToPort": to_port,
            "IpRanges": [{"CidrIp": cidr}],
        }],
    )
    return sg


@mock_aws
def test_ssh_open_to_world_is_flagged(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")
    sg = _make_sg(ec2, 22, 22, "0.0.0.0/0")

    findings = check_open_security_groups(session)

    match = [f for f in findings if f.resource == sg]
    assert len(match) == 1
    assert match[0].id == "CLOUD-SG-OPEN-INGRESS"
    assert match[0].evidence["port"] == 22


@mock_aws
def test_restricted_cidr_is_not_flagged(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")
    sg = _make_sg(ec2, 22, 22, "203.0.113.0/24")

    findings = check_open_security_groups(session)

    assert all(f.resource != sg for f in findings)


@mock_aws
def test_open_but_non_risky_port_is_not_flagged(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")
    sg = _make_sg(ec2, 8080, 8080, "0.0.0.0/0")

    findings = check_open_security_groups(session)

    assert all(f.resource != sg for f in findings)


@mock_aws
def test_ipv6_open_to_world_is_flagged(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(GroupName="v6", Description="d", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg,
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
        }],
    )

    findings = check_open_security_groups(session)

    match = [f for f in findings if f.resource == sg]
    assert len(match) == 1
    assert "::/0" in match[0].evidence["cidr"]
    # the description/remediation reflect the actual CIDR, not a hardcoded IPv4
    assert "::/0" in match[0].description
    assert "0.0.0.0/0" not in match[0].description


def _authorize(ec2, name, permission):
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(GroupName=name, Description="d", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[permission])
    return sg


@mock_aws
def test_all_protocols_open_to_world_is_flagged(aws_credentials):
    """The worst rule a group can have: -1 carries no port range to match on.

    A range check alone silently returns nothing here, which reads as "clean".
    """
    session = boto3.Session(region_name="us-east-1")
    sg = _authorize(
        session.client("ec2"), "all-traffic",
        {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
    )

    findings = check_open_security_groups(session)

    match = [f for f in findings if f.resource == sg]
    assert len(match) == 1
    assert match[0].evidence["port"] == "all"
    assert match[0].evidence["protocol"] == "-1"
    # It must not masquerade as a narrow SSH finding.
    assert "all ports and protocols" in match[0].title


@mock_aws
def test_udp_on_ssh_port_is_not_reported_as_ssh(aws_credentials):
    """UDP/22 is not SSH; labelling it so sends people chasing a service that isn't there."""
    session = boto3.Session(region_name="us-east-1")
    sg = _authorize(
        session.client("ec2"), "udp-22",
        {"IpProtocol": "udp", "FromPort": 22, "ToPort": 22,
         "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
    )

    findings = check_open_security_groups(session)

    assert all(f.resource != sg for f in findings)


@mock_aws
def test_wide_tcp_range_covering_ssh_is_flagged(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    sg = _authorize(
        session.client("ec2"), "wide-range",
        {"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535,
         "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
    )

    findings = check_open_security_groups(session)

    ports = {f.evidence["port"] for f in findings if f.resource == sg}
    assert ports == {22, 3389}


@mock_aws
def test_scans_multiple_regions(aws_credentials):
    session = boto3.Session()
    regions = ["us-east-1", "us-west-2"]
    for region in regions:
        ec2 = session.client("ec2", region_name=region)
        _make_sg(ec2, 22, 22, "0.0.0.0/0")

    findings = check_open_security_groups(session, regions)

    assert len(findings) == 2
    assert {f.evidence.get("region") for f in findings} == set(regions)
