from __future__ import annotations

from sentinel.core.asset import Asset
from sentinel.core.finding import Finding
from sentinel.core.rule import build_finding

from .. import rules  # noqa: F401 - registers cloudscan rules

# Ports that are dangerous to expose to the whole internet.
RISKY_PORTS = {22: "SSH", 3389: "RDP"}


def _covers(perm: dict, port: int) -> bool:
    from_port = perm.get("FromPort")
    to_port = perm.get("ToPort")
    if from_port is None or to_port is None:
        return False
    return from_port <= port <= to_port


def _world_open_cidrs(perm: dict) -> list[str]:
    """Return the world-open CIDRs on this permission (IPv4 0.0.0.0/0, IPv6 ::/0)."""
    cidrs: list[str] = []
    if any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])):
        cidrs.append("0.0.0.0/0")
    if any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", [])):
        cidrs.append("::/0")
    return cidrs


def _iter_security_groups(ec2):
    """Yield every security group, paginating so large accounts are fully covered."""
    for page in ec2.get_paginator("describe_security_groups").paginate():
        yield from page.get("SecurityGroups", [])


def _scan_group(sg: dict, region: str | None, account_id: str | None = None) -> list[Finding]:
    group_id = sg["GroupId"]
    findings: list[Finding] = []
    for perm in sg.get("IpPermissions", []):
        open_cidrs = _world_open_cidrs(perm)
        if not open_cidrs:
            continue
        for port, label in RISKY_PORTS.items():
            if not _covers(perm, port):
                continue
            cidr_str = ", ".join(open_cidrs)
            evidence = {"group_id": group_id, "port": port, "cidr": cidr_str}
            if region:
                evidence["region"] = region
            findings.append(
                build_finding(
                    "CLOUD-SG-OPEN-INGRESS",
                    title=f"Security group open to the world on {label}",
                    description=(
                        f"Security group '{group_id}' allows {cidr_str} "
                        f"inbound on port {port} ({label})."
                    ),
                    remediation=(
                        f"Restrict inbound {label} (port {port}) to known "
                        f"IP ranges instead of {cidr_str}."
                    ),
                    asset=Asset(
                        provider="aws", type="security_group",
                        id=group_id, region=region, account_id=account_id,
                    ),
                    evidence=evidence,
                    api="ec2:DescribeSecurityGroups",
                    rationale=(
                        f"An inbound rule permits {cidr_str} (the whole internet) to reach "
                        f"port {port}, which exposes {label} — a remote administration "
                        f"service — to untrusted networks."
                    ),
                    verify=(
                        f"aws ec2 describe-security-groups --group-ids {group_id}"
                        + (f" --region {region}" if region else "")
                    ),
                    resource=group_id,
                )
            )
    return findings


def check_open_security_groups(session, regions=None, account_id=None) -> list[Finding]:
    """Flag security groups allowing 0.0.0.0/0 or ::/0 inbound on a risky port.

    When `regions` is given, every region is scanned; otherwise the session's
    default region is used.
    """
    findings: list[Finding] = []
    for region in (regions or [None]):
        ec2 = session.client("ec2", region_name=region) if region else session.client("ec2")
        for sg in _iter_security_groups(ec2):
            findings.extend(_scan_group(sg, region, account_id))
    return findings
