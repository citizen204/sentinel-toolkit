from __future__ import annotations

from sentinel.core.asset import Asset
from sentinel.core.finding import Finding
from sentinel.core.rule import build_finding

from .. import rules  # noqa: F401 - registers cloudscan rules

# Ports that are dangerous to expose to the whole internet.
RISKY_PORTS = {22: "SSH", 3389: "RDP"}

# SSH and RDP are TCP services, so only TCP -- or "all protocols" -- can reach them.
# EC2 accepts either the name or the IANA number.
_TCP_PROTOCOLS = {"tcp", "6"}
ALL_PROTOCOLS = "-1"


def _protocol_of(perm: dict) -> str:
    return str(perm.get("IpProtocol", "")).lower()


def _is_all_protocols(perm: dict) -> bool:
    """True for the "all traffic" rule.

    EC2 encodes it as IpProtocol "-1" and omits FromPort/ToPort entirely -- there
    is no port range to compare against, which is exactly why a range check alone
    silently misses the single worst rule a group can have.
    """
    return _protocol_of(perm) == ALL_PROTOCOLS


def _covers(perm: dict, port: int) -> bool:
    """True if this permission actually admits TCP traffic to `port`.

    Protocol matters in both directions: "all traffic" reaches every port, while
    UDP on 22 is not SSH and must not be reported as such.
    """
    if _is_all_protocols(perm):
        return True
    if _protocol_of(perm) not in _TCP_PROTOCOLS:
        return False
    from_port = perm.get("FromPort")
    to_port = perm.get("ToPort")
    if from_port is None or to_port is None:
        # A TCP permission with no range admits the entire port range.
        return True
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


def _ingress_finding(
    group_id: str,
    region: str | None,
    account_id: str | None,
    cidr_str: str,
    protocol: str,
    port: str | int,
    title: str,
    description: str,
    remediation: str,
    rationale: str,
) -> Finding:
    evidence = {
        "group_id": group_id,
        "port": port,
        "cidr": cidr_str,
        "protocol": protocol,
    }
    if region:
        evidence["region"] = region
    return build_finding(
        "CLOUD-SG-OPEN-INGRESS",
        title=title,
        description=description,
        remediation=remediation,
        asset=Asset(
            provider="aws", type="security_group",
            id=group_id, region=region, account_id=account_id,
        ),
        evidence=evidence,
        api="ec2:DescribeSecurityGroups",
        rationale=rationale,
        verify=(
            f"aws ec2 describe-security-groups --group-ids {group_id}"
            + (f" --region {region}" if region else "")
        ),
        resource=group_id,
    )


def _scan_group(sg: dict, region: str | None, account_id: str | None = None) -> list[Finding]:
    group_id = sg["GroupId"]
    findings: list[Finding] = []
    for perm in sg.get("IpPermissions", []):
        open_cidrs = _world_open_cidrs(perm)
        if not open_cidrs:
            continue
        cidr_str = ", ".join(open_cidrs)
        protocol = _protocol_of(perm)

        # Reported on its own rather than as "port 22 is open": someone who reads
        # the narrower message would harden SSH and believe they were done, while
        # every other port stayed open to the internet.
        if _is_all_protocols(perm):
            findings.append(
                _ingress_finding(
                    group_id, region, account_id, cidr_str, protocol, "all",
                    title="Security group open to the world on all ports and protocols",
                    description=(
                        f"Security group '{group_id}' allows {cidr_str} inbound on "
                        f"every port and protocol."
                    ),
                    remediation=(
                        "Replace the all-traffic rule with rules scoped to the "
                        "specific protocols, ports, and source ranges required."
                    ),
                    rationale=(
                        f"An inbound rule permits {cidr_str} (the whole internet) with "
                        f"IpProtocol '-1', which admits every protocol on every port — "
                        f"including SSH and RDP — to anything attached to this group."
                    ),
                )
            )
            continue

        for port, label in RISKY_PORTS.items():
            if not _covers(perm, port):
                continue
            findings.append(
                _ingress_finding(
                    group_id, region, account_id, cidr_str, protocol, port,
                    title=f"Security group open to the world on {label}",
                    description=(
                        f"Security group '{group_id}' allows {cidr_str} "
                        f"inbound on port {port} ({label})."
                    ),
                    remediation=(
                        f"Restrict inbound {label} (port {port}) to known "
                        f"IP ranges instead of {cidr_str}."
                    ),
                    rationale=(
                        f"An inbound {protocol.upper()} rule permits {cidr_str} (the whole "
                        f"internet) to reach port {port}, which exposes {label} — a remote "
                        f"administration service — to untrusted networks."
                    ),
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
