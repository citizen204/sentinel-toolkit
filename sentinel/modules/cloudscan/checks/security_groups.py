from __future__ import annotations

from sentinel.core.finding import Finding, Severity

# Ports that are dangerous to expose to the whole internet.
RISKY_PORTS = {22: "SSH", 3389: "RDP"}

_SG_REFERENCE = "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html"


def _covers(perm: dict, port: int) -> bool:
    from_port = perm.get("FromPort")
    to_port = perm.get("ToPort")
    if from_port is None or to_port is None:
        return False
    return from_port <= port <= to_port


def _open_to_world(perm: dict) -> bool:
    return any(rng.get("CidrIp") == "0.0.0.0/0" for rng in perm.get("IpRanges", []))


def _iter_security_groups(ec2):
    """Yield every security group, paginating so large accounts are fully covered."""
    for page in ec2.get_paginator("describe_security_groups").paginate():
        yield from page.get("SecurityGroups", [])


def _scan_group(sg: dict, region: str | None) -> list[Finding]:
    group_id = sg["GroupId"]
    findings: list[Finding] = []
    for perm in sg.get("IpPermissions", []):
        if not _open_to_world(perm):
            continue
        for port, label in RISKY_PORTS.items():
            if not _covers(perm, port):
                continue
            evidence = {"group_id": group_id, "port": port, "cidr": "0.0.0.0/0"}
            if region:
                evidence["region"] = region
            findings.append(
                Finding(
                    id="CLOUD-SG-OPEN-INGRESS",
                    module="cloudscan",
                    severity=Severity.HIGH,
                    title=f"Security group open to the world on {label}",
                    description=(
                        f"Security group '{group_id}' allows 0.0.0.0/0 "
                        f"inbound on port {port} ({label})."
                    ),
                    remediation=(
                        f"Restrict inbound {label} (port {port}) to known "
                        f"IP ranges instead of 0.0.0.0/0."
                    ),
                    category="Network Exposure",
                    references=[_SG_REFERENCE],
                    evidence=evidence,
                    resource=group_id,
                )
            )
    return findings


def check_open_security_groups(session, regions=None) -> list[Finding]:
    """Flag security groups allowing 0.0.0.0/0 inbound on a risky port.

    When `regions` is given, every region is scanned; otherwise the session's
    default region is used.
    """
    findings: list[Finding] = []
    for region in (regions or [None]):
        ec2 = session.client("ec2", region_name=region) if region else session.client("ec2")
        for sg in _iter_security_groups(ec2):
            findings.extend(_scan_group(sg, region))
    return findings
