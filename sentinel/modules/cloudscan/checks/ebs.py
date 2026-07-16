from __future__ import annotations

from sentinel.core.asset import Asset
from sentinel.core.finding import Finding
from sentinel.core.rule import build_finding

from .. import rules  # noqa: F401 - registers cloudscan rules


def _iter_volumes(ec2):
    """Yield every EBS volume, paginating so large accounts are fully covered."""
    for page in ec2.get_paginator("describe_volumes").paginate():
        yield from page.get("Volumes", [])


def check_unencrypted_volumes(session, regions=None, account_id=None) -> list[Finding]:
    """Flag EBS volumes that are not encrypted at rest."""
    findings: list[Finding] = []
    for region in (regions or [None]):
        ec2 = session.client("ec2", region_name=region) if region else session.client("ec2")
        for vol in _iter_volumes(ec2):
            if vol.get("Encrypted", False):
                continue
            vol_id = vol["VolumeId"]
            evidence = {"volume_id": vol_id}
            if region:
                evidence["region"] = region
            findings.append(
                build_finding(
                    "CLOUD-EBS-UNENCRYPTED",
                    description=f"EBS volume '{vol_id}' is not encrypted at rest.",
                    remediation="Encrypt the volume and enable EBS encryption by default.",
                    asset=Asset(
                        provider="aws", type="ebs_volume", id=vol_id,
                        region=region, account_id=account_id,
                    ),
                    evidence={**evidence, "encrypted": False},
                    api="ec2:DescribeVolumes",
                    rationale=(
                        "DescribeVolumes reports Encrypted=false, so the volume's data and "
                        "its snapshots are stored unencrypted at rest."
                    ),
                    verify=(
                        f"aws ec2 describe-volumes --volume-ids {vol_id}"
                        + (f" --region {region}" if region else "")
                    ),
                    resource=vol_id,
                )
            )
    return findings
