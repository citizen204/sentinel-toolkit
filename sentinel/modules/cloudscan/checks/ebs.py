from __future__ import annotations

from sentinel.core.asset import Asset
from sentinel.core.finding import Finding
from sentinel.core.rule import build_finding

from .. import rules  # noqa: F401 - registers cloudscan rules


def check_unencrypted_volumes(session, regions=None) -> list[Finding]:
    """Flag EBS volumes that are not encrypted at rest."""
    findings: list[Finding] = []
    for region in (regions or [None]):
        ec2 = session.client("ec2", region_name=region) if region else session.client("ec2")
        for vol in ec2.describe_volumes().get("Volumes", []):
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
                    asset=Asset(provider="aws", type="ebs_volume", id=vol_id, region=region),
                    evidence=evidence,
                    resource=vol_id,
                )
            )
    return findings
