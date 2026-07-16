from __future__ import annotations

from sentinel.core.asset import Asset
from sentinel.core.finding import Finding
from sentinel.core.rule import build_finding

from .. import rules  # noqa: F401 - registers cloudscan rules


def _iter_db_instances(rds):
    """Yield every RDS instance, paginating so large accounts are fully covered."""
    for page in rds.get_paginator("describe_db_instances").paginate():
        yield from page.get("DBInstances", [])


def check_unencrypted_databases(session, regions=None) -> list[Finding]:
    """Flag RDS instances without storage encryption enabled."""
    findings: list[Finding] = []
    for region in (regions or [None]):
        rds = session.client("rds", region_name=region) if region else session.client("rds")
        for db in _iter_db_instances(rds):
            if db.get("StorageEncrypted", False):
                continue
            db_id = db["DBInstanceIdentifier"]
            evidence = {"db_instance": db_id}
            if region:
                evidence["region"] = region
            findings.append(
                build_finding(
                    "CLOUD-RDS-UNENCRYPTED",
                    description=f"RDS instance '{db_id}' does not have storage encryption enabled.",
                    remediation="Enable storage encryption (restore/recreate the instance encrypted).",
                    asset=Asset(provider="aws", type="rds_instance", id=db_id, region=region),
                    evidence=evidence,
                    resource=db_id,
                )
            )
    return findings
