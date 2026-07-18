"""What a scan actually covered, recorded alongside what it found.

A findings list on its own cannot distinguish these two runs:

1. every region was scanned and the RDS finding is gone -- someone fixed it
2. the role lost ``rds:DescribeDBInstances``, so nothing was assessed

Both produce a report without that finding, and a diff against yesterday reports
it as *Resolved* either way. That is the failure mode this module exists to close:
coverage travels with the findings, and the diff refuses to call anything resolved
outside the scope both runs actually covered.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from .. import __version__

SCHEMA_VERSION = "1.0"


class CoverageStatus(str, Enum):
    """The outcome of attempting one unit of work."""

    OK = "ok"            # ran to completion; its findings are authoritative
    ERROR = "error"      # raised; nothing may be concluded about this scope
    SKIPPED = "skipped"  # never ran (no input configured, excluded, filtered out)


class ScanCoverage(BaseModel):
    """The scope a run actually assessed."""

    model_config = ConfigDict(extra="forbid")

    scanners: dict[str, CoverageStatus] = Field(default_factory=dict)
    accounts: list[str] = Field(default_factory=list)
    regions: list[str] = Field(default_factory=list)
    rules: list[str] = Field(default_factory=list)

    def covered(self, module: str, rule_id: str, account: str | None,
                region: str | None) -> bool:
        """Whether this run is entitled to an opinion about such a finding.

        Every clause is a way a finding can vanish from a report without anything
        having been fixed.
        """
        if self.scanners.get(module) is not CoverageStatus.OK:
            return False
        if self.rules and rule_id not in self.rules:
            return False
        if account and self.accounts and account not in self.accounts:
            return False
        if region and self.regions and region not in self.regions:
            return False
        return True


class ReportEnvelope(BaseModel):
    """Identity and provenance for one scan run."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    run_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_version: str = __version__
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    # When either digest changes between runs, differences may come from the rules
    # or the configuration rather than from the estate. The diff says so.
    ruleset_digest: str = ""
    config_digest: str = ""
    coverage: ScanCoverage = Field(default_factory=ScanCoverage)


def _digest(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


def ruleset_digest() -> str:
    """Fingerprint the active rule catalog.

    Includes the fields that shape a finding's identity -- renaming a rule's title
    changes its dedupe_key, so without this a rule edit looks like a fixed finding.
    """
    from .rule import RULES

    return _digest([
        {
            "id": rule.id,
            "title": rule.title,
            "severity": getattr(rule.severity, "value", str(rule.severity)),
            "compliance": list(rule.compliance),
        }
        for rule in sorted(RULES.values(), key=lambda r: r.id)
    ])


def config_digest(config) -> str:
    """Fingerprint the settings that decide what gets scanned and reported."""
    if config is None:
        return ""
    fields = ("aws_regions", "aws_accounts", "profile", "rules", "ignore_ids",
              "suppressions", "log_paths", "target_url", "capture_file")
    snapshot = {}
    for name in fields:
        value = getattr(config, name, None)
        if hasattr(value, "model_dump"):
            value = value.model_dump(mode="json")
        elif isinstance(value, list):
            value = [
                v.model_dump(mode="json") if hasattr(v, "model_dump") else v
                for v in value
            ]
        elif isinstance(value, dict):
            value = {
                k: v.model_dump(mode="json") if hasattr(v, "model_dump") else v
                for k, v in value.items()
            }
        snapshot[name] = value
    return _digest(snapshot)


def build_envelope(config, coverage: ScanCoverage) -> ReportEnvelope:
    return ReportEnvelope(
        ruleset_digest=ruleset_digest(),
        config_digest=config_digest(config),
        coverage=coverage,
    )
