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
import os
import pathlib
import subprocess
import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from .. import __version__

SCHEMA_VERSION = "2.0"


class CoverageStatus(str, Enum):
    """The outcome of attempting one unit of work."""

    OK = "ok"            # ran to completion; its findings are authoritative
    ERROR = "error"      # raised; nothing may be concluded about this scope
    SKIPPED = "skipped"  # never ran (no input configured, excluded, filtered out)


class CoverageUnit(BaseModel):
    """One check, run against one concrete scope, and how it went.

    The scope is recorded from the scan context and the calls that were actually
    made. An earlier version inferred it from the findings that came back, which
    inverted the safety property: the cleaner an account was, the fewer findings
    it produced, and the less coverage it appeared to have.
    """

    model_config = ConfigDict(extra="forbid")

    scanner: str
    account_id: str | None = None
    region: str | None = None
    check: str | None = None
    status: CoverageStatus


class ScanCoverage(BaseModel):
    """The scope a run actually assessed, as a list of concrete units.

    Deliberately not a set of flat lists. `accounts=[A, B]` with
    `regions=[us-east-1, ap-southeast-2]` claims four scopes when only two were
    scanned, so an account that was never touched in a region could have its old
    findings retired.
    """

    model_config = ConfigDict(extra="forbid")

    units: list[CoverageUnit] = Field(default_factory=list)
    rules: list[str] = Field(default_factory=list)

    def scanner_statuses(self) -> dict[str, CoverageStatus]:
        """Worst status per scanner, for summaries and warnings."""
        worst: dict[str, CoverageStatus] = {}
        for unit in self.units:
            current = worst.get(unit.scanner)
            if current is None or (
                current is CoverageStatus.OK and unit.status is not CoverageStatus.OK
            ):
                worst[unit.scanner] = unit.status
        return worst

    def covered(self, module: str, rule_id: str, account: str | None,
                region: str | None) -> bool:
        """Whether this run is entitled to an opinion about such a finding.

        Requires positive evidence: a unit for this exact scope that ran to
        completion. No unit means nothing was proven about it -- absence of a
        constraint is never treated as permission to declare things resolved.
        """
        if self.rules and rule_id not in self.rules:
            return False
        matching = [
            unit for unit in self.units
            if unit.scanner == module
            and unit.account_id == account
            and unit.region == region
        ]
        if not matching:
            return False
        # One failed check leaves that scope partly unknown, so the whole scope is.
        return all(unit.status is CoverageStatus.OK for unit in matching)


class ReportEnvelope(BaseModel):
    """Identity and provenance for one scan run."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    run_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_version: str = __version__
    # Which build produced this report. A released version alone cannot identify
    # a report produced from a working tree between releases.
    build_commit: str | None = Field(default_factory=lambda: build_commit())
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    # When either digest changes between runs, differences may come from the rules
    # or the configuration rather than from the estate. The diff says so.
    ruleset_digest: str = ""
    config_digest: str = ""
    coverage: ScanCoverage = Field(default_factory=ScanCoverage)


def build_commit() -> str | None:
    """The git commit this ran from, when that is knowable.

    Set SENTINEL_BUILD_COMMIT in a container or CI build, where there is no
    working tree to ask. Returns None rather than guessing.
    """
    from_env = os.environ.get("SENTINEL_BUILD_COMMIT")
    if from_env:
        return from_env.strip()[:40]
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=pathlib.Path(__file__).resolve().parent,
            capture_output=True, text=True, timeout=2, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    commit = result.stdout.strip()
    return commit or None


def _digest(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


def ruleset_digest() -> str:
    """Fingerprint the active rule catalog.

    Covers both what a rule *says* and what it *does*: renaming a title changes a
    finding's dedupe_key, and `revision` stands in for the detection logic, which
    a metadata hash cannot see. Without the latter, tightening a check would leave
    the digest unchanged and the resulting differences would be blamed on the
    estate rather than on the rule.
    """
    from .rule import RULES

    return _digest([
        {
            "id": rule.id,
            "title": rule.title,
            "severity": getattr(rule.severity, "value", str(rule.severity)),
            "compliance": list(rule.compliance),
            "revision": rule.revision,
            "enabled_by_default": rule.default_enabled,
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
