from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field

from sentinel import __version__


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanContext(BaseModel):
    """Who/where/when a scan ran.

    Establishing identity up front is what makes multi-account and multi-region
    auditing coherent: every asset and finding can be attributed to an account
    and region, which in turn keeps dedupe keys, diffs, and suppressions stable.
    """

    account_id: str | None = None
    partition: str = "aws"
    regions: list[str] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=_utcnow)
    tool_version: str = __version__


def aws_scan_context(session, regions: list[str] | None = None) -> ScanContext:
    """Build a ScanContext from an AWS session via STS GetCallerIdentity."""
    identity = session.client("sts").get_caller_identity()
    arn = identity.get("Arn", "")
    parts = arn.split(":")
    partition = parts[1] if len(parts) > 2 and parts[1] else "aws"
    return ScanContext(
        account_id=identity.get("Account"),
        partition=partition,
        regions=list(regions or []),
    )
