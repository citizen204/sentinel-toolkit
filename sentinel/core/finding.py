from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field, computed_field

from .asset import Asset


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Confidence(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class Status(str, Enum):
    OPEN = "open"
    SUPPRESSED = "suppressed"


class Finding(BaseModel):
    id: str
    module: str
    severity: Severity
    title: str
    description: str
    remediation: str
    category: str | None = None
    references: list[str] = Field(default_factory=list)
    confidence: Confidence = Confidence.MEDIUM
    status: Status = Status.OPEN
    asset: Asset | None = None
    evidence: dict = Field(default_factory=dict)
    resource: str | None = None
    timestamp: datetime = Field(default_factory=_utcnow)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def dedupe_key(self) -> str:
        """Stable id for a logically-identical finding across scans.

        Includes the rule, module, resource, title, and stable identifying
        evidence (region/port/cidr/header) so distinct issues on the same
        resource don't collide — while volatile counts are excluded so a
        re-scan of the same issue keeps the same key.
        """
        ev = self.evidence
        parts = [
            self.id, self.module, self.resource or "", self.title,
            str(ev.get("region", "")), str(ev.get("port", "")),
            str(ev.get("cidr", "")), str(ev.get("header", "")),
        ]
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
