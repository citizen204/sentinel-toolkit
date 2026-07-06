from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Finding(BaseModel):
    id: str
    module: str
    severity: Severity
    title: str
    description: str
    remediation: str
    evidence: dict = Field(default_factory=dict)
    resource: str | None = None
    timestamp: datetime = Field(default_factory=_utcnow)
