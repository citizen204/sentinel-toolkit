from __future__ import annotations

from pydantic import BaseModel, Field

from .asset import Asset
from .finding import Confidence, Finding, Severity


class Rule(BaseModel):
    """Metadata for a detection rule — the single source of truth.

    Checks reference a rule by id and only supply instance-specific data
    (description, remediation, asset, evidence). Title/severity/category/
    references/confidence live here so a rule catalog, compliance mapping, and
    the dashboard's rule detail can all read from one place.
    """

    id: str
    module: str
    title: str
    severity: Severity
    category: str
    references: list[str] = Field(default_factory=list)
    confidence: Confidence = Confidence.HIGH
    default_enabled: bool = True
    description: str = ""


RULES: dict[str, Rule] = {}


def register_rule(rule: Rule) -> Rule:
    RULES[rule.id] = rule
    return rule


def get_rule(rule_id: str) -> Rule:
    return RULES[rule_id]


def build_finding(
    rule_id: str,
    *,
    description: str,
    remediation: str,
    title: str | None = None,
    severity: Severity | None = None,
    resource: str | None = None,
    asset: Asset | None = None,
    evidence: dict | None = None,
) -> Finding:
    """Build a Finding from a registered rule plus instance-specific data."""
    rule = RULES[rule_id]
    return Finding(
        id=rule.id,
        module=rule.module,
        severity=severity or rule.severity,
        title=title or rule.title,
        description=description,
        remediation=remediation,
        category=rule.category,
        references=rule.references,
        confidence=rule.confidence,
        asset=asset,
        resource=resource,
        evidence=evidence or {},
    )
