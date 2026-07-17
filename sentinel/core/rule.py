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
    # Compliance control ids this rule maps to (e.g. a CIS benchmark control).
    # Intentionally empty until a verified mapping matrix is added — inventing
    # control numbers would be false precision.
    compliance: list[str] = Field(default_factory=list)


RULES: dict[str, Rule] = {}


def register_rule(rule: Rule) -> Rule:
    RULES[rule.id] = rule
    return rule


def get_rule(rule_id: str) -> Rule:
    return RULES[rule_id]


def rule_enabled(rule_id: str, config) -> bool:
    """Whether a rule should report, given the profile and per-rule overrides.

    Precedence: an explicit per-rule `enabled` wins; otherwise the profile
    decides ("strict" enables everything, "baseline" honours the rule's own
    `default_enabled`). Ids that aren't registered rules — e.g. scanner/check
    error findings — are always kept, so config can never hide failures.
    """
    settings = config.rule_settings(rule_id) if hasattr(config, "rule_settings") else None
    if settings is not None and settings.enabled is not None:
        return settings.enabled

    rule = RULES.get(rule_id)
    if rule is None:
        return True

    profile = getattr(config, "profile", "baseline")
    if profile == "strict":
        return True
    if profile == "cis":
        # Only rules carrying a verified control mapping — an audit against a
        # benchmark shouldn't include rules that aren't part of it.
        return bool(rule.compliance)
    return rule.default_enabled


def apply_rule_config(findings: list[Finding], config) -> list[Finding]:
    """Drop findings from disabled rules and apply per-rule severity overrides."""
    kept: list[Finding] = []
    for finding in findings:
        if not rule_enabled(finding.id, config):
            continue
        settings = (
            config.rule_settings(finding.id)
            if hasattr(config, "rule_settings")
            else None
        )
        if settings is not None and settings.severity is not None:
            finding.severity = settings.severity
        kept.append(finding)
    return kept


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
    api: str | None = None,
    rationale: str | None = None,
    verify: str | None = None,
) -> Finding:
    """Build a Finding from a registered rule plus instance-specific data.

    `api` / `evidence` / `rationale` / `verify` together make a finding auditable:
    where the observation came from, the raw fields seen, why that is a failure,
    and how to confirm the fix.
    """
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
        compliance=rule.compliance,
        confidence=rule.confidence,
        asset=asset,
        resource=resource,
        evidence=evidence or {},
        api=api,
        rationale=rationale,
        verify=verify,
    )
