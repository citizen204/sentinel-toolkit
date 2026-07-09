from __future__ import annotations

from datetime import date

from pydantic import BaseModel

from .finding import Finding, Status


class Suppression(BaseModel):
    """An accepted-risk rule for hiding a finding without deleting it.

    A finding is suppressed (status -> suppressed) when an active suppression
    matches it. Suppressed findings stay in the report — counted separately —
    so nothing is silently dropped.
    """

    rule: str | None = None       # rule id; None matches any rule
    resource: str | None = None   # resource; None matches any resource
    reason: str = ""
    expires: date | None = None   # after this date the suppression is inactive

    def is_active(self, today: date | None = None) -> bool:
        if self.expires is None:
            return True
        return (today or date.today()) <= self.expires

    def matches(self, finding: Finding) -> bool:
        if self.rule is not None and finding.id != self.rule:
            return False
        if self.resource is not None and finding.resource != self.resource:
            return False
        return True


def apply_suppressions(
    findings: list[Finding], suppressions: list[Suppression], today: date | None = None
) -> list[Finding]:
    """Mark findings matched by an active suppression as suppressed (in place)."""
    active = [s for s in suppressions if s.is_active(today)]
    for finding in findings:
        for suppression in active:
            if suppression.matches(finding):
                finding.status = Status.SUPPRESSED
                finding.suppression_reason = suppression.reason or None
                break
    return findings
