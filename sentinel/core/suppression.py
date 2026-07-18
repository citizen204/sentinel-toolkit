from __future__ import annotations

from datetime import date

from pydantic import BaseModel, ConfigDict

from .finding import Finding, Status

# Fields that narrow what a suppression applies to. A suppression must set at
# least one of these — otherwise it would silently hide the entire report.
_CRITERIA = ("dedupe_key", "rule", "resource", "provider", "asset_type", "account_id", "region")


class Suppression(BaseModel):
    """An accepted-risk rule for hiding a finding without deleting it.

    Matching is deliberately precise: in a multi-account, multi-region estate a
    bare resource id like ``deploy-bot`` or ``sg-0a1b2c`` can exist in several
    places, so a suppression can be pinned to an account, region, asset type, or
    an exact ``dedupe_key``.

    Suppressed findings stay in the report (marked and counted) — nothing is
    silently dropped.
    """

    # A misspelled `reson:` would otherwise parse as a suppression with no reason.
    model_config = ConfigDict(extra="forbid")

    # --- what it applies to (at least one required) ---
    dedupe_key: str | None = None   # exact finding fingerprint; strongest match
    rule: str | None = None         # rule id
    resource: str | None = None
    provider: str | None = None     # asset.provider, e.g. "aws"
    asset_type: str | None = None   # asset.type, e.g. "iam_user"
    account_id: str | None = None   # asset.account_id
    region: str | None = None       # asset.region

    # --- audit trail ---
    reason: str = ""
    created_by: str | None = None
    created_at: date | None = None
    ticket: str | None = None
    expires: date | None = None     # after this date the suppression is inactive

    def is_active(self, today: date | None = None) -> bool:
        if self.expires is None:
            return True
        return (today or date.today()) <= self.expires

    def has_criteria(self) -> bool:
        return any(getattr(self, field) is not None for field in _CRITERIA)

    def matches(self, finding: Finding) -> bool:
        # A criteria-less suppression matches nothing — safer than hiding everything.
        if not self.has_criteria():
            return False

        # An exact fingerprint is authoritative on its own.
        if self.dedupe_key is not None:
            return finding.dedupe_key == self.dedupe_key

        asset = finding.asset
        checks = (
            (self.rule, finding.id),
            (self.resource, finding.resource),
            (self.provider, asset.provider if asset else None),
            (self.asset_type, asset.type if asset else None),
            (self.account_id, asset.account_id if asset else None),
            (self.region, asset.region if asset else None),
        )
        return all(expected is None or expected == actual for expected, actual in checks)


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
