from __future__ import annotations

from collections import Counter

from .envelope import CoverageStatus, ScanCoverage


def _by_key(report: dict) -> dict[str, dict]:
    """Index a report's findings by their stable dedupe_key."""
    return {
        f["dedupe_key"]: f
        for f in report.get("findings", [])
        if f.get("dedupe_key")
    }


def _coverage(report: dict) -> ScanCoverage | None:
    """The run's coverage, or None for a report written before envelopes existed."""
    raw = report.get("coverage")
    if raw is None:
        return None
    return ScanCoverage.model_validate(raw)


def _scope_labels(coverage: ScanCoverage) -> set[str]:
    """Human-readable (scanner, account, region) scopes that ran to completion."""
    return {
        "/".join(
            part for part in (unit.scanner, unit.account_id, unit.region) if part
        )
        for unit in coverage.units
        if unit.status is CoverageStatus.OK
    }


def _dropped_scopes(
    old_coverage: ScanCoverage | None, new_coverage: ScanCoverage
) -> list[str]:
    """Scopes the previous run covered and this one did not.

    Named explicitly because "3 unassessed findings" does not tell an operator
    *which* account or region stopped being scanned.
    """
    if old_coverage is None:
        return []
    return sorted(_scope_labels(old_coverage) - _scope_labels(new_coverage))


def _asset_scope(finding: dict) -> tuple[str | None, str | None]:
    asset = finding.get("asset") or {}
    evidence = finding.get("evidence") or {}
    account = asset.get("account_id")
    region = asset.get("region") or evidence.get("region")
    return account, region


def diff_reports(old_report: dict, new_report: dict) -> dict:
    """Compare two reports by dedupe_key, honouring what each run covered.

    A finding that is absent from the newer report has two possible explanations:
    it was fixed, or it was never looked for. Only the first is ``resolved``; the
    rest are ``unassessed``, because reporting an unscanned region as remediated
    is how a scanner talks an operator out of a real exposure.

    Returns ``new`` / ``resolved`` / ``persisting`` / ``unassessed`` plus a
    ``warnings`` list describing anything that makes the comparison less than
    apples-to-apples.
    """
    old = _by_key(old_report)
    new = _by_key(new_report)
    new_coverage = _coverage(new_report)

    warnings: list[str] = []
    if new_coverage is None or _coverage(old_report) is None:
        warnings.append(
            "One or both reports predate coverage tracking, so nothing can be "
            "confirmed as resolved."
        )

    old_env = old_report.get("ruleset_digest")
    new_env = new_report.get("ruleset_digest")
    if old_env and new_env and old_env != new_env:
        warnings.append(
            "The rule catalog changed between these runs. A rule that was renamed, "
            "re-rated, or split changes finding identity, so some differences below "
            "reflect the ruleset rather than the estate."
        )

    old_cfg = old_report.get("config_digest")
    new_cfg = new_report.get("config_digest")
    if old_cfg and new_cfg and old_cfg != new_cfg:
        warnings.append(
            "The configuration changed between these runs (regions, profile, rules, "
            "or suppressions), so the two runs may not cover the same scope."
        )

    resolved: list[dict] = []
    unassessed: list[dict] = []
    for key, finding in old.items():
        if key in new:
            continue
        account, region = _asset_scope(finding)
        if new_coverage is not None and new_coverage.covered(
            finding.get("module", ""), finding.get("id", ""), account, region
        ):
            resolved.append(finding)
        else:
            unassessed.append(finding)

    if new_coverage is not None:
        not_ok = [
            name for name, status in new_coverage.scanner_statuses().items()
            if status is not CoverageStatus.OK
        ]
        if not_ok:
            warnings.append(
                f"The newer run did not fully cover: {', '.join(sorted(not_ok))}. "
                f"Findings in that scope are unassessed, not resolved."
            )
        if not new_coverage.units:
            warnings.append(
                "The newer run recorded no coverage at all, so nothing in it can "
                "confirm a fix."
            )
        dropped = _dropped_scopes(_coverage(old_report), new_coverage)
        if dropped:
            warnings.append(
                f"Scopes covered before but not in the newer run: "
                f"{', '.join(dropped)}. Their findings are unassessed."
            )

    return {
        "new": [new[k] for k in new if k not in old],
        "resolved": resolved,
        "persisting": [new[k] for k in new if k in old],
        "unassessed": unassessed,
        "warnings": warnings,
    }


def severity_breakdown(findings: list[dict]) -> dict[str, int]:
    """Count findings by severity value."""
    return dict(Counter(f.get("severity", "") for f in findings))
