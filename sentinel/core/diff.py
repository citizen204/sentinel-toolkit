from __future__ import annotations

from collections import Counter


def _by_key(report: dict) -> dict[str, dict]:
    """Index a report's findings by their stable dedupe_key."""
    return {
        f["dedupe_key"]: f
        for f in report.get("findings", [])
        if f.get("dedupe_key")
    }


def diff_reports(old_report: dict, new_report: dict) -> dict[str, list[dict]]:
    """Compare two reports by dedupe_key.

    Returns findings that are new (only in the newer report), resolved (only in
    the older report), and persisting (in both). This is what turns a one-shot
    scanner into something that tracks posture over time.
    """
    old = _by_key(old_report)
    new = _by_key(new_report)
    return {
        "new": [new[k] for k in new if k not in old],
        "resolved": [old[k] for k in old if k not in new],
        "persisting": [new[k] for k in new if k in old],
    }


def severity_breakdown(findings: list[dict]) -> dict[str, int]:
    """Count findings by severity value."""
    return dict(Counter(f.get("severity", "") for f in findings))
