from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .envelope import CoverageStatus, ReportEnvelope
from .finding import Finding, Severity, Status

_SEVERITY_ORDER = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
]
_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


def summarize(findings: list[Finding]) -> dict[str, int]:
    """Severity counts of open (non-suppressed) findings."""
    counts = Counter(
        f.severity.value for f in findings if f.status != Status.SUPPRESSED
    )
    return {sev.value: counts.get(sev.value, 0) for sev in _SEVERITY_ORDER}


def count_suppressed(findings: list[Finding]) -> int:
    return sum(1 for f in findings if f.status == Status.SUPPRESSED)


def _timestamped_path(output_dir: str | Path, ext: str, when: datetime) -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    return out / f"report-{when.strftime('%Y%m%dT%H%M%S')}.{ext}"


def build_payload(
    findings: list[Finding],
    envelope: ReportEnvelope | None = None,
    when: datetime | None = None,
) -> dict:
    """The JSON report body.

    The envelope fields sit at the top level so a consumer can read coverage
    without parsing findings -- and so `sentinel diff` can refuse to call
    anything resolved that the newer run never covered.
    """
    envelope = envelope or ReportEnvelope()
    when = when or datetime.now(timezone.utc)
    return {
        "schema_version": envelope.schema_version,
        "run_id": envelope.run_id,
        "tool_version": envelope.tool_version,
        "build_commit": envelope.build_commit,
        "generated_at": when.isoformat(),
        "ruleset_digest": envelope.ruleset_digest,
        "config_digest": envelope.config_digest,
        "coverage": envelope.coverage.model_dump(mode="json"),
        "summary": summarize(findings),
        "suppressed": count_suppressed(findings),
        "findings": [f.model_dump(mode="json") for f in findings],
    }


def write_json(
    findings: list[Finding],
    output_dir: str | Path,
    envelope: ReportEnvelope | None = None,
) -> Path:
    when = datetime.now(timezone.utc)
    path = _timestamped_path(output_dir, "json", when)
    payload = build_payload(findings, envelope, when)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def coverage_summary(envelope: ReportEnvelope) -> dict:
    """Scan health in the shape a human-facing report needs.

    Every output format shows this. A reader of the HTML report should not have
    to open the JSON to discover that half the estate was never scanned.
    """
    statuses = envelope.coverage.scanner_statuses()
    incomplete = sorted(
        name for name, status in statuses.items() if status is not CoverageStatus.OK
    )
    scopes = sorted(
        {
            "/".join(p for p in (u.account_id, u.region) if p)
            for u in envelope.coverage.units
            if u.status is CoverageStatus.OK and (u.account_id or u.region)
        }
    )
    return {
        "run_id": envelope.run_id,
        "tool_version": envelope.tool_version,
        "build_commit": envelope.build_commit,
        "ruleset_digest": envelope.ruleset_digest,
        "config_digest": envelope.config_digest,
        "scanners": {name: status.value for name, status in sorted(statuses.items())},
        "incomplete": incomplete,
        "complete": not incomplete and bool(envelope.coverage.units),
        "scopes": scopes,
    }


def write_html(
    findings: list[Finding],
    output_dir: str | Path,
    envelope: ReportEnvelope | None = None,
) -> Path:
    when = datetime.now(timezone.utc)
    path = _timestamped_path(output_dir, "html", when)
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
    )
    template = env.get_template("report.html.j2")
    html = template.render(
        generated_at=when.isoformat(),
        summary=summarize(findings),
        suppressed=count_suppressed(findings),
        findings=findings,
        coverage=coverage_summary(envelope or ReportEnvelope()),
    )
    path.write_text(html, encoding="utf-8")
    return path


# SARIF 2.1.0 — consumable by GitHub code scanning and other SARIF viewers.
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
# GitHub uses a 0-10 "security-severity" to rank code-scanning alerts.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.0",
    Severity.HIGH: "7.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def _sarif_rules(findings: list[Finding]):
    """Build the de-duplicated SARIF rule list and an id -> index map."""
    rules: dict[str, dict] = {}
    order: list[str] = []
    for f in findings:
        if f.id in rules:
            continue
        rule = {
            "id": f.id,
            "name": f.id,
            "shortDescription": {"text": f.title},
            "properties": {"security-severity": _SECURITY_SEVERITY[f.severity]},
        }
        if f.category:
            rule["properties"]["category"] = f.category
            rule["properties"]["tags"] = [f.category]
        if f.references:
            rule["helpUri"] = f.references[0]
        rules[f.id] = rule
        order.append(f.id)
    return [rules[i] for i in order], {i: idx for idx, i in enumerate(order)}


def write_sarif(
    findings: list[Finding],
    output_dir: str | Path,
    envelope: ReportEnvelope | None = None,
) -> Path:
    """Write findings as a SARIF 2.1.0 report."""
    when = datetime.now(timezone.utc)
    path = _timestamped_path(output_dir, "sarif", when)
    rules, rule_index = _sarif_rules(findings)

    results = []
    for f in findings:
        message = [f.description]
        if f.rationale:
            message.append(f"Why: {f.rationale}")
        message.append(f"Remediation: {f.remediation}")
        if f.verify:
            message.append(f"Verify: {f.verify}")

        result = {
            "ruleId": f.id,
            "ruleIndex": rule_index[f.id],
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": "\n".join(message)},
            "partialFingerprints": {"sentinelFingerprint/v1": f.dedupe_key},
        }
        properties = {k: v for k, v in (("api", f.api), ("verify", f.verify)) if v}
        if properties:
            result["properties"] = properties
        if f.resource:
            result["locations"] = [
                {"logicalLocations": [{"fullyQualifiedName": f.resource}]}
            ]
        if f.status == Status.SUPPRESSED:
            result["suppressions"] = [
                {"kind": "external", "justification": f.suppression_reason or "accepted risk"}
            ]
        results.append(result)

    envelope = envelope or ReportEnvelope()
    health = coverage_summary(envelope)

    # SARIF models scan health in `invocations`, not in results: a consumer that
    # sees zero results should be able to tell a clean run from one that could
    # not execute. executionSuccessful is false when any scanner did not finish.
    notifications = [
        {
            "level": "error" if status != "skipped" else "warning",
            "message": {
                "text": (
                    f"Scanner '{name}' did not run to completion (status: {status}). "
                    f"Its scope is unassessed, not clean."
                )
            },
            "descriptor": {"id": f"coverage/{status}"},
            "properties": {"scanner": name, "status": status},
        }
        for name, status in health["scanners"].items()
        if status != "ok"
    ]

    invocation = {
        "executionSuccessful": health["complete"],
        "startTimeUtc": envelope.generated_at,
        "endTimeUtc": when.isoformat(),
        "properties": {
            "runId": health["run_id"],
            "rulesetDigest": health["ruleset_digest"],
            "configDigest": health["config_digest"],
            "scannerStatus": health["scanners"],
            "coveredScopes": health["scopes"],
        },
    }
    if notifications:
        invocation["toolExecutionNotifications"] = notifications

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Sentinel",
                        "version": envelope.tool_version,
                        "informationUri": "https://github.com/citizen204/sentinel-toolkit",
                        "rules": rules,
                    }
                },
                "invocations": [invocation],
                "automationDetails": {"id": f"sentinel/{health['run_id']}"},
                "results": results,
            }
        ],
    }
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return path
