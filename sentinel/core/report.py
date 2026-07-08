from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .finding import Finding, Severity

_SEVERITY_ORDER = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
]
_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


def summarize(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(f.severity.value for f in findings)
    return {sev.value: counts.get(sev.value, 0) for sev in _SEVERITY_ORDER}


def _timestamped_path(output_dir: str | Path, ext: str, when: datetime) -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    return out / f"report-{when.strftime('%Y%m%dT%H%M%S')}.{ext}"


def write_json(findings: list[Finding], output_dir: str | Path) -> Path:
    when = datetime.now(timezone.utc)
    path = _timestamped_path(output_dir, "json", when)
    payload = {
        "generated_at": when.isoformat(),
        "summary": summarize(findings),
        "findings": [f.model_dump(mode="json") for f in findings],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def write_html(findings: list[Finding], output_dir: str | Path) -> Path:
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
        findings=findings,
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


def write_sarif(findings: list[Finding], output_dir: str | Path) -> Path:
    """Write findings as a SARIF 2.1.0 report."""
    when = datetime.now(timezone.utc)
    path = _timestamped_path(output_dir, "sarif", when)
    rules, rule_index = _sarif_rules(findings)

    results = []
    for f in findings:
        result = {
            "ruleId": f.id,
            "ruleIndex": rule_index[f.id],
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.description}\nRemediation: {f.remediation}"},
            "partialFingerprints": {"sentinelFingerprint/v1": f.dedupe_key},
        }
        if f.resource:
            result["locations"] = [
                {"logicalLocations": [{"fullyQualifiedName": f.resource}]}
            ]
        results.append(result)

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Sentinel",
                        "informationUri": "https://github.com/citizen204/sentinel-toolkit",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return path
