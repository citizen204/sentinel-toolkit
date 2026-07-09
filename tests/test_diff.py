import json

from typer.testing import CliRunner

from sentinel.cli import app
from sentinel.core.diff import diff_reports, severity_breakdown

runner = CliRunner()


def _report(findings):
    return {"findings": findings}


def test_diff_new_resolved_persisting():
    old = _report([
        {"dedupe_key": "a", "id": "R1", "severity": "High"},
        {"dedupe_key": "b", "id": "R2", "severity": "Low"},
    ])
    new = _report([
        {"dedupe_key": "b", "id": "R2", "severity": "Low"},
        {"dedupe_key": "c", "id": "R3", "severity": "Medium"},
    ])
    result = diff_reports(old, new)
    assert {f["dedupe_key"] for f in result["new"]} == {"c"}
    assert {f["dedupe_key"] for f in result["resolved"]} == {"a"}
    assert {f["dedupe_key"] for f in result["persisting"]} == {"b"}


def test_severity_breakdown():
    findings = [{"severity": "High"}, {"severity": "High"}, {"severity": "Low"}]
    assert severity_breakdown(findings) == {"High": 2, "Low": 1}


def test_cli_diff_reports_counts(tmp_path):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(json.dumps(_report([
        {"dedupe_key": "a", "id": "R1", "severity": "High", "resource": "x"},
        {"dedupe_key": "b", "id": "R2", "severity": "Low", "resource": "y"},
    ])), encoding="utf-8")
    new.write_text(json.dumps(_report([
        {"dedupe_key": "b", "id": "R2", "severity": "Low", "resource": "y"},
        {"dedupe_key": "c", "id": "R3", "severity": "Medium", "resource": "z"},
    ])), encoding="utf-8")

    result = runner.invoke(app, ["diff", str(old), str(new)])
    assert result.exit_code == 0
    assert "New:        1" in result.stdout
    assert "Resolved:   1" in result.stdout
    assert "Persisting: 1" in result.stdout
