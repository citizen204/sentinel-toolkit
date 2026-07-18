import json

from typer.testing import CliRunner

from sentinel.cli import app
from sentinel.core.diff import diff_reports, severity_breakdown

runner = CliRunner()


def _covered(findings, scanners=None, accounts=None, regions=None, rules=None,
             ruleset="r1", config="c1"):
    """A report from a run that covered its scope, unless told otherwise."""
    return {
        "schema_version": "1.0",
        "ruleset_digest": ruleset,
        "config_digest": config,
        "coverage": {
            "scanners": scanners or {"cloudscan": "ok"},
            "accounts": accounts or [],
            "regions": regions or [],
            "rules": rules or [],
        },
        "findings": findings,
    }


def _legacy(findings):
    """A report written before coverage tracking existed."""
    return {"findings": findings}


def _finding(key, rule="R1", module="cloudscan", **asset):
    out = {"dedupe_key": key, "id": rule, "module": module, "severity": "High",
           "resource": key}
    if asset:
        out["asset"] = asset
    return out


# --- the basic three buckets, when coverage backs them up ---------------------

def test_diff_new_resolved_persisting():
    old = _covered([_finding("a"), _finding("b")])
    new = _covered([_finding("b"), _finding("c")])

    result = diff_reports(old, new)

    assert {f["dedupe_key"] for f in result["new"]} == {"c"}
    assert {f["dedupe_key"] for f in result["resolved"]} == {"a"}
    assert {f["dedupe_key"] for f in result["persisting"]} == {"b"}
    assert result["unassessed"] == []


# --- the P0: absence is only "resolved" where the newer run actually looked ---

def test_failed_scanner_makes_missing_findings_unassessed_not_resolved():
    """The scanner errored, so its findings vanished. Nothing was fixed."""
    old = _covered([_finding("a")])
    new = _covered([], scanners={"cloudscan": "error"})

    result = diff_reports(old, new)

    assert result["resolved"] == []
    assert {f["dedupe_key"] for f in result["unassessed"]} == {"a"}
    assert any("did not fully cover" in w for w in result["warnings"])


def test_skipped_scanner_makes_missing_findings_unassessed():
    old = _covered([_finding("a")])
    new = _covered([], scanners={"cloudscan": "skipped"})

    result = diff_reports(old, new)

    assert result["resolved"] == []
    assert len(result["unassessed"]) == 1


def test_region_dropped_from_scope_is_unassessed():
    """Narrowing aws_regions must not retire every finding in the dropped region."""
    old = _covered(
        [_finding("a", account_id="123456789012", region="ap-southeast-2")],
        regions=["us-east-1", "ap-southeast-2"],
    )
    new = _covered([], regions=["us-east-1"])

    result = diff_reports(old, new)

    assert result["resolved"] == []
    assert {f["dedupe_key"] for f in result["unassessed"]} == {"a"}


def test_account_that_could_not_be_assumed_is_unassessed():
    old = _covered([_finding("a", account_id="111111111111")],
                   accounts=["111111111111", "222222222222"])
    new = _covered([], accounts=["222222222222"])

    result = diff_reports(old, new)

    assert result["resolved"] == []
    assert len(result["unassessed"]) == 1


def test_disabled_rule_is_unassessed_not_resolved():
    """Turning a rule off is not the same as fixing what it found."""
    old = _covered([_finding("a", rule="CLOUD-S3-NO-VERSIONING")],
                   rules=["CLOUD-S3-NO-VERSIONING", "CLOUD-S3-PUBLIC"])
    new = _covered([], rules=["CLOUD-S3-PUBLIC"])

    result = diff_reports(old, new)

    assert result["resolved"] == []
    assert len(result["unassessed"]) == 1


def test_region_still_in_scope_still_resolves():
    """The guard must not swallow genuine fixes."""
    old = _covered([_finding("a", account_id="123456789012", region="us-east-1")],
                   regions=["us-east-1"])
    new = _covered([], regions=["us-east-1"])

    result = diff_reports(old, new)

    assert {f["dedupe_key"] for f in result["resolved"]} == {"a"}
    assert result["unassessed"] == []


# --- comparability warnings ---------------------------------------------------

def test_legacy_reports_cannot_confirm_resolution():
    result = diff_reports(_legacy([_finding("a")]), _legacy([]))

    assert result["resolved"] == []
    assert len(result["unassessed"]) == 1
    assert any("predate coverage tracking" in w for w in result["warnings"])


def test_ruleset_change_is_flagged():
    """A renamed or re-rated rule changes finding identity, mimicking a fix."""
    old = _covered([_finding("a")], ruleset="r1")
    new = _covered([_finding("a")], ruleset="r2")

    result = diff_reports(old, new)

    assert any("rule catalog changed" in w for w in result["warnings"])


def test_config_change_is_flagged():
    old = _covered([], config="c1")
    new = _covered([], config="c2")

    result = diff_reports(old, new)

    assert any("configuration changed" in w for w in result["warnings"])


def test_severity_breakdown():
    findings = [{"severity": "High"}, {"severity": "High"}, {"severity": "Low"}]
    assert severity_breakdown(findings) == {"High": 2, "Low": 1}


# --- CLI ----------------------------------------------------------------------

def test_cli_diff_reports_counts(tmp_path):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(json.dumps(_covered([_finding("a"), _finding("b")])), encoding="utf-8")
    new.write_text(json.dumps(_covered([_finding("b"), _finding("c")])), encoding="utf-8")

    result = runner.invoke(app, ["diff", str(old), str(new)])

    assert result.exit_code == 0
    assert "New:        1" in result.stdout
    assert "Resolved:   1" in result.stdout
    assert "Persisting: 1" in result.stdout
    assert "Unassessed: 0" in result.stdout


def test_cli_diff_explains_unassessed(tmp_path):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(json.dumps(_covered([_finding("a")])), encoding="utf-8")
    new.write_text(
        json.dumps(_covered([], scanners={"cloudscan": "error"})), encoding="utf-8"
    )

    result = runner.invoke(app, ["diff", str(old), str(new)])

    assert result.exit_code == 0
    assert "Resolved:   0" in result.stdout
    assert "Unassessed: 1" in result.stdout
    assert "not resolved" in result.stdout
