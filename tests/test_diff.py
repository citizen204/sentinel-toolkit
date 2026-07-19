import json

from typer.testing import CliRunner

from sentinel.cli import app
from sentinel.core.diff import diff_reports, severity_breakdown

runner = CliRunner()


def _unit(scanner="cloudscan", account=None, region=None, check="c", status="ok"):
    return {"scanner": scanner, "account_id": account, "region": region,
            "check": check, "status": status}


def _covered(findings, units=None, rules=None, ruleset="r1", config="c1"):
    """A report from a run that covered its scope, unless told otherwise."""
    return {
        "schema_version": "2.0",
        "ruleset_digest": ruleset,
        "config_digest": config,
        "coverage": {
            "units": [_unit()] if units is None else units,
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
    new = _covered([], units=[_unit(status="error")])

    result = diff_reports(old, new)

    assert result["resolved"] == []
    assert {f["dedupe_key"] for f in result["unassessed"]} == {"a"}
    assert any("did not fully cover" in w for w in result["warnings"])


def test_skipped_scanner_makes_missing_findings_unassessed():
    old = _covered([_finding("a")])
    new = _covered([], units=[_unit(status="skipped")])

    result = diff_reports(old, new)

    assert result["resolved"] == []
    assert len(result["unassessed"]) == 1


def test_region_dropped_from_scope_is_unassessed():
    """Narrowing aws_regions must not retire every finding in the dropped region."""
    acct = "123456789012"
    old = _covered(
        [_finding("a", account_id=acct, region="ap-southeast-2")],
        units=[_unit(account=acct, region="us-east-1"),
               _unit(account=acct, region="ap-southeast-2")],
    )
    new = _covered([], units=[_unit(account=acct, region="us-east-1")])

    result = diff_reports(old, new)

    assert result["resolved"] == []
    assert {f["dedupe_key"] for f in result["unassessed"]} == {"a"}


def test_account_that_could_not_be_assumed_is_unassessed():
    old = _covered([_finding("a", account_id="111111111111")],
                   units=[_unit(account="111111111111"),
                          _unit(account="222222222222")])
    new = _covered([], units=[_unit(account="222222222222")])

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
    acct = "123456789012"
    old = _covered([_finding("a", account_id=acct, region="us-east-1")],
                   units=[_unit(account=acct, region="us-east-1")])
    new = _covered([], units=[_unit(account=acct, region="us-east-1")])

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
        json.dumps(_covered([], units=[_unit(status="error")])), encoding="utf-8"
    )

    result = runner.invoke(app, ["diff", str(old), str(new)])

    assert result.exit_code == 0
    assert "Resolved:   0" in result.stdout
    assert "Unassessed: 1" in result.stdout
    assert "not resolved" in result.stdout


# --- empty coverage must never mean "everything" ------------------------------

def test_empty_coverage_confirms_nothing():
    """The regression that matters most: a clean scan recorded no scope at all.

    Coverage used to be inferred from findings, so the emptier a report was, the
    wider its implied scope -- the cleanest possible run made the strongest
    possible claim, and retired arbitrary findings from accounts it never touched.
    """
    old = _covered([_finding("a", account_id="111111111111", region="ap-southeast-2")])
    new = _covered([], units=[])

    result = diff_reports(old, new)

    assert result["resolved"] == []
    assert len(result["unassessed"]) == 1
    assert any("no coverage at all" in w for w in result["warnings"])


def test_coverage_does_not_cross_multiply_accounts_and_regions():
    """Account A in us-east-1 and account B in ap-southeast-2 is two scopes, not four."""
    old = _covered(
        [_finding("a", account_id="111111111111", region="ap-southeast-2")],
        units=[_unit(account="111111111111", region="ap-southeast-2")],
    )
    new = _covered(
        [],
        units=[_unit(account="111111111111", region="us-east-1"),
               _unit(account="222222222222", region="ap-southeast-2")],
    )

    result = diff_reports(old, new)

    assert result["resolved"] == []
    assert {f["dedupe_key"] for f in result["unassessed"]} == {"a"}


def test_one_failed_account_does_not_block_another_accounts_resolution():
    """Per-scope status: a broken account must not freeze the healthy ones."""
    old = _covered(
        [_finding("a", account_id="111111111111"),
         _finding("b", account_id="222222222222")],
        units=[_unit(account="111111111111"), _unit(account="222222222222")],
    )
    new = _covered(
        [],
        units=[_unit(account="111111111111", status="error"),
               _unit(account="222222222222", status="ok")],
    )

    result = diff_reports(old, new)

    assert {f["dedupe_key"] for f in result["resolved"]} == {"b"}
    assert {f["dedupe_key"] for f in result["unassessed"]} == {"a"}


def test_one_failed_check_marks_its_scope_unassessed():
    """Two checks share a scope; if either failed, that scope is not fully known."""
    old = _covered([_finding("a", account_id="111111111111")],
                   units=[_unit(account="111111111111", check="s3")])
    new = _covered(
        [],
        units=[_unit(account="111111111111", check="s3", status="ok"),
               _unit(account="111111111111", check="iam", status="error")],
    )

    result = diff_reports(old, new)

    assert result["resolved"] == []
    assert len(result["unassessed"]) == 1


def test_dropped_scope_is_named_not_just_counted():
    """"3 unassessed" does not tell an operator which account stopped being scanned."""
    old = _covered(
        [_finding("a", account_id="111111111111", region="ap-southeast-2")],
        units=[_unit(account="111111111111", region="ap-southeast-2")],
    )
    new = _covered([], units=[_unit(account="111111111111", region="us-east-1")])

    result = diff_reports(old, new)

    assert any("ap-southeast-2" in w for w in result["warnings"])
