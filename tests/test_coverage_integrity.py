"""Regressions for the ways a run could look complete when it was not.

Each test here corresponds to a case where `--fail-on-incomplete` exited 0, or a
diff confirmed a resolution, on a scan that had not established what it claimed.
"""
from __future__ import annotations

from moto import mock_aws

import sentinel.modules.cloudscan.scanner as cloudscan_scanner
from sentinel.cli import EXIT_INCOMPLETE, _gate, _mark_unrun_as_skipped, run_scanners_with_coverage
from sentinel.core.config import AwsAccount, Config
from sentinel.core.envelope import CoverageStatus, CoverageUnit, ScanCoverage
from sentinel.modules.cloudscan.scanner import CloudScanner
from sentinel.modules.cloudscan.session import account_id_from_arn


def _explode(*args, **kwargs):
    raise RuntimeError("AccessDenied")


# --- identity and reachability ------------------------------------------------

@mock_aws
def test_unresolved_account_identity_is_not_coverage(aws_credentials, monkeypatch):
    """Without an account id, findings cannot be attributed or compared.

    The checks still run and still produce findings, so the scan *looks* complete.
    It is not: nothing it produced can be matched against a run that did resolve
    identity.
    """
    monkeypatch.setattr(cloudscan_scanner, "aws_scan_context", _explode)

    findings, coverage = run_scanners_with_coverage(
        {"cloudscan": CloudScanner}, Config(aws_regions=["us-east-1"])
    )

    assert {u.status for u in coverage.units} == {CoverageStatus.ERROR}
    assert any(f.id == "CLOUD-CHECK-ERROR" for f in findings)
    assert _gate(findings, coverage, None, True, {"cloudscan"}) == EXIT_INCOMPLETE


@mock_aws
def test_unreachable_account_is_recorded_as_an_error_scope(aws_credentials, monkeypatch):
    """An account we could not assume into must leave a trace.

    Skipping it silently means the report covers only the reachable accounts and
    still reads as a complete scan of the estate.
    """
    def half(base, role_arn, *args, **kwargs):
        if "broken" in role_arn:
            raise RuntimeError("AccessDenied on AssumeRole")
        return base

    monkeypatch.setattr(cloudscan_scanner, "assume_role_session", half)
    config = Config(aws_regions=["us-east-1"], aws_accounts=[
        AwsAccount(role_arn="arn:aws:iam::111111111111:role/broken"),
        AwsAccount(role_arn="arn:aws:iam::222222222222:role/good"),
    ])

    findings, coverage = run_scanners_with_coverage({"cloudscan": CloudScanner}, config)

    errored = [u for u in coverage.units if u.status is CoverageStatus.ERROR]
    assert [u.account_id for u in errored] == ["111111111111"]
    assert _gate(findings, coverage, None, True, {"cloudscan"}) == EXIT_INCOMPLETE


def test_account_id_is_parsed_from_the_role_arn():
    """STS never answered, so the account id has to come from the ARN."""
    assert account_id_from_arn("arn:aws:iam::123456789012:role/X") == "123456789012"
    assert account_id_from_arn("arn:aws-cn:iam::123456789012:role/X") == "123456789012"
    assert account_id_from_arn("not-an-arn") is None
    assert account_id_from_arn("") is None


# --- the gate must judge what was asked for -----------------------------------

def test_deliberately_excluded_scanners_do_not_fail_the_gate():
    """Running only webscan, successfully, is a complete scan of what was requested."""
    coverage = ScanCoverage(units=[
        CoverageUnit(scanner="webscan", status=CoverageStatus.OK)
    ])
    _mark_unrun_as_skipped(coverage)

    assert _gate([], coverage, None, True, {"webscan"}) == 0
    # ... and the excluded scanners are still recorded, for the diff's benefit.
    assert {u.scanner for u in coverage.units} > {"webscan"}


def test_a_selected_scanner_that_skipped_still_fails_the_gate():
    coverage = ScanCoverage(units=[
        CoverageUnit(scanner="webscan", status=CoverageStatus.SKIPPED)
    ])

    assert _gate([], coverage, None, True, {"webscan"}) == EXIT_INCOMPLETE


def test_gate_without_a_selection_judges_everything():
    """Backwards-compatible default for callers that do not pass a selection."""
    coverage = ScanCoverage(units=[
        CoverageUnit(scanner="webscan", status=CoverageStatus.SKIPPED)
    ])

    assert _gate([], coverage, None, True) == EXIT_INCOMPLETE


# --- audit metadata -----------------------------------------------------------

def test_aws_profile_changes_the_config_digest():
    """Two runs against different accounts are not comparable and must not
    advertise the same configuration."""
    from sentinel.core.envelope import config_digest

    assert config_digest(Config(aws_profile="prod")) != config_digest(
        Config(aws_profile="dev")
    )
