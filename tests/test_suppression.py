from datetime import date

from sentinel.core.finding import Finding, Severity, Status
from sentinel.core.suppression import Suppression, apply_suppressions


def _f(rule="R1", resource="res1"):
    return Finding(
        id=rule, module="m", severity=Severity.HIGH,
        title="t", description="d", remediation="r", resource=resource,
    )


def test_suppress_by_rule():
    findings = [_f("R1", "a"), _f("R2", "b")]
    apply_suppressions(findings, [Suppression(rule="R1", reason="accepted")])
    assert findings[0].status is Status.SUPPRESSED
    assert findings[0].suppression_reason == "accepted"
    assert findings[1].status is Status.OPEN


def test_suppress_by_rule_and_resource():
    findings = [_f("R1", "a"), _f("R1", "b")]
    apply_suppressions(findings, [Suppression(rule="R1", resource="a", reason="x")])
    by_resource = {f.resource: f.status for f in findings}
    assert by_resource["a"] is Status.SUPPRESSED
    assert by_resource["b"] is Status.OPEN


def test_expired_suppression_is_inactive():
    findings = [_f("R1", "a")]
    apply_suppressions(
        findings, [Suppression(rule="R1", reason="x", expires=date(2020, 1, 1))]
    )
    assert findings[0].status is Status.OPEN


def test_unexpired_suppression_is_active():
    findings = [_f("R1", "a")]
    apply_suppressions(
        findings, [Suppression(rule="R1", reason="x", expires=date(2099, 1, 1))]
    )
    assert findings[0].status is Status.SUPPRESSED


def _with_asset(rule="R1", resource="res1", account=None, region=None, atype="iam_user"):
    from sentinel.core.asset import Asset

    return Finding(
        id=rule, module="m", severity=Severity.HIGH,
        title="t", description="d", remediation="r", resource=resource,
        asset=Asset(
            provider="aws", type=atype, id=resource,
            account_id=account, region=region,
        ),
    )


def test_suppression_scoped_to_account():
    a = _with_asset(account="111111111111")
    b = _with_asset(account="222222222222")
    apply_suppressions([a, b], [Suppression(rule="R1", account_id="111111111111", reason="x")])
    assert a.status is Status.SUPPRESSED
    assert b.status is Status.OPEN   # same resource id, different account: untouched


def test_suppression_scoped_to_region():
    a = _with_asset(region="us-east-1")
    b = _with_asset(region="ap-southeast-2")
    apply_suppressions([a, b], [Suppression(rule="R1", region="us-east-1", reason="x")])
    assert a.status is Status.SUPPRESSED
    assert b.status is Status.OPEN


def test_suppression_scoped_to_asset_type():
    a = _with_asset(atype="iam_user")
    b = _with_asset(atype="s3_bucket")
    apply_suppressions([a, b], [Suppression(asset_type="iam_user", reason="x")])
    assert a.status is Status.SUPPRESSED
    assert b.status is Status.OPEN


def test_suppression_by_exact_dedupe_key():
    a = _with_asset(account="111111111111")
    b = _with_asset(account="222222222222")
    apply_suppressions([a, b], [Suppression(dedupe_key=a.dedupe_key, reason="x")])
    assert a.status is Status.SUPPRESSED
    assert b.status is Status.OPEN


def test_criteria_less_suppression_matches_nothing():
    a = _with_asset()
    apply_suppressions([a], [Suppression(reason="oops - no criteria")])
    assert a.status is Status.OPEN  # must not hide the whole report


def test_suppression_carries_audit_trail():
    s = Suppression(
        rule="R1", reason="accepted", created_by="chilton",
        created_at=date(2026, 7, 9), ticket="SEC-123",
    )
    assert s.created_by == "chilton"
    assert s.ticket == "SEC-123"
