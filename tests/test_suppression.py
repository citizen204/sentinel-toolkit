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
