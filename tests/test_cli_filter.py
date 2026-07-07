from sentinel.cli import filter_ignored
from sentinel.core.finding import Finding, Severity


def _f(fid):
    return Finding(
        id=fid, module="m", severity=Severity.LOW,
        title="t", description="d", remediation="r",
    )


def test_filter_removes_ignored_ids():
    out = filter_ignored([_f("A"), _f("B"), _f("C")], ["B"])
    assert [f.id for f in out] == ["A", "C"]


def test_filter_empty_ignore_returns_all():
    findings = [_f("A"), _f("B")]
    assert filter_ignored(findings, []) == findings


def test_filter_multiple_ignored():
    out = filter_ignored([_f("A"), _f("B"), _f("C")], ["A", "C"])
    assert [f.id for f in out] == ["B"]
