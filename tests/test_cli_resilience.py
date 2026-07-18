from sentinel.cli import filter_ignored, run_scanners
from sentinel.core.finding import Finding, Severity
from sentinel.core.scanner import BaseScanner, ScannerSkipped


class _GoodScanner(BaseScanner):
    name = ""  # empty name => not auto-registered in the global registry

    def run(self, config):
        return [
            Finding(
                id="GOOD-1", module="good", severity=Severity.LOW,
                title="ok", description="d", remediation="r",
            )
        ]


class _BadScanner(BaseScanner):
    name = ""

    def run(self, config):
        raise RuntimeError("boom")


def test_failing_scanner_is_isolated_and_others_still_run():
    findings = run_scanners({"good": _GoodScanner, "bad": _BadScanner}, config=None)
    ids = {f.id for f in findings}
    assert "GOOD-1" in ids           # the healthy scanner still produced results
    assert "SCANNER-ERROR" in ids     # the failure is surfaced, not swallowed


def test_scanner_error_finding_has_expected_shape():
    findings = run_scanners({"bad": _BadScanner}, config=None)
    err = next(f for f in findings if f.id == "SCANNER-ERROR")
    assert err.resource == "bad"
    assert err.module == "bad"
    assert err.severity is Severity.INFO
    assert "boom" in err.description


def test_all_scanners_succeed_no_error_finding():
    findings = run_scanners({"good": _GoodScanner}, config=None)
    assert all(f.id != "SCANNER-ERROR" for f in findings)


class _SkippedScanner(BaseScanner):
    name = "skipped"

    def run(self, config):
        raise ScannerSkipped("no input configured")


def test_skipped_scanner_is_reported_not_silently_empty():
    """The whole point: "didn't look" must not render the same as "looked, found nothing"."""
    findings = run_scanners({"skipped": _SkippedScanner}, config=None)

    skipped = next(f for f in findings if f.id == "SCANNER-SKIPPED")
    assert skipped.module == "skipped"
    assert skipped.severity is Severity.INFO
    assert "no input configured" in skipped.description
    assert "not a pass" in skipped.rationale


def test_skipped_findings_cannot_be_filtered_away():
    """Config must not be able to turn "unknown" into silence."""
    findings = run_scanners({"skipped": _SkippedScanner}, config=None)

    kept = filter_ignored(findings, ["SCANNER-SKIPPED"])

    assert any(f.id == "SCANNER-SKIPPED" for f in kept)
