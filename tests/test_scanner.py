import pytest
from sentinel.core.finding import Finding, Severity
from sentinel.core.scanner import BaseScanner, all_scanners, get_scanner


def test_subclass_with_name_is_registered():
    class DemoScanner(BaseScanner):
        name = "demo"

        def run(self, config):
            return []

    assert "demo" in all_scanners()
    assert get_scanner("demo") is DemoScanner


def test_subclass_without_name_is_not_registered():
    before = set(all_scanners())

    class Nameless(BaseScanner):
        def run(self, config):
            return []

    assert set(all_scanners()) == before


def test_cannot_instantiate_without_run():
    with pytest.raises(TypeError):
        class Broken(BaseScanner):  # missing run
            name = "broken"
        Broken()


def test_run_returns_findings():
    class OneFinding(BaseScanner):
        name = "one"

        def run(self, config):
            return [
                Finding(
                    id="X-1", module="one", severity=Severity.LOW,
                    title="t", description="d", remediation="r",
                )
            ]

    findings = OneFinding().run(config=None)
    assert len(findings) == 1
    assert findings[0].id == "X-1"


def test_all_scanners_returns_copy():
    snapshot = all_scanners()
    snapshot["injected"] = object  # mutate the returned dict
    assert "injected" not in all_scanners()
