from sentinel.core.finding import Severity
from sentinel.core.rule import RULES, build_finding, get_rule


def test_catalog_registers_all_module_rules():
    import sentinel.modules  # noqa: F401 - triggers every module's rule registration
    expected = {
        "CLOUD-S3-PUBLIC", "CLOUD-SG-OPEN-INGRESS", "CLOUD-IAM-NO-MFA", "CLOUD-CHECK-ERROR",
        "LOG-BRUTEFORCE", "LOG-ROOT-LOGIN", "WEB-MISSING-HEADER",
        "NET-PORT-SCAN", "NET-HOST-SWEEP",
    }
    assert expected <= set(RULES)


def test_build_finding_pulls_metadata_from_rule():
    import sentinel.modules  # noqa: F401
    f = build_finding("CLOUD-S3-PUBLIC", description="d", remediation="r", resource="b")
    rule = get_rule("CLOUD-S3-PUBLIC")
    assert f.severity == rule.severity
    assert f.category == rule.category
    assert f.references == rule.references
    assert f.title == rule.title
    assert f.confidence == rule.confidence


def test_build_finding_allows_title_and_severity_override():
    import sentinel.modules  # noqa: F401
    f = build_finding(
        "WEB-MISSING-HEADER", title="Missing security header: CSP",
        severity=Severity.MEDIUM, description="d", remediation="r",
    )
    assert f.title == "Missing security header: CSP"
    assert f.severity is Severity.MEDIUM
