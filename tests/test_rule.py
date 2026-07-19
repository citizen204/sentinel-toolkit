from sentinel.core.finding import Severity
from sentinel.core.rule import RULES, build_finding, get_rule


def test_catalog_registers_all_module_rules():
    import sentinel.modules  # noqa: F401 - triggers every module's rule registration
    expected = {
        "CLOUD-S3-PUBLIC", "CLOUD-SG-OPEN-INGRESS", "CLOUD-IAM-NO-MFA", "CLOUD-IAM-EFFECTIVE-ADMIN", "CLOUD-CHECK-ERROR",
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


def test_ruleset_digest_tracks_detection_logic_not_just_metadata():
    """Changing what a rule *does* must change the digest.

    Hashing only title/severity/compliance meant a tightened or loosened check
    left the digest identical, and a later diff blamed the changed findings on
    the estate rather than on the rule.
    """
    import sentinel.modules  # noqa: F401
    from sentinel.core.envelope import ruleset_digest
    from sentinel.core.rule import RULES

    rule = RULES["CLOUD-SG-OPEN-INGRESS"]
    before = ruleset_digest()
    original = rule.revision
    try:
        rule.revision = original + 1
        assert ruleset_digest() != before
    finally:
        rule.revision = original
    assert ruleset_digest() == before


def test_build_commit_is_none_rather_than_guessed(monkeypatch):
    """Unknown provenance is recorded as unknown, never invented."""
    import subprocess

    from sentinel.core import envelope as env

    monkeypatch.delenv("SENTINEL_BUILD_COMMIT", raising=False)

    def _boom(*args, **kwargs):
        raise OSError("no git here")

    monkeypatch.setattr(subprocess, "run", _boom)
    assert env.build_commit() is None


def test_build_commit_prefers_the_environment(monkeypatch):
    """Containers and CI have no working tree to ask."""
    from sentinel.core import envelope as env

    monkeypatch.setenv("SENTINEL_BUILD_COMMIT", "a" * 40)
    assert env.build_commit() == "a" * 40
