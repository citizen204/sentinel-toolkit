from sentinel.core.config import Config, RuleConfig
from sentinel.core.finding import Finding, Severity
from sentinel.core.rule import Rule, apply_rule_config, register_rule


def _f(rule_id="CLOUD-S3-PUBLIC", severity=Severity.HIGH):
    return Finding(
        id=rule_id, module="cloudscan", severity=severity,
        title="t", description="d", remediation="r",
    )


def test_per_rule_disable():
    import sentinel.modules  # noqa: F401 - register the catalog
    cfg = Config(rules={"CLOUD-S3-PUBLIC": RuleConfig(enabled=False)})
    assert apply_rule_config([_f()], cfg) == []


def test_per_rule_severity_override():
    import sentinel.modules  # noqa: F401
    cfg = Config(rules={"CLOUD-S3-PUBLIC": RuleConfig(severity=Severity.LOW)})
    out = apply_rule_config([_f()], cfg)
    assert out[0].severity is Severity.LOW


def test_error_findings_are_never_filtered():
    # SCANNER-ERROR is not a registered rule: config must never hide failures.
    out = apply_rule_config([_f("SCANNER-ERROR")], Config())
    assert len(out) == 1


def test_profile_baseline_vs_strict():
    register_rule(Rule(
        id="TEST-OFF-BY-DEFAULT", module="test", title="off by default",
        severity=Severity.LOW, category="Test", default_enabled=False,
    ))
    baseline = apply_rule_config([_f("TEST-OFF-BY-DEFAULT", Severity.LOW)], Config())
    strict = apply_rule_config(
        [_f("TEST-OFF-BY-DEFAULT", Severity.LOW)], Config(profile="strict")
    )
    assert baseline == []      # baseline honours the rule's own default
    assert len(strict) == 1    # strict turns everything on


def test_explicit_enable_beats_profile():
    register_rule(Rule(
        id="TEST-OFF-2", module="test", title="off by default",
        severity=Severity.LOW, category="Test", default_enabled=False,
    ))
    cfg = Config(rules={"TEST-OFF-2": RuleConfig(enabled=True)})
    assert len(apply_rule_config([_f("TEST-OFF-2", Severity.LOW)], cfg)) == 1


def test_threshold_for():
    cfg = Config(rules={"LOG-BRUTEFORCE": RuleConfig(threshold=20)})
    assert cfg.threshold_for("LOG-BRUTEFORCE", 5) == 20
    assert cfg.threshold_for("NET-PORT-SCAN", 10) == 10  # unset falls back
