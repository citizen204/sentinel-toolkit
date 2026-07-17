"""Guards on the compliance mapping.

The mapping is deliberately small: a rule carries a control id only when it
checks what the control requires. These tests stop it drifting.
"""
from sentinel.core.config import Config
from sentinel.core.finding import Finding, Severity
from sentinel.core.rule import RULES, apply_rule_config, build_finding

# Verified against the AWS Security Hub CIS mapping table (see docs/compliance.md).
_EXPECTED = {
    "CLOUD-SG-OPEN-INGRESS": ["CIS-AWS-3.0.0:5.2", "CIS-AWS-3.0.0:5.3"],
    "CLOUD-S3-NO-BPA": ["CIS-AWS-3.0.0:2.1.4"],
    "CLOUD-RDS-UNENCRYPTED": ["CIS-AWS-3.0.0:2.3.1"],
    "CLOUD-IAM-EFFECTIVE-ADMIN": ["CIS-AWS-1.4.0:1.16"],
}

# Documented as deliberately unmapped — see docs/compliance.md for the reasoning.
_UNMAPPED = [
    "CLOUD-S3-NO-ENCRYPTION",   # CIS 2.1.1 is "require SSL", not at-rest encryption
    "CLOUD-EBS-UNENCRYPTED",    # CIS 2.2.1 is the account default, not per volume
    "CLOUD-IAM-NO-MFA",         # CIS 1.10 scopes to console users only
    "CLOUD-IAM-NO-PASSWORD-POLICY",  # CIS 1.8/1.9 assert specific parameters
    "CLOUD-S3-PUBLIC",
    "CLOUD-S3-NO-VERSIONING",
]


def test_mapped_rules_carry_the_verified_control_ids():
    import sentinel.modules  # noqa: F401
    for rule_id, controls in _EXPECTED.items():
        assert RULES[rule_id].compliance == controls, rule_id


def test_rules_without_a_verified_match_stay_unmapped():
    import sentinel.modules  # noqa: F401
    for rule_id in _UNMAPPED:
        assert RULES[rule_id].compliance == [], (
            f"{rule_id} gained a mapping — justify it in docs/compliance.md first"
        )


def test_cis_profile_runs_only_mapped_rules():
    import sentinel.modules  # noqa: F401

    def _f(rule_id):
        return Finding(
            id=rule_id, module="cloudscan", severity=Severity.HIGH,
            title="t", description="d", remediation="r",
        )

    findings = [_f("CLOUD-SG-OPEN-INGRESS"), _f("CLOUD-S3-NO-ENCRYPTION")]
    kept = {f.id for f in apply_rule_config(findings, Config(profile="cis"))}

    assert kept == {"CLOUD-SG-OPEN-INGRESS"}  # unmapped rule is out of a CIS run


def test_findings_inherit_compliance_from_their_rule():
    import sentinel.modules  # noqa: F401
    finding = build_finding(
        "CLOUD-RDS-UNENCRYPTED", description="d", remediation="r", resource="db"
    )
    assert finding.compliance == ["CIS-AWS-3.0.0:2.3.1"]
