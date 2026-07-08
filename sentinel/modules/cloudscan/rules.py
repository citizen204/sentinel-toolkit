from sentinel.core.finding import Confidence, Severity
from sentinel.core.rule import Rule, register_rule

S3_PUBLIC = register_rule(Rule(
    id="CLOUD-S3-PUBLIC", module="cloudscan", severity=Severity.HIGH,
    category="Data Exposure", confidence=Confidence.HIGH,
    title="Publicly accessible S3 bucket",
    description="S3 bucket ACL grants access to a public group (AllUsers/AuthenticatedUsers).",
    references=[
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
    ],
))

SG_OPEN_INGRESS = register_rule(Rule(
    id="CLOUD-SG-OPEN-INGRESS", module="cloudscan", severity=Severity.HIGH,
    category="Network Exposure", confidence=Confidence.HIGH,
    title="Security group open to the world",
    description="Security group allows unrestricted inbound (0.0.0.0/0 or ::/0) on a risky port.",
    references=["https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html"],
))

IAM_NO_MFA = register_rule(Rule(
    id="CLOUD-IAM-NO-MFA", module="cloudscan", severity=Severity.MEDIUM,
    category="Access Control", confidence=Confidence.HIGH,
    title="IAM user without MFA",
    description="IAM user has no MFA device enabled.",
    references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"],
))

CHECK_ERROR = register_rule(Rule(
    id="CLOUD-CHECK-ERROR", module="cloudscan", severity=Severity.INFO,
    category="Operational", confidence=Confidence.LOW,
    title="cloudscan check failed",
    description="A cloudscan check raised an error (e.g. missing permission).",
))
