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

# --- deeper S3 posture ------------------------------------------------------

S3_NO_ENCRYPTION = register_rule(Rule(
    id="CLOUD-S3-NO-ENCRYPTION", module="cloudscan", severity=Severity.MEDIUM,
    category="Data Protection", confidence=Confidence.HIGH,
    title="S3 bucket without default encryption",
    description="S3 bucket has no default server-side encryption configured.",
    references=[
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html"
    ],
))

S3_NO_VERSIONING = register_rule(Rule(
    id="CLOUD-S3-NO-VERSIONING", module="cloudscan", severity=Severity.LOW,
    category="Data Protection", confidence=Confidence.HIGH,
    title="S3 bucket without versioning",
    description=(
        "S3 bucket does not have versioning enabled (no protection against "
        "overwrite/delete). Durability/compliance oriented rather than a direct "
        "exposure, and noisy on buckets that hold disposable data — so it ships "
        "in the 'strict' profile, not 'baseline'."
    ),
    references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html"],
    default_enabled=False,
))

S3_NO_BPA = register_rule(Rule(
    id="CLOUD-S3-NO-BPA", module="cloudscan", severity=Severity.MEDIUM,
    category="Data Exposure", confidence=Confidence.HIGH,
    title="S3 bucket without Block Public Access",
    description=(
        "S3 bucket is not covered by Block Public Access at bucket or account level."
    ),
    references=[
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
    ],
))

# --- deeper IAM posture -----------------------------------------------------

IAM_NO_PASSWORD_POLICY = register_rule(Rule(
    id="CLOUD-IAM-NO-PASSWORD-POLICY", module="cloudscan", severity=Severity.MEDIUM,
    category="Access Control", confidence=Confidence.HIGH,
    title="Account has no IAM password policy",
    description="The AWS account has no IAM password policy configured.",
    references=[
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"
    ],
))

IAM_EFFECTIVE_ADMIN = register_rule(Rule(
    id="CLOUD-IAM-EFFECTIVE-ADMIN", module="cloudscan", severity=Severity.HIGH,
    category="Access Control", confidence=Confidence.HIGH,
    title="IAM user with admin-equivalent privileges",
    description=(
        "IAM user is granted Action '*' on Resource '*' through any path: a managed "
        "policy attached to the user, an inline policy, or either of those via a group. "
        "Supersedes the earlier direct-attachment-only check. Not yet evaluated: "
        "privilege-escalation chains (e.g. iam:PassRole + compute), permission "
        "boundaries, and SCPs."
    ),
    references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"],
))

# --- encryption at rest -----------------------------------------------------

EBS_UNENCRYPTED = register_rule(Rule(
    id="CLOUD-EBS-UNENCRYPTED", module="cloudscan", severity=Severity.MEDIUM,
    category="Data Protection", confidence=Confidence.HIGH,
    title="Unencrypted EBS volume",
    description="EBS volume is not encrypted at rest.",
    references=["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"],
))

RDS_UNENCRYPTED = register_rule(Rule(
    id="CLOUD-RDS-UNENCRYPTED", module="cloudscan", severity=Severity.HIGH,
    category="Data Protection", confidence=Confidence.HIGH,
    title="Unencrypted RDS instance",
    description="RDS database instance does not have storage encryption enabled.",
    references=[
        "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html"
    ],
))
