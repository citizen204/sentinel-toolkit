import pytest
from sentinel.core.finding import Finding, Severity


@pytest.fixture
def sample_findings():
    return [
        Finding(
            id="CLOUD-S3-PUBLIC-001", module="cloudscan", severity=Severity.HIGH,
            title="Public S3 bucket", description="Bucket allows public read.",
            remediation="Set the bucket ACL to private.",
            evidence={"bucket": "my-bucket", "acl": "public-read"},
            resource="my-bucket",
        ),
        Finding(
            id="LOG-BRUTE-001", module="logwatch", severity=Severity.CRITICAL,
            title="Brute-force login detected", description="20 failed logins in 60s.",
            remediation="Lock the account and investigate source IP.",
            evidence={"ip": "10.0.0.5", "attempts": 20},
        ),
        Finding(
            id="WEB-HEADER-001", module="webscan", severity=Severity.LOW,
            title="Missing security header", description="No Content-Security-Policy.",
            remediation="Add a Content-Security-Policy header.",
        ),
    ]


@pytest.fixture
def aws_credentials(monkeypatch):
    """Fake AWS creds so boto3 never reaches a real account under moto."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
