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
