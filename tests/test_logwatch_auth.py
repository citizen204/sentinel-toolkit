from sentinel.core.finding import Severity
from sentinel.modules.logwatch.checks.auth import check_bruteforce, check_root_login


def _failed(ip):
    return (
        f"Jan 1 10:00:00 host sshd[1]: Failed password for invalid user admin "
        f"from {ip} port 22 ssh2"
    )


def test_bruteforce_flagged_over_threshold():
    lines = [_failed("10.0.0.5") for _ in range(6)] + [_failed("10.0.0.9")]
    findings = check_bruteforce(lines, threshold=5)
    flagged = {(f.id, f.resource) for f in findings}
    assert ("LOG-BRUTEFORCE", "10.0.0.5") in flagged
    assert all(f.resource != "10.0.0.9" for f in findings)
    hit = next(f for f in findings if f.resource == "10.0.0.5")
    assert hit.severity is Severity.HIGH
    assert hit.evidence["failed_attempts"] == 6


def test_no_bruteforce_below_threshold():
    lines = [_failed("10.0.0.5") for _ in range(3)]
    assert check_bruteforce(lines, threshold=5) == []


def test_root_login_flagged():
    lines = [
        "Jan 1 10:00:00 host sshd[1]: Accepted password for root "
        "from 203.0.113.7 port 22 ssh2"
    ]
    findings = check_root_login(lines)
    assert len(findings) == 1
    assert findings[0].id == "LOG-ROOT-LOGIN"
    assert findings[0].resource == "203.0.113.7"
    assert findings[0].severity is Severity.MEDIUM


def test_normal_user_login_not_flagged():
    lines = [
        "Jan 1 10:00:00 host sshd[1]: Accepted password for alice "
        "from 10.0.0.2 port 22 ssh2"
    ]
    assert check_root_login(lines) == []
